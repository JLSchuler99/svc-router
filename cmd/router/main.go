package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// configuration
const (
	UDPListenAddr    = "0.0.0.0:24454"
	HTTPListenAddr   = "0.0.0.0:8080"
	PacketTypeVoice  = 0xFF
	DefaultVoicePort = "24454"
)

// WebhookPayload matches the JSON sent by mc-router
type WebhookPayload struct {
	Event  string `json:"event"`
	Status string `json:"status"`
	Server string `json:"server"`
	Player struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"player"`
	Backend string `json:"backend"`
	Error   string `json:"error"`
}

// Session tracks a player's connection
type Session struct {
	ClientAddr  *net.UDPAddr
	BackendConn *net.UDPConn
	BackendStr  string
	LastActive  time.Time
}

// global state
var (
	// Routes: UUID -> Target UDP Address (e.g. "127.0.0.1:24454")
	routes   = make(map[uuid.UUID]string)
	routesMu sync.RWMutex

	// Sessions: ClientIP:Port -> Active Session
	sessions = make(map[string]*Session)
	sessMu   sync.Mutex
)

// convert server TCP address from mc-router to the Simple Voice Chat UDP address
func transformBackendAddress(tcpAddress string) string {
	host, _, err := net.SplitHostPort(tcpAddress)
	if err != nil {
		host = tcpAddress
	}

	return fmt.Sprintf("%s:%s", host, DefaultVoicePort)
}

// handle incoming webhook requests from mc-router
func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload WebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad JSON", http.StatusBadRequest)
		return
	}

	var playerUUID *uuid.UUID
	if res, err := uuid.Parse(payload.Player.UUID); err == nil {
		playerUUID = &res
	} else if payload.Player.UUID != "" { // ignore unspecified UUID here, handled below
		log.Printf("[Webhook] Invalid UUID: %s", payload.Player.UUID)
		http.Error(w, "Invalid UUID", http.StatusBadRequest)
		return
	}

	routesMu.Lock()
	defer routesMu.Unlock()

	switch payload.Event {
	case "connect":
		switch payload.Status {
		case "success":
			// continue
		case "missing-backend":
			// mc-router did not find a backend, so we have nothing more to do
			return
		case "failed-backend-connection":
			// mc-router failed to connect to backend server
			// we can just assume that SVC also won't work then, so there's nothing more to do
			return
		default:
			log.Printf("[Webhook] connect: Unknown status received: %s", payload.Status)
			http.Error(w, "Unknown status", http.StatusBadRequest)
			return
		}

		if payload.Player.UUID == "00000000-0000-0000-0000-000000000000" {
			log.Printf("[Webhook] Can't register connection to backend %s (%s) for UUID 0", payload.Backend, payload.Server)
			http.Error(w, "Invalid UUID (0)", http.StatusBadRequest)
			return
		}
		if playerUUID == nil {
			// just a server connection test, nothing for us to do
			return
		}

		if _, ok := routes[*playerUUID]; ok {
			log.Printf("[Webhook] Received connect for already mapped UUID: %s (replacing)", *playerUUID)
		}
		udpTarget := transformBackendAddress(payload.Backend)
		routes[*playerUUID] = udpTarget
		log.Printf("[Webhook] Registered %s -> %s (Source: %s)", *playerUUID, udpTarget, payload.Backend)

	case "disconnect":
		if payload.Status != "success" {
			log.Printf("[Webhook] disconnect: Unknown status received: %s", payload.Status)
			http.Error(w, "Unknown status", http.StatusBadRequest)
			return
		}

		if playerUUID == nil {
			log.Printf("[Webhook] Received disconnect for empty UUID")
			return
		}

		if _, ok := routes[*playerUUID]; !ok {
			log.Printf("[Webhook] Received disconnect for unmapped UUID: %s", *playerUUID)
			return
		}
		delete(routes, *playerUUID)
		log.Printf("[Webhook] Removed %s", *playerUUID)

	default:
		log.Printf("[Webhook] Unknown event type received: %s (ignoring)", payload.Event)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	go func() {
		http.HandleFunc("/", handleWebhook)
		log.Printf("HTTP Webhook Listener running on %s", HTTPListenAddr)
		if err := http.ListenAndServe(HTTPListenAddr, nil); err != nil {
			log.Fatalf("HTTP Server failed: %v", err)
		}
	}()

	mainAddr, _ := net.ResolveUDPAddr("udp", UDPListenAddr)
	mainConn, err := net.ListenUDP("udp", mainAddr)
	if err != nil {
		log.Fatalf("UDP Listener failed: %v", err)
	}
	defer mainConn.Close()

	log.Printf("UDP Voice Router listening on %s", UDPListenAddr)

	buffer := make([]byte, 4096)

	for {
		// 3. Read from Client
		n, clientAddr, err := mainConn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}

		// Create a copy of data immediately (buffer is reused)
		packet := make([]byte, n)
		copy(packet, buffer[:n])

		handlePacket(mainConn, clientAddr, packet, routes)
	}
}

func handlePacket(mainConn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte, routes map[uuid.UUID]string) {
	clientKey := clientAddr.String()

	sessMu.Lock()
	session, exists := sessions[clientKey]
	sessMu.Unlock()

	// SCENARIO A: Existing Session
	// Known session. Just forward to its backend.
	if exists {
		session.LastActive = time.Now()
		_, err := session.BackendConn.Write(packet)
		if err != nil {
			log.Printf("Error forwarding to backend: %v", err)
		}
		return
	}

	// SCENARIO B: New Session
	// Check packet validity
	if len(packet) < 17 {
		log.Printf("[Debug] Short packet from %s (len=%d)", clientKey, len(packet))
		return
	}

	// Simple Voice Chat sends data and ping packets
	// we can only setup a session on voice data packets, afterwards all packets are forwarded
	if packet[0] != PacketTypeVoice {
		log.Printf("[Debug] Ignored non-voice packet (type %x) from %s", packet[0], clientKey)
		return
	}

	// Extract UUID
	uuidBytes := packet[1:17]
	playerID, err := uuid.FromBytes(uuidBytes)
	if err != nil {
		log.Printf("[Router] Invalid UUID bytes from %s", clientKey)
		return
	}

	// Find Route
	routesMu.RLock()
	targetBackend, found := routes[playerID]
	routesMu.RUnlock()
	if !found {
		// received a packet, but mc-router hasn't told us about this player yet
		// happens if UDP packet beats the Webhook
		// seems to recover no problem but in theory could hold onto this and retry later
		log.Printf("[Router] Dropped packet for unmapped UUID: %s (Source: %s)", playerID, clientKey)
		return
	}

	// Create New Session
	log.Printf("New Session: %s -> %s", playerID, targetBackend)

	// Open a NEW temporary socket just for this player
	backendAddr, err := net.ResolveUDPAddr("udp", targetBackend)
	if err != nil {
		log.Printf("Invalid backend address: %s", targetBackend)
		return
	}
	// DialUDP creates an ephemeral port on our side
	proxyConn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		log.Printf("Failed to dial backend: %v", err)
		return
	}

	// Store Session
	newSession := &Session{
		ClientAddr:  clientAddr,
		BackendConn: proxyConn,
		LastActive:  time.Now(),
	}

	sessMu.Lock()
	sessions[clientKey] = newSession
	sessMu.Unlock()

	log.Printf("[New Tunnel] %s (%s) <-> %s", playerID, clientAddr, targetBackend)

	// Forward the *initial* packet that triggered this
	proxyConn.Write(packet)

	// Start a goroutine to handle the RETURN traffic (Server -> Client)
	go func(s *Session) {
		buf := make([]byte, 4096)
		defer s.BackendConn.Close()
		for {
			//s.BackendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			// Read from Backend
			n, _, err := s.BackendConn.ReadFromUDP(buf)
			if err != nil {
				// timeout or closed
				sessMu.Lock()
				// Only delete if it's still *this* session (prevent race with new connections)
				if sessions[clientKey] == s {
					delete(sessions, clientKey)
				}
				sessMu.Unlock()
				return
			}

			// Send back to Client using the MAIN connection
			// This ensures the client sees the response coming from port 24454
			_, err = mainConn.WriteToUDP(buf[:n], s.ClientAddr)
			if err != nil {
				log.Printf("Error sending back to client: %v", err)
			}
		}
	}(newSession)
}

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
	SVC_MagicByte    = 0xFF
	DefaultVoicePort = "24454"
	UseBroadcast     = true
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
	ClientAddr       *net.UDPAddr
	BroadConn        *net.UDPConn
	Mapped           bool
	MappedBackend    BackendDef
	LastClientPacket time.Time
	LastServerPacket time.Time
}

type OldBackendData struct {
	ConnectionCount int
	Addr            net.UDPAddr
	LastActive      time.Time
}

type BackendDef struct {
	name string
	addr net.UDPAddr
}

// global state
var (
	// Routes: UUID -> Target UDP Address (e.g. "127.0.0.1:24454")
	routes   = make(map[uuid.UUID]string)
	routesMu sync.RWMutex

	// Sessions: ClientIP:Port -> Active Session
	sessions = make(map[string]*Session)
	sessMu   sync.Mutex

	// Set of backends (Target UDP Addresses) that don't support proper UUID registration
	oldBackends = make(map[string]OldBackendData)
	oldBMu      sync.RWMutex
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

		if playerUUID == nil {
			// just a server connection test, nothing for us to do
			return
		}

		udpTarget := transformBackendAddress(payload.Backend)

		if payload.Player.UUID == "00000000-0000-0000-0000-000000000000" {
			log.Printf("[Webhook] Backend %s uses old protocol without UUIDs", payload.Backend)

			// TODO: does this need to be initialized everytime?
			udpAddr, err := net.ResolveUDPAddr("udp", udpTarget)
			if err != nil {
				log.Printf("[Webhook] Failed to resolve %s: %v", udpTarget, err)
				return
			} else if udpAddr == nil {
				log.Printf("[Webhook] Failed to resolve %s: nil", udpTarget)
				return
			}

			oldBMu.Lock()
			oldBackends[udpTarget] = OldBackendData{
				ConnectionCount: 1,
				Addr:            *udpAddr,
				LastActive:      time.Now(),
			}
			oldBMu.Unlock()
			// We can't do anything more here
			return
		} else {
			oldBMu.Lock()
			if _, has := oldBackends[udpTarget]; has {
				log.Printf("[Webhook] Backend %s now uses new protocol, may have been replaced", payload.Backend)
				delete(oldBackends, udpTarget)
			}
			oldBMu.Unlock()
		}

		if _, has := routes[*playerUUID]; has {
			log.Printf("[Webhook] Received connect for already mapped UUID: %s (replacing)", *playerUUID)
		}
		routes[*playerUUID] = udpTarget
		log.Printf("[Webhook] Registered %s -> %s (Source: %s)", *playerUUID, udpTarget, payload.Backend)

	case "disconnect":
		if payload.Status != "success" {
			log.Printf("[Webhook] disconnect: Unknown status received: %s", payload.Status)
			http.Error(w, "Unknown status", http.StatusBadRequest)
			return
		}

		if playerUUID == nil {
			// The end of a server connection test?
			return
		}

		if payload.Player.UUID == "00000000-0000-0000-0000-000000000000" {
			// The disconnect for an old-backend connection; the error was already logged, ignore
			// log.Printf("[Webhook] Backend %s uses old protocol without UUIDs; no handling", payload.Backend)
			http.Error(w, "UUID is required", http.StatusBadRequest)
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

func getAllBroadcastTargets() []BackendDef {
	// Multiple scenarios are possible:
	// 1. the server is old and its protocol version doesn't allow us to get the UUID
	// 2. the server is new, but the UDP packet has beaten the webhook event
	// 3. an erroneous/malicious packet was sent
	// In cases 2 and 3, we can just drop the packet. But we need to rule out case 1.
	//
	// For now, all we can do is broadcast the result to all known problematic backends,
	// and listen for any responses to narrow down or continue this approach.

	// Opt-out for this new additional model, as it may impact performance if many backends are affected
	// TODO: add command-line / env flag to toggle this
	if !UseBroadcast {
		return []BackendDef{}
	}

	oldBMu.RLock()
	backends := make([]BackendDef, 0, len(oldBackends))
	for key, value := range oldBackends {
		backends = append(backends, BackendDef{
			name: key,
			addr: value.Addr,
		})
	}
	oldBMu.RUnlock()
	return backends
}

func getBroadcastTargetsInitial(playerID uuid.UUID) (backends []BackendDef, mapped bool) {
	routesMu.RLock()
	targetBackend, found := routes[playerID]
	routesMu.RUnlock()
	if found {
		udpAddr, err := net.ResolveUDPAddr("udp", targetBackend)
		if err != nil {
			log.Printf("[Webhook] Failed to resolve %s: %v", targetBackend, err)
			return nil, false
		} else if udpAddr == nil {
			log.Printf("[Webhook] Failed to resolve %s: nil", targetBackend)
			return nil, false
		}
		return []BackendDef{{name: targetBackend, addr: *udpAddr}}, true
	} else {
		return getAllBroadcastTargets(), false
	}
}

func (s *Session) getBroadcastTargets() (backends []BackendDef, mapped bool) {
	if s.Mapped {
		return []BackendDef{s.MappedBackend}, true
	} else {
		return getAllBroadcastTargets(), false
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
		session.LastClientPacket = time.Now()

		broadcastTargets, _ := session.getBroadcastTargets()

		for _, target := range broadcastTargets {
			_, err := session.BroadConn.WriteToUDP(packet, &target.addr)
			if err != nil {
				log.Printf("Error forwarding to backend %s: %v", target.name, err)
			}
		}
		return
	}

	if packet[0] != SVC_MagicByte {
		// TODO: make this log message print only once per clientKey
		log.Printf("[Router] Received packet without magic byte from %s. The client and/or server may be using an old version of SVC, which is not supported.", clientKey)
		return
	}

	// SCENARIO B: New Session
	// Check packet validity
	if len(packet) < 17 {
		log.Printf("[Debug] Short packet from %s (len=%d)", clientKey, len(packet))
		return
	}

	// TODO: we can only set up a session on voice data packets, afterwards all packets are forwarded

	// Extract UUID
	uuidBytes := packet[1:17]
	playerID, err := uuid.FromBytes(uuidBytes)
	if err != nil {
		log.Printf("[Router] Invalid UUID bytes from %s", clientKey)
		return
	}

	broadcastTargets, mapped := getBroadcastTargetsInitial(playerID)
	var backend BackendDef
	if mapped {
		backend = broadcastTargets[0]
		log.Printf("[Router] New Session: %s -> %s", playerID, backend.name)
	} else if len(broadcastTargets) == 0 {
		log.Printf("[Router] Dropped packet for unmapped UUID: %s (Source: %s)", playerID, clientKey)
		return
	} else {
		log.Printf("[Router] Broadcasting for %s", playerID)
	}

	// 1. open a local ephemeral port to send our packets from & receive responses under
	// TODO: We may not need to specify the local port explicitly, check this

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("Failed to open backend dial: %v", err)
		return
	}

	// 2. Store that port's handle as a Session for this clientKey
	// TODO: the Session data structure needs to be adjusted

	// Store Session
	newSession := &Session{
		ClientAddr:       clientAddr,
		Mapped:           mapped,
		MappedBackend:    backend,
		BroadConn:        udpConn,
		LastClientPacket: time.Now(),
	}

	sessMu.Lock()
	sessions[clientKey] = newSession
	sessMu.Unlock()

	if mapped {
		log.Printf("[New Tunnel] %s (%s) <-> %s", playerID, clientAddr, backend.name)
	}

	// 3. Forward the (initial) packet to all backends using the port above
	// If a mapping was properly established, then we'll just do this with the single mapped backend

	for _, target := range broadcastTargets {
		_, err = udpConn.WriteToUDP(packet, &target.addr)
		if err != nil {
			log.Printf("Error forwarding to backend %s: %v", target.name, err)
		}
	}

	// 4. Start a goroutine to handle the RETURN traffic (Server -> Client)

	/*
		Notes for old clients
		=====================
		If any of the servers sends ANYTHING back to us, we now know that's the one we care about

		However, if we just assume this is true forever and only send data to that server from now on,
		then the following problematic sequence can happen:
		- The player leaves the server. due to the old-protocol nature, we are not notified of this.
		- The player joins a different server under this router.
		- The local port the player uses to connect to this new server happens to be the same port as previously.
		- Now the router will assume the same clientKey should send to the old server.
			But because the player is no longer there, we're shouting into the void.
			The new server will never receive any input.

		The only solution here is to check if the server is still listening for this player, which can only be done
		by receiving its response (or any other kind of packet). But not all requests elicit a response, and we can't
		guarantee that there will be frequent enough data/heartbeat transmissions.

		Our best bet would be to wait a reasonable amount of time, within which we can expect a responsive server to reply.
		If we don't get a reply in time, we just try the broadcast again, including the original server just in case.

		This only leaves the question: how do we tell if the server didn't respond because it's down? In that case
		continuing to broadcast to it would be shouting into the void. I'm not confident we can use the webhooks to
		be notified when all players have left, but if every connect is ALWAYS paired with a disconnect that might work (and vice versa).
		The easiest solution would be to just ping the server, to ensure it's at least still alive; but this can be disabled in
		server config, so we need to let the user know.
	*/

	go func(s *Session) {
		buf := make([]byte, 4096)
		defer s.BroadConn.Close()
		for {
			//s.BackendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			// Read from Backend
			n, addr, err := s.BroadConn.ReadFromUDP(buf)
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

			// Update the last packet time
			s.LastServerPacket = time.Now()

			if !s.Mapped {
				if s.MappedBackend.name == "" {
					// we did not previously have a guess for which might be the correct server
					log.Printf("[Broadcast] received response %s <- %s", s.ClientAddr, addr)
					s.MappedBackend = BackendDef{name: addr.String(), addr: *addr}
				} else if s.MappedBackend.addr.String() != addr.String() {
					// the guess was wrong
					log.Printf("[Broadcast] received response %s <- %s (unexpected backend! updating)", s.ClientAddr, addr)
					s.MappedBackend = BackendDef{name: addr.String(), addr: *addr}
				}
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

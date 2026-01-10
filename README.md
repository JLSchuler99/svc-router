# svc-router

A UDP router for the **Simple Voice Chat** mod that pairs with [mc-router](https://github.com/itzg/mc-router) to direct audio traffic to the correct backend server.

## Overview

[mc-router](https://github.com/itzg/mc-router) is a lightweight connection multiplexer that routes TCP traffic based on the server address (hostname) in the initial Minecraft handshake. This allows hosting multiple servers on a single public IP.

**svc-router** works alongside [mc-router](https://github.com/itzg/mc-router) to handle the UDP traffic required by the Simple Voice Chat mod. It listens for connection webhooks to dynamically map a player's UDP voice packets to the correct backend server, ensuring voice chat works transparently across your backend.

## Architecture

1. **TCP Handshake:** Player connects to [mc-router](https://github.com/itzg/mc-router).
2. **Webhook Trigger:** [mc-router](https://github.com/itzg/mc-router) sends a POST webhook to `svc-router` containing the player's UUID and the target backend address.
3. **Route Creation:** `svc-router` creates an internal mapping: `UUID -> Backend UDP IP`.
4. **UDP Voice Stream:** The player's voice client sends UDP packets to `svc-router`. The router inspects the packet header for the UUID and forwards it to the mapped backend.

## Configuration

### 1. Configure mc-router
You must configure [mc-router](https://github.com/itzg/mc-router) to broadcast connection events to this application.

Add the `-webhook-url` flag to your startup command, pointing to the HTTP address of `svc-router`:

```bash
# Example: svc-router running on the same host, port 80
./mc-router -webhook-url "http://localhost:8080/event" ...
```

### 3. Running svc-router
**Default Ports:**
* **UDP Listening:** `0.0.0.0:24454` (Simple Voice Chat Traffic)
* **HTTP Listening:** `0.0.0.0:8080` (Webhooks)

### 3. Running svc-router
**Default Ports:**
* **UDP Listening:** `0.0.0.0:24454` (Game Traffic)
* **HTTP Listening:** `0.0.0.0:8080` (Webhooks)

**Run via Docker (Example):**
```bash
docker run -d \
  -p 24454:24454/udp \
  -p 8080:8080 \
  --name svc-router \
  jschuler99/svc-router:latest
```

## Contributing
This project has undergone limited testing in live environments. Feedback and contributions are highly encouraged!

If you encounter any issues or have suggestions for improvements, please feel free to open an issue or submit a Pull Request.

## Special Thanks

* **[itzg](https://github.com/itzg)** - For creating [mc-router](https://github.com/itzg/mc-router) and providing the inspiration and webhook architecture that made this project possible.

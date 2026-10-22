# XMesh Node

Standalone edge node for **XMesh Nexus**. Initial implementation: a TLS ClientHello TCP passthrough multiplexer on port 443, with a separately configured UDP/443 forwarder.

## What it does

- Routes TCP TLS connections by **exact SNI** or **wildcard suffix** without terminating TLS, with optional ALPN selection.
- Relays original ClientHello bytes unchanged to localhost backends (Xray, Caddy, Nginx, etc.).
- Default TCP route handles missing/unknown SNI (including non-TLS traffic when configured).
- Independent UDP/443 listener and a **single explicitly configured UDP backend**.
- Explicit route priority, bounded hello buffering and timeouts, basic TCP concurrency limits.
- Bind TCP and UDP on the **same numeric port** (different transport sockets).

**Important:** This is NOT a magical way to put every transport on the same 443 socket. TCP vs UDP can coexist, but QUIC/H3 and other UDP protocols cannot be safely demultiplexed without protocol-aware handling. Distinct TLS clients sharing exactly the same SNI + ALPN also cannot be told apart reliably. For Reality, XHTTP, Trojan, WebSocket, TLS sites, etc., route to distinct loopback listeners with distinct SNI when available.

## Recommended installation: Docker Compose

XMesh Node is **Docker-first**. Neither Go nor a host systemd unit is required.

```bash
git clone https://github.com/TriplexCorp/XMesh-Node.git
cd XMesh-Node
bash install.sh                    # creates config.json on first run
nano config.json                  # set your REAL SNI and loopback backends
bash install.sh                    # builds Go within Docker and launches
docker compose logs -f xmesh-node
```

On updates run `git pull --ff-only && docker compose up -d --build`.
To check configuration without starting a daemon:
```bash
docker compose run --rm --no-deps xmesh-node -check -config /etc/xmesh-node/config.json
```

**Networking:** Compose intentionally uses `network_mode: host`, so the node reaches Xray/Caddy listeners on host `127.0.0.1`. This means no `ports:` section, and any existing listener on host TCP/443 or UDP/443 conflicts with the node. Stop/move that listener first; keep backends on distinct loopback ports. Host mode reduces network isolation, so only deploy a trusted image and lock down the VPS. If you later need container-to-container routing, use a dedicated Docker network and update the loopback-only backend validation accordingly.

The JSON routing configuration is not a secret and is readable by the unprivileged container. Do not place passwords or private keys in it. Settings remain in the bind-mounted `config.json` across rebuilds.

## Legacy host build (optional)

## Build

Requires Go 1.23 or newer.

```bash
go test ./...
go build -o xmesh-node .
sudo install -m 0755 xmesh-node /usr/local/bin/xmesh-node
sudo install -d -m 0755 /etc/xmesh-node
sudo cp config.example.json /etc/xmesh-node/config.json
sudo cp deploy/xmesh-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xmesh-node
```

**Before starting:** update backend ports/SNI names in the sample config, ensure backend listeners are bound to 127.0.0.1, validate with `xmesh-node -check -config /etc/xmesh-node/config.json`, and stop any existing process holding TCP/443 or UDP/443 respectively. The same port cannot be bound by two unrelated processes on the same IP and transport.

## Security / boundaries

Routes are allowlisted by configuration; backend addresses must be loopback IP addresses (IPv4 or IPv6). The edge deliberately does not terminate TLS, inspect encrypted application payloads or bypass TLS authentication. Protect the node's configuration and restrict its management interface. Production controller enrolment and signed configuration delivery are planned, **not yet implemented**. This daemon does not claim to be connected to XMesh Nexus.

UDP forwarding is suitable for a selected service (e.g. one QUIC/H3 endpoint), not multiple unrelated UDP services. Network counters / CPU metrics are separately provided by the existing XMesh metrics agent.

## Config

See [config.example.json](config.example.json). First-match routing uses ordered rules, then `default_tcp`. Use `alpn` only if the client actually advertises the protocol. Wildcard SNI `*.example.com` matches subdomains only.

## Roadmap

- Secure node registration with control plane and authenticated configuration synchronization
- Explicit protocol-aware QUIC routing on UDP/443
- Atomic reloads, readiness endpoint, structured metrics and audited runtime management
- Xray-core process supervision / configuration validation

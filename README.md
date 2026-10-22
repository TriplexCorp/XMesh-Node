# XMesh Node

Standalone edge node for **XMesh Nexus**. Initial implementation: a TLS ClientHello TCP passthrough multiplexer on port 443, with a separately configured UDP/443 forwarder.

## Быстрое подключение из XMesh Nexus (Docker + метрики)

В панели откройте **Узлы → Подключить ноду и метрики** и скопируйте одноразовую команду. Выполните её от имени администратора целевого VPS. Токен действует **10 минут**, не публикуйте команду в переписках и логах.

Установщик автоматически:
- использует существующий `/root/XMesh-Node` или устанавливает исходники в `/opt/xmesh-node`;
- проверяет существующий `config.json` и не допускает незаметную смену ID ноды;
- сохраняет ранее созданный ключ Ed25519 и регистрирует **только публичный** ключ в панели;
- собирает и запускает контейнер Docker, а затем подключает системные метрики через таймер systemd;
- проверяет JSON-конфигурацию перед запуском Docker.

**Требуются:** Docker Engine с Compose plugin, Linux с systemd, Git, curl, OpenSSL и Python 3. Go на сервере не нужен. Скрипт не останавливает Nginx и не занимает TCP/443 без отдельной настройки. По умолчанию выбирается TCP/8443.

Если ключ для данного узла уже зарегистрирован, установщик может использовать **тот же ключ**, но не заменит другой действующий ключ. Для замены нужно явно отозвать прежнюю привязку в панели.

Проверка после установки:

```bash
docker logs --tail 30 xmesh-node
systemctl status xmesh-node-metrics.timer
journalctl -u xmesh-node-metrics.service -n 30 --no-pager
```

Наличие heartbeat означает только связь с маршрутизатором. Удалённое управление Xray-core и полноценный QUIC/UDP-мультиплексор пока не реализованы.

## What it does

- Routes TCP TLS connections by **exact SNI** or **wildcard suffix** without terminating TLS, with optional ALPN selection.
- Relays original ClientHello bytes unchanged to localhost backends (Xray, Caddy, Nginx, etc.).
- Default TCP route handles missing/unknown SNI (including non-TLS traffic when configured).
- Independent UDP/443 listener and a **single explicitly configured UDP backend**.
- Explicit route priority, bounded hello buffering and timeouts, basic TCP concurrency limits.
- Bind TCP and UDP on the **same numeric port** (different transport sockets).

**Important:** This is NOT a magical way to put every transport on the same 443 socket. TCP vs UDP can coexist, but QUIC/H3 and other UDP protocols cannot be safely demultiplexed without protocol-aware handling. Distinct TLS clients sharing exactly the same SNI + ALPN also cannot be told apart reliably. For Reality, XHTTP, Trojan, WebSocket, TLS sites, etc., route to distinct loopback listeners with distinct SNI when available.

## Connect XMesh Node to XMesh Nexus (signed heartbeat)

The panel and the node now support a **signed heartbeat**. This reports whether the
router process is alive; it is **not yet remote Xray supervision or configuration rollout**.

1. Create a node in XMesh Nexus and open **Nodes → Configure metrics**. Register
   the **Ed25519 public key** from the metrics agent installed on the same VPS.
   The panel node ID must match the metrics agent's `XMESH_NODE_ID`.
2. On the node host, configure these additional fields in `config.json`:

```json
{
  "panel_url": "https://panel.example.com",
  "node_id": 1,
  "private_key_file": "/etc/xmesh-node-metrics/node.key"
}
```

**Merge these fields into your existing JSON**; do not replace SNI routing fields.
`panel_url` must be the externally reachable HTTPS origin. With the default
Docker Compose, the agent's key directory is mounted read-only into the
container. Never place the private key into a Git repository or paste it into
the panel.

3. Run `docker compose up -d --build` and `docker compose logs --tail=40`.
   Signed heartbeats are sent immediately and every 60 seconds. XMesh Nexus
   marks the node offline when no heartbeat arrives for 150 seconds.
   `HTTP 401` means the Ed25519 public key is unregistered, mismatched, or
   the node's timestamp is outside the allowed window. Synchronize NTP and
   verify the ID.

If the metrics agent is not installed on that host, create an Ed25519
PKCS#8 private key using OpenSSL and register its public key in the panel.
Do not modify or replace an existing metrics agent key without updating
its registration. The current node and metrics reporter use one registered
identity for a given panel node.

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

# XMesh Node

Standalone edge node for **XMesh Nexus**. Initial implementation: a TLS ClientHello TCP passthrough multiplexer on port 443, with a separately configured UDP/443 forwarder.

## XSP-v2 — этап спецификации гибридной PQ-защиты (27 октября 2026)

В Node и Nexus `main` добавлены одинаковые [спецификация](docs/XSP_V2_WIRE_SPEC.md) и [публичные wire-векторы](docs/XSP_V2_VECTORS.json). Тест `security/xspv2/wire_test.go` независимо от Rust и JavaScript воспроизводит байты двух направлений, проверяет границы и отрицательные случаи. Это **test-only foundation (PR01)**: без новых приватных ключей, без смены версии `go.mod`, без модификации heartbeat/agent, без подключения v2 и без заявлений о постквантовой защите в эксплуатации.

**PR02 test-only:** в отдельном Go-модуле `security/xspv2/poc-go` выбран Go 1.27.3 с `crypto/mldsa`, реализованы проверки двойных подписей Ed25519 **AND** ML-DSA-65 на общих тестовых векторах. Негативные проверки отвергают подмену ключа, payload и отсутствие любой подписи. Контрольные результаты сопоставляются с независимой реализацией OpenSSL 3.5 на Rust-стороне; см. [Crypto PoC](docs/XSP_V2_CRYPTO_POC.md). Основной Go 1.23-модуль и Docker router не менялись.

Следующий gate: зелёный CI обоих репозиториев, прямой двусторонний Rust↔Go обмен подписанными сообщениями, security-review, затем отдельная проверка гибридного TLS. Strict-активация по-прежнему невозможна без персональной миграции ноды и запрета downgrade.

## Подписанная офлайн-политика и Hysteria 2

`xmesh-policy-guard.py` проверяет подписанный профиль Xray и сопоставляет
`policy.users` с фактически созданными пользователями протокола:
VLESS использует `settings.clients[].id`, Hysteria2 — `settings.users[].auth`,
другие поддерживаемые протоколы используют свой тип учётных данных.
Сопоставление по имени `xmesh-u<ID>--<tag>` связывает учётную запись
с ID пользователя панели; для паролей SS2022 используется отдельный PSK,
а не UUID. Проверка не разрешает дополнительные учётные записи и не
отключает Ed25519, проверку digest или локальные ограничения трафика.
Ранее VLESS-only проверка выдавала `Signed policy and VLESS clients differ`,
поэтому Hysteria не доходила до проверки Xray и маршрутизатора.

Для диагностики используйте `journalctl -u xmesh-xray-sync.service -n 70 --no-pager`.
Пока подпись, состав пользователей и конфигурация не согласованы, предыдущая
рабочая конфигурация Xray намеренно сохраняется.

## Обновление управляемой ноды до control-v5.1.2

После выпуска **обоих репозиториев** (XMesh-Node и XMesh Nexus) установите обновление
управляющего агента **control-v5.1.2** из панели Nexus: **Узлы → Обновить Agent**.
В версии исправлена отправка независимого состояния маршрутизатора и Xray,
сохранена проверка подписанных профилей, включая оба транспорта, и закрыты
циклические TCP/UDP-маршруты. Автоматическое обновление агента также
подтягивает актуальный XMesh-Node и офлайн-проверяющий модуль.

Для диагностики на VPS: `systemctl status xmesh-node-control.timer`,
`journalctl -u xmesh-node-agent-upgrade.service -n 70 --no-pager`,
`docker ps --filter name=xmesh-node`, `journalctl -u xmesh-xray-sync.service -n 60 --no-pager`.
Версия после обновления проверяется командой
`grep '^AGENT_VERSION=' /usr/local/sbin/xmesh-node-control`.
Если обновление через панель недоступно, на уже установленной ноде можно
выполнить штатный `sudo /usr/local/sbin/xmesh-update-agent` и снова проверить
версию и состояние служб. Не перезаписывайте приватный ключ ноды.

При первом подключении с помощью `bootstrap.sh` heartbeat маршрутизатора
больше не дублирует heartbeat управляющего агента. В старых конфигурациях
маршрутизатора могут сохраняться поля `panel_url` / `node_id`, но новый
Nexus игнорирует такой устаревший heartbeat, не затирая статус агента.

## VLESS + Hysteria2 на одном публичном 443

Управляемый профиль XRAY STUDIO может содержать **один TCP-прокси inbound и один Hysteria2 inbound** (порядок не важен). Nexus выдаёт им два локальных порта: `xrayLocalPort` и следующий за ним. XMesh-Node сохраняет раздельные `default_tcp` и `udp_backend`; публичный TCP и UDP могут использовать одинаковый номер порта. Пример при `xrayLocalPort=5000` и порядке VLESS → Hysteria2: TCP/443 → `127.0.0.1:5000`, UDP/443 → `127.0.0.1:5001`.

Для XHTTP в TCP-профиле используйте `h2`/`http/1.1`, **без `h3`**: разделять несколько QUIC-бэкендов один UDP-forwarder не умеет. Схема не поддерживает произвольные три и более пользовательских inbound. Сохранены Ed25519-проверка конфигурации, offline-policy и блокировки пользователей обоих протоколов. Требуется обновление и панели, и XMesh-Node, затем реальный тест на VPS. Перед миграцией сохраните конфиги и проверьте оба локальных порта, сертификат и firewall UDP.

## Hysteria 2: автоматическое UDP-проксирование

При синхронизации профиля Xray с одним inbound протокола `hysteria` агент определяет UDP-транспорт и согласует `listen_udp: ":443"` и `udp_backend: "127.0.0.1:<xrayLocalPort>"` в установленном `config.json` маршрутизатора. Изменение применяется с пересозданием `xmesh-node` (файл подключён Docker bind-mount). При переходе обратно на TCP ранее управляемый UDP-listener отключается; самостоятельно настроенный UDP-backend не перезаписывается. TCP `default_tcp` при UDP-профиле не перенаправляется автоматически.

Для работы нужны действующий Hysteria2 inbound на UDP `127.0.0.1:<xrayLocalPort>`, доступный контейнеру сертификат, назначенные пользователи и разрешённый UDP/443 на VPS и у провайдера. Выполните `ss -lunp | grep -E ':(443|5000)\\b'`, `docker logs --tail 50 xmesh-managed-xray` и `journalctl -u xmesh-xray-sync.service -n 60 --no-pager`. **Наличие UDP-listener маршрутизатора не доказывает, что Xray успешно применил Hysteria2.**

## Первый запуск без XRAY STUDIO-профиля

Подключение ноды **не требует заранее созданного Xray-профиля**. На пустой панели достаточно создать запись узла и воспользоваться «Подключить ноду и метрики». Bootstrap устанавливает Docker, маршрутизатор, ключи Ed25519, телеметрию и таймер синхронизации.

Если профиль ещё не назначен, Nexus возвращает аутентифицированному узлу **HTTP 202** с кодом состояния `awaiting_profile` вместо HTTP 409. Это нормальное ожидание: Xray не запускается с фиктивным конфигом, `xmesh-xray-sync.service` завершается успешно, а таймер проверяет назначение раз в минуту. В карточке узла отображается «Подключена · ждёт профиль».

После создания XRAY STUDIO-профиля выберите его у узла в панели. Нода автоматически получит проверяемую подписанную политику и применит Xray в следующем цикле синхронизации; повторный одноразовый токен или переустановка не нужны. Ошибки реальной конфигурации (несуществующий назначенный профиль, неверный JSON, несовместимые TLS-режимы) по-прежнему блокируют применение без обхода подписей.

Если профиль **сняли** с уже работавшей ноды, агент остановит только XMesh-managed Xray, сохранив регистрацию, ключи, маршрутизатор и данные. При повторном назначении корректного профиля работа возобновится обычной синхронизацией.

## Быстрое подключение из XMesh Nexus (Docker + метрики)

В панели откройте **Узлы → Подключить ноду и метрики**. Сначала скопируйте команду БЕЗ токена и запустите на целевом VPS; установщик попросит одноразовый токен отдельным скрытым вводом. Скопируйте его отдельно из панели и вставьте при запросе. Токен действует **10 минут**, не публикуйте его. Он не передаётся аргументом процесса; регистрация дополнительно требует Ed25519-подпись сообщения, связывающего токен и публичный ключ.

Установщик автоматически:
- устанавливает Docker Engine и Compose на чистой Ubuntu (если они отсутствуют) до регистрации одноразового токена;
- использует существующий `/root/XMesh-Node` или устанавливает исходники в `/opt/xmesh-node`;
- проверяет существующий `config.json` и не допускает незаметную смену ID ноды;
- сохраняет ранее созданный ключ Ed25519 и регистрирует **только публичный** ключ в панели;
- собирает и запускает контейнер Docker, а затем подключает системные метрики через таймер systemd;
- проверяет JSON-конфигурацию перед запуском Docker.

**Требуются:** интерактивный терминал, Ubuntu с systemd и права root. Установщик сам поставит Docker Engine, Compose plugin, Git, curl, OpenSSL и Python 3 через официальный репозиторий Docker. Go на сервере не нужен. На других ОС автоматическая установка пока не поддерживается. Скрипт не останавливает Nginx и не занимает TCP/443 без отдельной настройки. По умолчанию выбирается TCP/8443.

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

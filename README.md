# XMesh Node

**Управляемая VPN-нода для XMesh Nexus:** Docker-маршрутизатор TCP/TLS ClientHello (SNI/ALPN), настраиваемый UDP-forwarder, подписанный heartbeat и агенты, которые синхронизируют и применяют конфигурацию Xray с панели. Нода устанавливается автоматически из Nexus или отдельно как самостоятельный Docker-router.

## Основной способ: автоматическое подключение из Nexus

Для управляемой ноды **не нужно вручную устанавливать Docker, Compose, Go, Xray-контрольный агент или метрики**. В панели **XMesh Nexus → Узлы → Подключить ноду и метрики** создайте узел и скопируйте bootstrap-команду **без токена**. Запустите её на целевой VPS с Ubuntu, root/sudo и systemd. Одноразовый токен скопируйте отдельно и вставьте по защищённому запросу установщика (срок действия — 10 минут).

`bootstrap.sh` автоматически подготавливает Docker Engine/Compose и зависимости, развёртывает репозиторий, проверяет `config.json` и ID ноды, создаёт/сохраняет Ed25519-ключ, регистрирует **только публичный ключ**, запускает Docker-router, метрики и таймеры управления и синхронизации Xray. **Профиль XRAY STUDIO можно назначить позже** — до назначения нода находится в состоянии `awaiting_profile`, без фиктивного Xray-конфига. [Шаги подключения и проверки](#быстрое-подключение-из-xmesh-nexus-docker--метрики).

**Отдельный `bash install.sh` в этом репозитории — самостоятельная установка Docker-router:** в отличие от управляемого bootstrap, он **не устанавливает Docker**, а требует уже имеющийся Engine/Compose и настроенный `config.json`. Не путайте эти два сценария. Nginx/HTTPS **панели Nexus** автоматически настраивает [установщик панели](https://github.com/TriplexCorp/XMesh-Nexus#установка-панели), а Node не заменяет его конфигурацию.

**Восстановление после ошибки подключения:** обычный `XMESH1`/Ed25519 bootstrap при конфликте public key выдаёт **HTTP 409**. После обновления Nexus владелец может явно одобрить legacy переподключение через одноразовый recovery-token; новая подпись проверяется до изменения доверенного ключа. [Подробные шаги ниже](#быстрое-подключение-из-xmesh-nexus-docker--метрики). Это не имеет отношения к experimental XSP-v2.

## XSP-v2 — P0: post-quantum security в разработке (27 октября 2026)

**Текущий управляемый Node (Go 1.23) по-прежнему работает по `XMESH1`/Ed25519; `strict-pq` не включён.** Вся описанная ниже реализация XSP-v2 находится в **отдельном Go 1.27.3 staging/PoC-модуле** `security/xspv2/poc-go` и экспериментальном Rust API Nexus; штатный `bootstrap.sh` не включает эти механизмы.

| Этап | Реализовано в test-only/staging | Открытые production-задачи |
| --- | --- | --- |
| **Wire и crypto** | Общие [wire-векторы](docs/XSP_V2_WIRE_SPEC.md), строгий декодер `envelope` (результат **Untrusted**), Ed25519 **AND** ML-DSA-65 подписи и независимая Rust ↔ Go проверка | Freeze протокола, FIPS 204 KAT, fuzz и security review |
| **Защита приватных ключей** | AES-256-GCM vault `keyring`, отдельный wrapping key, права `0600/0700`, локальная staging-двухфазная ротация `prepare/activate/recover` с сохранением прежнего sealed keyset; [инструкция](docs/XSP_V2_TWO_PHASE_VAULT_STAGING.md) | Production KMS/backup, защищённое восстановление и двухфазная смена ключей |
| **Регистрация по одобрению владельца** | `keytool prove` подписывает 32-байтный challenge **обоими приватными ключами**; Nexus staging API принимает только заранее одобренные владельцем публичные ключи/следующую эпоху, проверяет обе подписи, срок **10 минут** и одноразовость | UI и защищённый канал, независимое противодействие rollback, canary-нодa |
| **Сетевой протокол и TLS** | В Nexus staging heartbeat проверяет обе подписи и уникальный nonce, возвращая только **неподписанный 204**; Go/OpenSSL и изолированный Nginx CI подтверждают TLS 1.3/`X25519MLKEM768`, проверку имени сервера/CA и отказ от downgrade | Подписанные ответы и команды, полноценный node-only ingress с реальным сертификатом и проверка TLS на отдельной VPS |

**CI evidence (27 октября 2026, по конкретным SHA):** [Nexus Backend CI `f5f3e06` — success](https://github.com/TriplexCorp/XMesh-Nexus/actions/runs/40444076259) с PostgreSQL/API integration; [Nexus Crypto PoC — success](https://github.com/TriplexCorp/XMesh-Nexus/actions/runs/40444076298). [Node CI `ba6013d` — success](https://github.com/TriplexCorp/XMesh-Node/actions/runs/40443828379) и [Node Crypto CI — success](https://github.com/TriplexCorp/XMesh-Node/actions/runs/40443828424). Локальная staged-ротация и prepared-key proof реализованы в слитых [PR #5](https://github.com/TriplexCorp/XMesh-Node/pull/5) и [#6](https://github.com/TriplexCorp/XMesh-Node/pull/6), с успешными изолированными Go Crypto CI на соответствующих коммитах; это не production cutover. CI не доказывает recovery на VPS, наличие подписанных ACK или включённый production `strict-pq`.

**Правильный путь для управляемой Node остаётся прежним:** установить ноду из панели (**Узлы → Подключить ноду и метрики**); Docker/Compose и агенты готовит автоматический bootstrap. Не запускайте `keytool` и не заменяйте production-ключи ноды ради PoC. Для экспериментальной схемы понадобятся отдельная тестовая VPS и подтверждение владельца.

Документация: [регистрация и ротация двойных ключей](docs/XSP_V2_OWNER_KEY_ENROLLMENT.md) · [стендовый API и vault](docs/XSP_V2_EXPERIMENTAL_GATEWAY.md) · [двухфазный staging vault](docs/XSP_V2_TWO_PHASE_VAULT_STAGING.md) · [TLS-probe](docs/XSP_V2_TLS_PROBE.md) · [Roadmap Nexus](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/docs/ENTERPRISE_ROADMAP.md).

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

Если ключ для данного ID уже зарегистрирован, установщик может использовать **тот же ключ**, но не заменит другой действующий ключ по обычному токену. Если при `/api/v1/node/enroll` пришёл **HTTP 409**, в Nexus за этим ID закреплён другой Ed25519 public key. **Не удаляйте прежний ключ заранее.** В обновлённой панели **Узлы → Подключить агент ноды** предложит владельцу отдельное подтверждение переподключения и создаст 10-минутный recovery-token ([Nexus PR #26](https://github.com/TriplexCorp/XMesh-Nexus/pull/26)). `bootstrap.sh` сохраняет локальный приватный ключ и проверяет token + подпись; прежний ключ останется действующим до успешного подтверждения нового, после чего старый агент потеряет управление. Если прежняя нода тоже должна остаться в сети, **создайте вторую запись Node с новым ID**, не выполняя recovery. [Node bootstrap fix #7](https://github.com/TriplexCorp/XMesh-Node/pull/7), [CI `main` #40448354429](https://github.com/TriplexCorp/XMesh-Node/actions/runs/40448354429). Слияние PR не обновляет установленную панель на VPS.

Проверка после установки:

```bash
docker logs --tail 30 xmesh-node
systemctl status xmesh-node-metrics.timer
journalctl -u xmesh-node-metrics.service -n 30 --no-pager
```

Наличие heartbeat означает только связь с маршрутизатором, **не** успешное применение профиля Xray. Подписанная синхронизация, запуск и управление Xray по назначенному профилю уже реализованы отдельными агентами; проверяйте `xmesh-xray-sync.timer`, статус Xray и актуальную ревизию. Произвольный QUIC/UDP-мультиплексор нескольких разных протоколов на одном UDP/443 не заявляется.

## What it does

- Routes TCP TLS connections by **exact SNI** or **wildcard suffix** without terminating TLS, with optional ALPN selection.
- Relays original ClientHello bytes unchanged to localhost backends (Xray, Caddy, Nginx, etc.).
- Default TCP route handles missing/unknown SNI (including non-TLS traffic when configured).
- Independent UDP/443 listener and a **single explicitly configured UDP backend**.
- Explicit route priority, bounded hello buffering and timeouts, basic TCP concurrency limits.
- Bind TCP and UDP on the **same numeric port** (different transport sockets).

**Important:** This is NOT a magical way to put every transport on the same 443 socket. TCP vs UDP can coexist, but QUIC/H3 and other UDP protocols cannot be safely demultiplexed without protocol-aware handling. Distinct TLS clients sharing exactly the same SNI + ALPN also cannot be told apart reliably. For Reality, XHTTP, Trojan, WebSocket, TLS sites, etc., route to distinct loopback listeners with distinct SNI when available.

## Connect XMesh Node to XMesh Nexus (signed heartbeat)

The panel and node support a **signed heartbeat** reporting whether the router process is alive. **Managed Xray configuration delivery, local signature checks and process reconciliation are implemented separately** by the node control/sync agents installed by Nexus bootstrap; router heartbeat alone does not attest that Xray was started or a policy was applied. For an ordinary managed installation, use the automated onboarding section above instead of these manual heartbeat-only steps.

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

## Самостоятельная установка Docker-router (альтернативный способ)

Этот сценарий предназначен для опытного администратора, который **не использует автоматическую установку из Nexus**. Для прямого `bash install.sh` на VPS **Docker Engine и Compose должны быть уже установлены**: он создаёт образ и запускает роутер, но **не** ставит Docker/Nginx/Certbot, не регистрирует управляемую ноду и не поднимает систему метрик и control-таймеров. Go и отдельный systemd-юнит для самого маршрутизатора не нужны — сборка Go выполняется в Docker.

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

**XSP-v2 P0 — экспериментальные основы готовы, production-внедрение не начато.** Полный статус и CI см. [выше](#xsp-v2--p0-post-quantum-security-в-разработке-27-октября-2026) и в [Roadmap Nexus](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/docs/ENTERPRISE_ROADMAP.md).

- [x] PR01/PR02: общий бинарный формат и cross-language Rust ↔ Go Ed25519 + ML-DSA-65 с отрицательными тестами
- [x] PR07 lab: X25519MLKEM768/TLS 1.3, Nginx/OpenSSL/Go handshake, отсутствие downgrade в изолированном CI
- [x] P0 staging: строгий Go-декодер, AES-256-GCM key vault, `keytool prove` и проверка **двойного** challenge-proof в Rust Nexus
- [x] P0 staging: владелец утверждает конкретные ключи/epoch; транзакционная смена публичных ключей и запрет повтора challenge в отдельном API Nexus
- [ ] **Release gate:** зелёный полный Nexus Backend CI после Rustfmt и PostgreSQL integration, security review и утверждение протокола
- [ ] **Production:** двухфазная ротация, долговременное защищённое хранение, подписанные ответы/ACK, продакшен-агент и монотонный suite-floor на Node
- [ ] **Real VPS:** выделенный node-only TLS endpoint, подтверждённые CA/SNI/handshake/прокси-сегменты, canary, recovery и ручное включение без downgrade

- Secure node registration with control plane and authenticated configuration synchronization
- Explicit protocol-aware QUIC routing on UDP/443
- Atomic reloads, readiness endpoint, structured metrics and audited runtime management
- Xray-core process supervision / configuration validation

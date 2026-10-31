# XMesh Node

> Управляемая edge-нода для XMesh Nexus: TCP/TLS routing, UDP forwarding, Xray reconciliation, telemetry и production-capable XSP/2 strict-PQ control plane без автоматического classical fallback.

![Version](https://img.shields.io/badge/version-6.0.0-111827)
![Control plane](https://img.shields.io/badge/control%20plane-strict--PQ-0f766e)
![Fallback](https://img.shields.io/badge/classical%20fallback-disabled-b91c1c)

## Текущий статус — 31 октября 2026

XMesh Node `v6.0.0` содержит рабочий strict-PQ managed path для свежего подключения из XMesh Nexus. Bootstrap работает **fail-closed**: router, Xray, metrics, control и reconciliation не запускаются, пока локально не подтверждён durable activation receipt.

Проверенный production bootstrap release:

```text
2745b03677fc6e12761021c5dad6d48138af87d4
```

Это merge XMesh-Node [PR #60](https://github.com/TriplexCorp/XMesh-Node/pull/60), который исправил operational failure после истечения 120-секундного окна свежести первоначального activation response. Nexus после [PR #210](https://github.com/TriplexCorp/XMesh-Nexus/pull/210) закрепляет именно этот reviewed Node SHA для новых установок.

| Область | Состояние v6 |
| --- | --- |
| Managed bootstrap | ✅ exact reviewed SHA, Ubuntu + systemd, fail-closed до PQ activation |
| Transport | ✅ TLS 1.3 + `X25519MLKEM768` |
| Client TLS identity | ✅ ML-DSA-65 certificate |
| XSP/2 message authentication | ✅ Ed25519 **AND** ML-DSA-65 |
| Panel identity | ✅ pinned signing keys from enrollment |
| Activation | ✅ signed durable receipt + local active state |
| Operational metrics/control/Xray sync | ✅ только через strict-PQ product tunnel |
| Automatic classical fallback | ❌ запрещён |
| Managed Xray start | ✅ только после strict-PQ desired-config reconciliation |
| User VPN data plane | Xray; отдельный от control plane |

## Что такое XMesh Node

XMesh Node состоит из двух логически разных частей:

1. **Data-plane edge/router** — принимает TCP/TLS и UDP на публичном интерфейсе и направляет трафик к loopback-бэкендам, обычно Xray.
2. **Managed control plane** — получает policy/config/control от XMesh Nexus, отправляет metrics и применяет Xray через authenticated XSP/2 strict-PQ transport.

```text
                         CONTROL PLANE

 XMesh Node VPS                                      XMesh Nexus
 ┌───────────────────────────┐                  ┌──────────────────────┐
 │ xmesh-agent-xspv2-product │ ── TLS 1.3 ───▶ │ public TCP/443       │
 │                           │    X25519MLKEM768│ strict-PQ ingress    │
 │ Ed25519 + ML-DSA-65       │ ◀─ signed ───── │ dual-signed response │
 └─────────────┬─────────────┘                  └──────────────────────┘
               │
      ┌────────┼─────────┐
      ▼        ▼         ▼
   metrics   control   Xray sync

                          DATA PLANE

 Internet ── TCP/UDP ──▶ XMesh Node router ──▶ loopback Xray/backend
```

Control-plane post-quantum guarantees **не означают**, что пользовательский VPN data plane автоматически становится post-quantum. Xray и его клиентские протоколы являются отдельным слоем.

## Strict-PQ security contract

### Transport

Managed v6 product transport требует:

- TLS **1.3 only**;
- реально согласованный `X25519MLKEM768`;
- проверенный server CA / SNI;
- ML-DSA-65 client certificate;
- отсутствие автоматического перехода на classical TLS/control transport.

Если эти условия не выполнены, managed operational request должен завершиться ошибкой.

### XSP/2 envelope

Управляющие сообщения связываются с:

- protocol/suite/direction;
- message type;
- issuer и Node ID;
- HTTP method/path;
- Ed25519 и ML-DSA-65 key IDs;
- key epoch;
- issued/expires time;
- nonce;
- request ID;
- release revision;
- SHA-256 payload.

Envelope принимается только после проверки **обеих** подписей: Ed25519 и ML-DSA-65.

### Live freshness и durable activation receipt

У v6 намеренно разные правила для живого сообщения и уже зафиксированного durable proof:

- свежий activation/tunnel response обязан пройти live freshness window;
- после успешной активации exact receipt сохраняется локально и его SHA-256 фиксируется в `active.json`;
- последующие `verify-active` снова проверяют endpoint binding, Node ID, request ID, panel issuer/key IDs, key epoch и **обе** подписи;
- исторический durable activation receipt не объявляется недействительным только потому, что прошёл его первоначальный live TTL;
- live operational responses по-прежнему проверяются на свежесть.

Именно разделение live freshness и durable cryptographic evidence исправлено в [PR #60](https://github.com/TriplexCorp/XMesh-Node/pull/60). Оно не включает classical fallback и не ослабляет freshness для сетевого tunnel traffic.

## Основной способ установки: из XMesh Nexus

Для managed Node используйте **команду, которую выдаёт Nexus** в разделе подключения ноды. Панель закрепляет reviewed XMesh-Node SHA и выдаёт одноразовый enrollment token отдельно от bootstrap-команды.

Fresh v6 bootstrap требует:

- Ubuntu;
- systemd;
- root/sudo;
- исходящий HTTPS;
- интерактивный TTY для первоначального одноразового token;
- exact 40-hex reviewed `XMESH_NODE_RELEASE_REF`.

Общая форма команды:

```bash
curl --proto '=https' --tlsv1.2 \
  -H 'Cache-Control: no-cache' \
  -fsSLo /tmp/xmesh-bootstrap-v6.sh \
  https://raw.githubusercontent.com/TriplexCorp/XMesh-Node/2745b03677fc6e12761021c5dad6d48138af87d4/bootstrap.sh

grep -Fq 'XMesh Node v6 fresh installer. Security invariant:' /tmp/xmesh-bootstrap-v6.sh

sudo env XMESH_NODE_RELEASE_REF=2745b03677fc6e12761021c5dad6d48138af87d4 \
  bash /tmp/xmesh-bootstrap-v6.sh https://panel.example.com NODE_ID NODE_PORT
```

Предпочтительный вариант — **не собирать эту команду вручную**, а копировать её из актуальной панели Nexus: там уже подставлены правильные panel origin, Node ID, port и reviewed release SHA.

### Что делает bootstrap

До strict-PQ activation bootstrap:

- проверяет Ubuntu/systemd;
- устанавливает необходимые host dependencies и Docker/Compose, если их нет;
- checkout'ит **только exact reviewed Node SHA**;
- останавливает старые managed timers/runtime на время security gate;
- собирает и устанавливает strict-PQ product client;
- создаёт/использует dual-key identity и ML-DSA TLS identity;
- выполняет owner-authorized enrollment и activation;
- проверяет signed durable receipt.

Только после успешного gate он:

- запускает XMesh router;
- устанавливает strict-PQ operational adapter;
- включает metrics/control/Xray reconciliation timers;
- разрешает managed Xray стартовать через desired-config reconciliation.

Ключевой инвариант `bootstrap.sh`:

```text
NO router, Xray, metrics, control or reconciliation runtime may start
until the strict-PQ product client has verified a durable activation receipt.
```

## Повторный запуск / repair уже активированной ноды

Если `/var/lib/xmesh-agent/product/active.json` и сохранённый receipt валидны, новый bootstrap сначала выполняет `verify-active`. При успехе он выводит:

```text
Existing strict-PQ activation receipt verified.
```

и **не требует новый enrollment token** только ради повторной установки reviewed runtime.

Не удаляйте вручную:

- `/var/lib/xmesh-agent/product/`;
- `/var/lib/xmesh-agent/xsp-v2/keys/`;
- client certificate/private key;
- durable activation receipt;

если задача — обычный repair/update. Удаление этих данных меняет identity/recovery semantics и должно выполняться только как отдельная осознанная процедура.

## Проверка после установки

### 1. Durable strict-PQ activation

```bash
sudo /usr/local/bin/xmesh-agent-xspv2-product \
  verify-active \
  --panel https://panel.example.com \
  --node-id NODE_ID

sudo cat /var/lib/xmesh-agent/product/active.json
```

Ожидаемые claims:

```json
{
  "schema": "xmesh-v6-strict-pq-active-1",
  "productionActivation": true,
  "strictPQEnabled": true,
  "automaticClassicalFallback": false
}
```

### 2. Core operational timers

```bash
systemctl status xmesh-node-control.timer --no-pager
systemctl status xmesh-node-metrics.timer --no-pager
systemctl status xmesh-xray-sync.timer --no-pager
```

### 3. Последние operational runs

```bash
systemctl status xmesh-node-control.service --no-pager
systemctl status xmesh-node-metrics.service --no-pager
systemctl status xmesh-xray-sync.service --no-pager

journalctl \
  -u xmesh-node-control.service \
  -u xmesh-node-metrics.service \
  -u xmesh-xray-sync.service \
  -n 100 --no-pager
```

### 4. Containers

```bash
docker ps --filter name=xmesh-node
docker ps --filter name=xmesh-managed-xray
```

Managed Xray может отсутствовать/быть остановлен до получения корректного desired config. Наличие router container само по себе не доказывает применение Xray policy.

## Operational services

Три основных v6 workers:

| Unit | Назначение |
| --- | --- |
| `xmesh-node-metrics.service` | telemetry/metrics через strict-PQ product transport |
| `xmesh-node-control.service` | heartbeat, polling и control operations через strict-PQ transport |
| `xmesh-xray-sync.service` | signed policy / desired-config reconciliation и managed Xray |

Для совместимости существующая worker business logic может локально формировать исторические Ed25519 headers, но network `curl` подменяется узким strict-PQ adapter'ом. Эти historical headers не являются сетевой авторизацией XSP/2 и не создают classical fallback.

## Xray policy и reconciliation

`xmesh-xray-sync` сохраняет fail-safe поведение:

- применяет только проверяемую policy/config;
- не заменяет рабочую Xray конфигурацию неподтверждёнными данными;
- может находиться в `awaiting_profile`, если профиль ещё не назначен;
- запускает managed Xray только после разрешённого reconciliation;
- использует `xmesh-policy-guard.py` и локальную attestation для проверки состава пользователей и активного JSON.

Если panel временно недоступна, текущий Xray не должен быть уничтожен только из-за transport error. Offline policy применяется только если ранее была выдана и локально проходит требуемые проверки.

## Router / edge capabilities

Сам XMesh Node router:

- маршрутизирует TCP TLS по **exact SNI** и wildcard suffix;
- может учитывать ALPN;
- передаёт исходный ClientHello в backend без TLS termination;
- имеет default TCP route для unknown/missing SNI, если он настроен;
- поддерживает отдельный UDP listener и **один явно заданный UDP backend**;
- позволяет TCP и UDP использовать одинаковый номер публичного порта как разные transport sockets;
- ограничивает буферы/таймауты/concurrency;
- принимает только loopback backend addresses по policy конфигурации.

### Важные границы

XMesh Node **не** является универсальным мультиплексором любого протокола на одном socket.

- TCP и UDP могут использовать один numeric port, потому что это разные transport sockets.
- Несколько независимых QUIC/UDP протоколов нельзя безопасно разделить одним простым UDP forwarder без protocol-aware demux.
- Клиентов с одинаковыми SNI + ALPN нельзя надёжно разделить только по ClientHello.
- Router не завершает пользовательский TLS и не обходит authentication backend'а.

## Standalone Docker-router

Если нужен только edge router без managed Nexus control plane, можно использовать отдельный standalone path.

Требуются уже установленные Docker Engine и Compose:

```bash
git clone https://github.com/TriplexCorp/XMesh-Node.git
cd XMesh-Node
bash install.sh
nano config.json
bash install.sh
docker compose logs -f xmesh-node
```

Проверка конфигурации без запуска daemon:

```bash
docker compose run --rm --no-deps \
  xmesh-node -check -config /etc/xmesh-node/config.json
```

Standalone `install.sh`:

- не выполняет v6 Nexus enrollment;
- не создаёт strict-PQ activation;
- не устанавливает managed metrics/control/Xray timers;
- не делает standalone router автоматически «управляемой нодой» Nexus.

Compose использует `network_mode: host`, чтобы router мог обращаться к loopback backend'ам на host. Любой другой процесс, уже занимающий тот же IP/port/transport, конфликтует с router.

## Сборка и разработка

Основной router module использует Go `1.23+`:

```bash
go test ./...
go vet ./...
go build ./...
```

XSP/2 production-capable Agent artifacts и cryptographic test modules проверяются отдельными Go 1.27 CI jobs.

Полный CI репозитория проверяет, среди прочего:

- shell/Python syntax;
- router/unit tests с race detector;
- strict-PQ Go modules;
- production Agent artifact boundary;
- crash durability;
- snapshot anti-rollback;
- Docker image build/config check.

Для reviewed PR #60 exact-head CI перед merge был green в:

- `Node CI` #736;
- `XSP-v2 P0-D Agent Artifact` #97;
- `XSP-v2 P0-E Crash Durability` #86;
- `XSP-v2 P0-E Snapshot Anti-Rollback` #84.

CI подтверждает код и тестовые contracts на проверенном SHA; это не заменяет диагностику конкретной VPS.

## Troubleshooting

### `panel response binding rejected` через несколько минут после activation

Если нода была установлена со старым reviewed SHA `7b6ec04d7dfe6e9b785f9988b5c43afb64499456`, operational workers могли начать падать примерно после окончания первоначального live freshness window.

Причина была не в PQ handshake: `verify-active` повторно применял live TTL к уже сохранённому durable activation receipt. Исправление находится в release:

```text
2745b03677fc6e12761021c5dad6d48138af87d4
```

Обновите Nexus и повторно запустите выданную им bootstrap-команду. При валидной сохранённой activation identity новый enrollment token для обычного repair не требуется.

### Xray CLI unavailable in metrics

Сообщение вида:

```text
Xray CLI not installed on host (possibly containerized)
```

означает, что host-side collector не нашёл ожидаемый CLI. Это нужно разбирать отдельно от strict-PQ transport. Само по себе оно не объясняет `panel response binding rejected`.

### Диагностические команды

```bash
journalctl -u xmesh-node-control.service -n 100 --no-pager
journalctl -u xmesh-node-metrics.service -n 100 --no-pager
journalctl -u xmesh-xray-sync.service -n 100 --no-pager

docker logs --tail 100 xmesh-node
docker logs --tail 100 xmesh-managed-xray
```

## Документация

Актуальные security contracts и исторические XSP/2 материалы остаются в `docs/`:

- [`docs/POSTQUANTUM_SECURITY_INVARIANT.md`](docs/POSTQUANTUM_SECURITY_INVARIANT.md)
- [`docs/POSTQUANTUM_V6.md`](docs/POSTQUANTUM_V6.md)
- [`docs/STRICT_PQ_ONLY.md`](docs/STRICT_PQ_ONLY.md)
- [`docs/STRICT_PQ_ONLY_BOOTSTRAP.md`](docs/STRICT_PQ_ONLY_BOOTSTRAP.md)
- [`docs/XSP_V2_CRYPTO_POC.md`](docs/XSP_V2_CRYPTO_POC.md)
- [`docs/XSP_V2_WIRE_SPEC.md`](docs/XSP_V2_WIRE_SPEC.md)
- [`docs/XSP_V2_APPLIED_ACK_VAULT_GATE.md`](docs/XSP_V2_APPLIED_ACK_VAULT_GATE.md)

Общий product/security roadmap ведётся в XMesh Nexus:

- [Enterprise Roadmap](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/docs/ENTERPRISE_ROADMAP.md)
- [PQ-only security policy](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/docs/XSP_V2_PQ_ONLY_SECURITY_POLICY.md)
- [Single public TCP/443 control-plane topology](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/docs/SINGLE_PUBLIC_443_CONTROL_PLANE.md)

## Security reporting / operational rule

Не публикуйте в issues или логах:

- enrollment tokens;
- private Ed25519/ML-DSA keys;
- client private TLS keys;
- production secrets из Nexus/Node environment.

Для production incident сначала сохраняйте точные service logs, active receipt metadata и reviewed source SHA. Не лечите strict-PQ failure включением classical fallback: v6 contract намеренно fail-closed.

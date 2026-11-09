# Managed Xray update transaction (Agent control-v6.0.11)

## Confirmed defect

The control-v6.0.9 updater mounted the config and optional GeoData only, while
`XMesh-Node/deploy/xmesh-xray-sync.sh` mounted the complete `/etc/letsencrypt`
tree for both validation and runtime. A TLS configuration referring to `live/`
symlinks therefore failed `xray run -test` during updates. The same omission
also affected new-container startup and reconstruction of the old image.
The old updater discarded stdout (where Xray prints its configuration error)
and replaced the error with `New Xray image failed config validation`.

The disposable reproduction uses an actual official GHCR image and one config:
without the runtime certificate mount Xray exits 23; with the read-only tree it
passes. No production-node configuration was accessed. This proves the TLS
mount defect; it does not assert that every production validation failure has
that cause. The new diagnostics also distinguish config, GeoData, permissions,
Docker execution, registry and runtime failures.

## Operation

1. The panel verifies the official release and GHCR image before queueing a
   fixed `{version}` command. Updating Xray requires Agent 6.0.11+; older agents
   can still enroll and receive the signed Agent upgrade.
2. The signed Agent invokes a locally installed, version-matched worker. It
   shares the synchronizer's lock and records a durable per-command journal.
3. The worker inspects the actual managed container, config bind and read-only
   mounts, including the whole certificate/symlink tree and GeoData. It checks
   that the config visible inside the old container matches the host source.
4. It pulls only the selected official tag, checks the immutable image ID and
   the binary version, and runs bounded isolated `run -test` with those resources.
5. It creates a candidate before touching the serving container. After preflight,
   the old container is stopped and renamed, never reconstructed from guesses.
   The candidate is started and checked for image identity, process stability,
   restart count and TCP listeners. UDP-only transport semantics are not inferred
   from a TCP probe; the integration test additionally transfers real TLS traffic.
6. Successful runtime evidence precedes the persisted official tag + immutable ID.
   Subsequent config synchronization uses that ID rather than resolving the tag.
   The latest stopped rollback container retains its exact image/config/mounts.
7. On a failed switch the exact old container is restored and checked. Rollback
   failure is distinct from verified rollback. Interrupted switches recover on
   redelivery; exact completed command/ACK retries do not perform another update.

Only the specifically owned staged/validation containers can be cleaned up.
Existing Docker volumes (including the official image's automatically declared
config/log volumes), their access modes and the working directory are preserved.
Writable bind mounts and unsupported resource types fail preflight without touching Xray.
Concurrent manual Docker edits outside the managed services are unsupported.

## Diagnostics and privacy

The signed progress endpoint accepts only closed stage/error/rollback codes and
an exit status. Raw stdout/stderr, config JSON, Reality keys, TLS keys, credentials
and environment values are never uploaded to the panel. Local captures are 0600,
64 KiB per stdout/stderr file and at most 64 retained capture files per command.
The actual config snapshot is separately private and bounded to 4 MiB. Raw
captures and snapshots are retained for the latest ten transactions; completed
result journals are retained for idempotence. Interrupted older transactions are
recovered before a later command can switch the live container.

Single-node operations show actual stages on the action button. Bulk operations
keep a separate command/result for each node. Failure diagnostics remain available
in the single-node dialog and the bulk result list, translated to RU/EN.

Read-only inventory on a production node (no stops, pulls or container changes):

```sh
sudo python3 - <<'PY'
import json,os,stat,subprocess
v=json.loads(subprocess.check_output(['docker','inspect','xmesh-managed-xray']))[0]
mounts=v.get('Mounts',[])
c=next((m for m in mounts if m['Destination']=='/etc/xray/config.json'),None)
summary={'running':v['State']['Running'],'imageId':v['Image'],
 'user':v['Config'].get('User'),'readOnlyRoot':v['HostConfig']['ReadonlyRootfs'],
 'networkMode':v['HostConfig']['NetworkMode'],
 'tlsTreeMounted':any(m['Destination']=='/etc/letsencrypt' and not m.get('RW') for m in mounts),
 'assetTreeMounted':any(m['Destination']=='/usr/local/share/xray' and not m.get('RW') for m in mounts)}
if c:
 s=os.stat(c['Source']);summary['configOwnerUid']=s.st_uid;summary['configMode']=oct(stat.S_IMODE(s.st_mode))
print(json.dumps(summary,indent=2))
PY
```

Share only this filtered output and the safe stage/error/exit code. Root-only raw
captures under `/var/lib/xmesh-xray-sync/updates/<command-id>/` may contain secrets;
do not paste or upload them unredacted. Their presence does not authorize exporting
production credentials.

## Release / rollout

This is a coordinated Nexus + Node Agent patch to control-v6.0.11. The source
version, backend target, strict-PQ gateway, bootstrap/updater validators and Node
product identity checks must agree. Build release identities from the exact
reviewed Node commit; do not substitute placeholder source revisions/digests or
reuse a 6.0.9 binary. Existing immutable staged-release verification remains active.

Publish/review the paired Node change and Nexus control-plane change together.
After their green CI and release publication, update the panel and upgrade Agent
on one noncritical canary through its existing signed update action. Verify its
6.0.11 version and strict-PQ release identity before selecting an official Xray
version. Then roll out the Agent and Xray update in batches. No production nodes
are modified by this development task. Do not merge red or conflicted PRs.

## Executable evidence

- `scripts/test-xray-update-unit.py`: preflight, stage/health faults, exact rollback,
  crash recovery, repeated delivery, immutable result and bounded private logs.
- `scripts/test-xray-update-ui.cjs`: actual single/bulk operation implementation,
  stage callbacks, per-node failure isolation, diagnostics and version refresh.
- `scripts/test-managed-xray-transaction.py`: official 26.10.21 to 26.10.31, real
  TLS HTTP data plane before/after, actual incompatible config and missing resources,
  controlled registry/start failures, checked rollback and no second update on retry.
  CI runs this as root so host UID/mode match production 0600 mounts. The local
  limited-disk reproduction can run with `XMESH_TEST_REPRO_ONLY=1` and one official
  image; that mode proves only the mount defect, not a two-version update.
- Real API integration covers verified queueing, signed progress, private-field
  rejection, safe claimed redelivery, exact ACK replay and terminal-state immutability.

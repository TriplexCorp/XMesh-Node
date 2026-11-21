# V1 offline budget: cross-Node partial acknowledgement remediation

## Why this matters

The current signed V1 desired policy contains `panelUsedBytes`, an
**aggregate user total**. It does not specify how many bytes were acknowledged
for *this Node*, nor an immutable per-Node reservation/grant identity. Before
this patch, changing that number in a newer signed policy reset the Node's
local `anchor` and `budget`. A delayed report from Node A while Node B's
already-reported bytes change the global total could therefore reissue Node
A's already consumed offline allowance.

This is a real **guard-level invariant failure** reproduced by the audit in
Node #88. It is not evidence that an end-to-end two-VPS exploit was completed.

## What the conservative guard patch enforces

- Once the Node first accepts a signed V1 policy, its original local
  `anchor` is a non-resettable absolute ledger baseline. The local
  `budget` may shrink, but cannot increase from aggregate usage changes,
  policy renewal, quota plan upgrades, or repeated policy polling.
- Changing `panelUsedBytes` is retained only as diagnostic monotonic
  metadata; **it cannot acknowledge this Node's unsettled bytes**.
- A signed new expiry can remove an *expiry-only* local denial if and only
  if the original offline bytes still remain. Expiry renewal never
  clears a quota-exhaustion denial.
- An old unlimited allowance becoming limited gets **zero offline grant**
  until a separately proven Node-scoped authorization exists; a previously
  finite allowance cannot become unlimited solely through a global
  policy refresh. Online ordinary policy paths are not recast as new V2
  settlements; only local offline grants are affected here.
- Sticky quota denials survive process restarts and changes in total user
  consumption on other Nodes. The same-runtime and replay checks stay intact.

This patch deliberately does **not** claim a complete V1 allocator fix, a
new signed lease protocol, or production approval. The test exercises actual
`enforce()` decisions with two independent persisted ledgers; it does not
exercise live Nexus PostgreSQL/metrics transactions.

## Compatibility caveat and production rollout condition

The old behavior allowed a new global usage snapshot, plan upgrade, or
subscription reset to implicitly reissue offline budget. That was unsafe.
After this patch those events do **not** replenish exhausted offline
allowances. If a user legitimately resets traffic or purchases more traffic,
the user may remain locally denied while offline until a Node-scoped grant
or safe V2 migration provides explicit authority.

Before merging as a production V1 fix, either:
1. implement **durable, per-Node signed grant/acknowledgement epochs** with
   strictly serialized global reservation conservation, with clear reset,
   plan increase, reassignment, Node deletion and prior outstanding lease
   behavior; or
2. approve and document this deliberately fail-closed V1 compatibility
   tradeoff with an operational remediation path.

Required follow-up: real two-Agent/Nexus/PostgreSQL failure/retry and
partial-acknowledgement tests, including delayed and duplicate usage uploads;
the final `panelUsedBytes` regression must be based on real policy issuance
and signed application. V2 reservation/policy semantics remain separate,
and `XMESH_QUOTA_V2_ENABLED=0` is unchanged.

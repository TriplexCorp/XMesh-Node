# Meter snapshot retention review — 2026-11-17

Node baseline: 647adcf7af326b205fce12545fb5d75a20bb8191. Nexus baseline reviewed: fdf6f5ed95573cc5582a1c395d66dafb84253cd7.

Source trace: policy guard integrate_counters retains historical users/inbounds; store_metrics_snapshot publishes all retained inbound records without current-policy filtering. The unprivileged Nexus metrics uploader reads this snapshot and curl --fail exits on a rejected upload. No successful-upload acknowledgment prunes the root-owned meter history. Retained cumulative totals protect against immediate loss on an isolated upload failure, but a retired object can remain in subsequent packets after reconciliation. Combined with Nexus whole-batch object-scope rejection, this may indefinitely delay accounting for otherwise authorized users.

The new no-network characterization test records this behavior: a later observation contains only one active user, but the published snapshot still includes the retired user's cumulative total. A passing test is evidence of current behavior, NOT security approval or a fix. It writes no files and performs no production requests.

Next: reproduce an actual signed policy change end to end, including inbound removal while a user retains another inbound; filter the published view using authenticated current user/inbound scope while preserving the durable ledger. Test retries, restart, scope restoration, exact server delta and first-baseline behavior. Do not erase historic totals, weaken Nexus authorization or drop bad rows server-side without an explicit contract. Coordinate runtime/Agent version policy for any subsequent fix.

Status: source observation; characterization CI pending. Full policy-change impact and recovery duration remain to be measured.

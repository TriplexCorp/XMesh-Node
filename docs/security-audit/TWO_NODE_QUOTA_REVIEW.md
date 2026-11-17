# Two-node offline quota review — 2026-11-17

Pinned Node baseline: 48c299f842475e191e2eb6bc05de709f5e53da5f; reviewed Nexus policy issuer: f0715e5f21c38deabaa78308ebd8438c6f00781f.

## Actual execution

Test revision 5ba7f8444a639a0f76d8de2079d6381ddd10a95e, GitHub Actions job 133817951365: four tests ran, three passed, one failed. Passing cases: separate original offline allowances enforce cutoff; replay, JSON process-state reload and Xray restart preserve spending; missing counters and expired policy fail closed.

The failing required invariant is cross-node partial acknowledgement. The actual guard enforce() implementation resets its local anchor when global panelUsedBytes changes. A shared user-wide counter does not identify which node's local bytes have been acknowledged. In the generated two-ledger model, a fresh policy reflecting only the other node's accepted usage permits renewed local spending that the previous offline allowance would reject.

## Evidence boundary

This is a reproduced guard-level behavior, NOT a completed two-running-agent/Nexus/VPN exploit. The policy issuance order is modeled using the reviewed issuer fields; real desired-config polling versus metrics upload timing, network recovery, PostgreSQL totals and issuance serialization still require an isolated integration reproduction. Severity/CVSS is not assigned from the model alone. No production request, runtime change or merge was performed.

## Coordinated remediation requirements

1. Reproduce the same ordering with two enrolled disposable identities and the actual Nexus policy issuer; assert exact global and per-node PostgreSQL deltas.
2. Distinguish node-specific acknowledgement from aggregate user usage. Consider outstanding reservations/lease identity, epoch and monotonic acknowledgement rather than resetting local spending solely on a shared total.
3. Preserve legitimate quota resets, expiry renewal, plan increases, node removal/reassignment, old-agent upgrade and offline cutoffs. A local patch that never advances an anchor would break legitimate replenishment; accepting unsigned acknowledgement would break authorization.
4. Verify conservation across simultaneous lease issuance, disabled nodes retaining unexpired leases, partial recovery and repeated uploads. Keep the existing failing regression enabled until the protocol invariant is satisfied.

Other unresolved matrix items: concurrent real API spending, full outage/reconnection, fleet membership changes, proof of reservation conservation and end-to-end recovery. This block is not complete; no increase in overall audit percentage is claimed solely from adding the model tests.

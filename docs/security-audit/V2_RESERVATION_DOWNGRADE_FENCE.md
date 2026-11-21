# Quota V2 reservation downgrade fence

A signed policy with `limitBytes=0` and no `quotaReservation` is NOT
proof that a previously signed limited Node lease has been settled or
revoked. A stale Node can still hold unreported spend against that old
lease. The old policy guard admitted the new unlimited policy on the
unreserved path when it saw no current user limit; this dropped the old
reserved-byte constraint and bypassed the `quotaMeterContinuityLost` and
signed revocation checks that only apply to limited V2 users.

The guard now refuses to switch any user **with a durable prior
`quotaReservation` field** to an unreserved V2 unlimited or V1 policy.
It rejects malformed retained reservations as well; it never treats
corruption as proof of a clean slate. The same Node and user in a truly
fresh unlimited v2 policy, with NO previous reservation, continue
working without change.

Positive re-admission after a legitimate limited-to-unlimited plan
change requires an **explicit, signed, serializable reservation-close
contract** from Nexus, covering all outstanding budget, old runtime
stop/meter finality, and durable consumed-byte carryforward. That
contract does not exist here. Until it does, the downgrade is blocked
rather than silently unlocking the data plane.

Tests cover direct offline/online guard calls and a separately signed
Ed25519 envelope applied through the real policy guard CLI. The
failed signed prepare must not overwrite the committed prior policy.

This PR is stacked on the experimental Agent 6.0.25 branch and
does NOT enable `XMESH_QUOTA_V2_ENABLED`, issue refunds, alter
production, or qualify WAL birth-index as terminal traffic.

#!/usr/bin/env python3
"""CI-only NONFINAL observed Xray meter floor validation.

The Node's durable journal is a lower bound, not a final counter. The live
container identity MUST be independently discovered by trusted Docker inspect.
Nothing here proves all Xray background writers have completed or permits
refunds / terminal settlement.
"""
import json
from urllib.parse import unquote

MAX_METER = (1 << 63) - 1


def unsigned_byte(value, name):
    if type(value) is not int or not 0 <= value <= MAX_METER:
        raise ValueError(f"invalid durable {name}")
    return value


def exact_docker_runtime(container):
    if not isinstance(container, tuple) or len(container) != 3:
        raise ValueError("untrusted managed Xray runtime")
    cid, started, pid = container
    if (not isinstance(cid, str) or len(cid) != 64 or
            not all(c in "0123456789abcdef" for c in cid) or
            not isinstance(started, str) or not started or
            type(pid) is not int or pid <= 0):
        raise ValueError("invalid Docker runtime identity")
    return cid + " " + started


def verify_monotonic_meter_floor(ledger, checkpoint, managed_runtime):
    """Reject a signed observation below durable same-Xray StatsService history.

    This function MUST run only AFTER the committed signed Node policy has
    verified every actual per-inbound Xray identity and the Node has verified
    the runtime PID through independently inspected Docker + kernel pidfd.
    It compares RAW counters only for the SAME Docker runtime, never resets
    the previous incarnation's absolute paid bytes to zero.
    """
    if not isinstance(ledger, dict) or not isinstance(checkpoint, dict):
        raise ValueError("missing durable Node meter or Xray observation")
    if ledger.get("runtimeId") != exact_docker_runtime(managed_runtime):
        raise ValueError("durable Node meter belongs to another Xray runtime")
    uid = checkpoint.get("userId")
    if type(uid) is not int or uid <= 0:
        raise ValueError("invalid observed billing user")
    users = ledger.get("users")
    record = users.get(str(uid)) if isinstance(users, dict) else None
    if not isinstance(record, dict):
        raise ValueError("durable Node user meter missing")
    # The Agent latches a LOST-CONTINUITY marker on same-runtime reset,
    # vanished counters, or replacement without a terminal old-process
    # proof. It is never safe to sign a deceptively clean current reading
    # after this permanent user-scoped incident.
    if "quotaMeterContinuityLost" in record:
        raise ValueError("sticky quota-v2 meter continuity loss forbids observation")
    last = unsigned_byte(record.get("last"), "user raw counter")
    durable_total = unsigned_byte(record.get("total"), "absolute user total")
    rows = checkpoint.get("inboundMeters")
    inbound = ledger.get("inbounds")
    if not isinstance(inbound, dict) or not isinstance(rows, list) or (
            not 0 < len(rows) <= 16):
        raise ValueError("durable per-inbound meter missing")
    up = down = 0
    last_up = last_down = 0
    cumulative_inbound = 0
    seen = set()
    prefix = f"xmesh-u{uid}--"
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "email", "uplinkBytes", "downlinkBytes"}:
            raise ValueError("invalid Xray inbound meter row")
        email = row["email"]
        if not isinstance(email, str) or not email.startswith(prefix):
            raise ValueError("observed Xray inbound belongs to another user")
        tag = unquote(email[len(prefix):], encoding="utf-8", errors="strict")
        if not tag or tag in seen or any(ord(c) < 32 for c in tag):
            raise ValueError("duplicate or malformed Xray inbound identity")
        seen.add(tag)
        key = json.dumps([uid, tag], separators=(",", ":"))
        floor = inbound.get(key)
        if not isinstance(floor, dict):
            raise ValueError("durable signed inbound floor missing")
        current_up = unsigned_byte(row["uplinkBytes"], "observed uplink")
        current_down = unsigned_byte(row["downlinkBytes"], "observed downlink")
        prior_up = unsigned_byte(floor.get("lastUp"), "inbound uplink floor")
        prior_down = unsigned_byte(floor.get("lastDown"), "inbound downlink floor")
        cumulative_up = unsigned_byte(
            floor.get("totalUp"), "inbound cumulative uplink")
        cumulative_down = unsigned_byte(
            floor.get("totalDown"), "inbound cumulative downlink")
        if cumulative_up < prior_up or cumulative_down < prior_down:
            raise ValueError("durable inbound cumulative bytes below current raw floor")
        cumulative_inbound += cumulative_up + cumulative_down
        if cumulative_inbound > MAX_METER:
            raise ValueError("cumulative signed inbound meter overflow")
        if current_up < prior_up or current_down < prior_down:
            raise ValueError("Xray inbound counter regressed below durable Node floor")
        up += current_up
        down += current_down
        last_up += prior_up
        last_down += prior_down
        if up + down > MAX_METER or last_up + last_down > MAX_METER:
            raise ValueError("multi-inbound meter total overflow")
    if up + down < last or last < last_up + last_down:
        raise ValueError("Xray user counter regressed below durable Node floor")
    if (type(checkpoint.get("uplinkBytes")) is not int or
            type(checkpoint.get("downlinkBytes")) is not int or
            up != checkpoint["uplinkBytes"] or down != checkpoint["downlinkBytes"]):
        raise ValueError("Xray combined observed bytes differ from per-inbound meters")
    if durable_total < last:
        raise ValueError("durable absolute meter is below its raw counter")
    # The SAME Xray runtime has monotonic raw counters. Extend both
    # independently journalled absolute histories by only the new observed
    # raw delta; the sum of the signed per-inbound histories must never
    # exceed the account's own absolute history. Otherwise one side lost
    # bytes despite each individual raw reading appearing monotonic.
    observed_delta = up + down - last
    inbound_delta = up + down - (last_up + last_down)
    user_absolute_at_observation = durable_total + observed_delta
    inbound_absolute_at_observation = cumulative_inbound + inbound_delta
    if user_absolute_at_observation > MAX_METER or (
            inbound_absolute_at_observation > MAX_METER):
        raise ValueError("observed absolute Xray counter overflow")
    if inbound_absolute_at_observation > user_absolute_at_observation:
        raise ValueError("signed inbound cumulative bytes exceed user absolute meter")
    return {"sameDockerRuntime": True, "aboveDurableFloor": True,
            "durableAbsoluteBytes": durable_total,
            "observedRawBytes": up + down,
            "finalMeterVerified": False, "refundableBytes": 0}

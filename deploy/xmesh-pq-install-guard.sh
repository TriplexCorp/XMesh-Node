#!/usr/bin/env bash
# Sourced by fresh-install entry points. This is not an upgrade authorization.
xmesh_product_binding_exists() {
  local state="$1" entry
  if [[ -L "$state" || ( -e "$state" && ! -d "$state" ) ]]; then
    return 0
  fi
  # The encrypted keyring can reach disk before the first product config.
  # No signed key may be treated as a fresh installation after SIGKILL.
  for entry in config.json activation-request.json activation-receipt.json active.json \
    client-key.pem client.pem server-ca.pem panel-pin.json; do
    if [[ -e "$state/$entry" || -L "$state/$entry" ]]; then
      return 0
    fi
  done
  local ring="${state%/*}/xsp-v2/keys"
  if [[ -L "${state%/*}/xsp-v2" || -L "$ring" ||
        ( -e "$ring" && ! -d "$ring" ) ]]; then
    return 0
  fi
  for entry in node-request.master node-request.vault; do
    if [[ -e "$ring/$entry" || -L "$ring/$entry" ]]; then
      return 0
    fi
  done
  return 1
}

xmesh_refuse_quota_cold_install() {
  local state="$1" evidence
  if [[ -L "$state" || ( -e "$state" && ! -d "$state" ) ]]; then
    echo 'Untrusted quota state path; refusing cold install.' >&2
    return 2
  fi
  for evidence in "$state"/{genesis-quarantine-envelope.json,genesis-reservation-prepared-u*.json,genesis-reservation-confirmed-u*.json,genesis-positive-cap-u*.json,genesis-renewal-u*.json,genesis-renewal-request-u*.json,calendar-*-u*.json,wal-cap-u*.json,wal-charge-*.json,ingress-u*,xmesh-quota-u*}; do
    if [[ -e "$evidence" || -L "$evidence" ]]; then
      echo 'Quota V2 spending evidence exists; use a verified coordinated upgrade, not a cold install.' >&2
      return 2
    fi
  done
}

xmesh_require_unchanged_binary() {
  local installed="$1" candidate="$2" actual mode owner
  if [[ ! "$candidate" =~ ^[a-f0-9]{64}$ || ! -f "$installed" || -L "$installed" || ! -x "$installed" ]]; then
    echo 'Existing enrolled Agent has no safely verifiable installed artifact; coordinated recovery required.' >&2
    return 2
  fi
  owner="$(stat -c '%u' -- "$installed")" || return 2
  mode="$(stat -c '%a' -- "$installed")" || return 2
  if [[ "$owner" != 0 || ! "$mode" =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 0022) != 0 )); then
    echo 'Existing enrolled Agent artifact has unsafe ownership or permissions.' >&2
    return 2
  fi
  actual="$(sha256sum -- "$installed")" || return 2
  if [[ "${actual%% *}" != "$candidate" ]]; then
    echo 'Candidate differs from the enrolled Agent; coordinated signed upgrade required. Existing artifacts unchanged.' >&2
    return 2
  fi
}

# A bound Agent is never sent through enrollment again after a lost receipt.
# Called before stopping any operational service; root-owned product CLI
# verifies the original dual signatures, release identity and local files.
xmesh_verify_or_resume_enrolled_product() {
  local state="$1" product="$2" panel="$3" node="$4"
  if [[ -L "$state" || ( -e "$state" && ! -d "$state" ) ]]; then
    echo 'Invalid PQ product state root; refusing enrollment.' >&2
    return 2
  fi
  if [[ -d "$state" && "$(stat -c '%u:%a' -- "$state")" != "0:700" ]]; then
    echo 'PQ product directory must be owned by root with mode 0700.' >&2
    return 2
  fi
  if ! xmesh_product_binding_exists "$state"; then
    printf '%s\n' fresh
    return 0
  fi
  for entry in config.json activation-request.json activation-receipt.json active.json \
    client-key.pem client.pem server-ca.pem panel-pin.json; do
    if [[ -L "$state/$entry" ]]; then
      echo 'PQ product symlink state is not recoverable.' >&2
      return 2
    fi
  done
  if [[ ! -x "$product" || -L "$product" ]]; then
    echo 'Enrolled PQ product binary unavailable.' >&2
    return 2
  fi
  if "$product" verify-active --panel "$panel" --node-id "$node" >/dev/null 2>&1; then
    printf '%s\n' active
    return 0
  fi
  # Never "repair" an invalid existing active marker or incomplete state
  # by consuming a new enrollment token; fail closed before router changes.
  if [[ -e "$state/active.json" || -L "$state/active.json" ||
        ! -f "$state/config.json" || -L "$state/config.json" ||
        ! -f "$state/activation-request.json" || -L "$state/activation-request.json" ]]; then
    echo 'Unsafe or incomplete PQ activation; coordinated recovery required.' >&2
    return 2
  fi
  if ! "$product" resume-activation >/dev/null; then
    echo 'Original PQ activation could not be recovered; re-enrollment refused.' >&2
    return 2
  fi
  if ! "$product" verify-active --panel "$panel" --node-id "$node" >/dev/null 2>&1; then
    echo 'Recovered Agent failed original PQ activation verification.' >&2
    return 2
  fi
  printf '%s\n' resumed
}

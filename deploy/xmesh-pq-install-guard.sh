#!/usr/bin/env bash
# Sourced by fresh-install entry points. This is not an upgrade authorization.
xmesh_product_binding_exists() {
  local state="$1" entry
  if [[ -L "$state" || ( -e "$state" && ! -d "$state" ) ]]; then
    return 0
  fi
  for entry in config.json activation-request.json activation-receipt.json active.json; do
    if [[ -e "$state/$entry" || -L "$state/$entry" ]]; then
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

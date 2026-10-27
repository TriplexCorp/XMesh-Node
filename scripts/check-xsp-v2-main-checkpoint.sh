#!/usr/bin/env bash
set -euo pipefail
# CI inventory of test-only XSP-v2 artifacts. This is NOT a cryptographic
# validation or authorization to enable XSP-v2 in the production Node.
expected=(
  security/xspv2/poc-go/go.mod
  security/xspv2/poc-go/keyring/two_phase.go
  security/xspv2/poc-go/keyring/applied_attestation.go
  security/xspv2/poc-go/cutover/signed.go
  security/xspv2/poc-go/cutover/candidate.go
  security/xspv2/poc-go/cutover/permit_journal_linux.go
  security/xspv2/poc-go/cutover/applied_ack_journal_linux.go
  security/xspv2/poc-go/cutover/committed_vault_ack_linux.go
  security/xspv2/poc-go/cutover/committed_vault_ack_linux_test.go
  docs/XSP_V2_CUTOVER_CONTRACT_VECTORS.json
  docs/XSP_V2_CUTOVER_CANDIDATE_VECTORS.json
  docs/XSP_V2_APPLIED_ACK_VAULT_GATE.md
  .github/workflows/xsp-crypto-poc.yml
)
for file in "${expected[@]}"; do
  if [[ ! -f "$file" ]]; then
    printf 'ERROR: required XSP-v2 staging artifact missing: %s\n' "$file" >&2
    exit 1
  fi
done
if ! grep -Eq '^go 1\.27(\.[0-9]+)?$' security/xspv2/poc-go/go.mod; then
  printf 'ERROR: isolated PQ Go 1.27 module missing or misconfigured\n' >&2
  exit 1
fi
if grep -Fq 'security/xspv2/poc-go' go.mod; then
  printf 'ERROR: production Node root module must not depend on PQ PoC\n' >&2
  exit 1
fi
printf 'PASS: %s test-only Node XSP-v2 artifacts present and isolated\n' "${#expected[@]}"

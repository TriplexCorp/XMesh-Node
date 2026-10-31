#!/usr/bin/env bash
# Narrow curl-compatible adapter for existing XMesh workers.
# It intentionally supports ONLY the registered operational POST subset and
# always transports the request through xmesh-agent-xspv2-product. It never
# opens a network socket itself and has no classical HTTP fallback.
set -Eeuo pipefail
umask 077
export LC_ALL=C

: "${XMESH_API_URL:?XMESH_API_URL is required}"
: "${XMESH_NODE_ID:?XMESH_NODE_ID is required}"
[[ "${XMESH_STRICT_PQ_REQUIRED:-}" == 1 ]] || {
  echo "strict-PQ transport adapter requires XMESH_STRICT_PQ_REQUIRED=1" >&2
  exit 2
}
[[ "$XMESH_API_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || {
  echo "invalid XMesh panel origin" >&2; exit 2;
}
[[ "$XMESH_NODE_ID" =~ ^[1-9][0-9]*$ ]] || { echo "invalid XMesh node ID" >&2; exit 2; }
PRODUCT=/usr/local/bin/xmesh-agent-xspv2-product
[[ -x "$PRODUCT" ]] || { echo "strict-PQ product client missing" >&2; exit 1; }

method=""
url=""
data=""
output=""
write_out=""
fail_http=0
headers=()

while (($#)); do
  case "$1" in
    -X|--request)
      (($# >= 2)) || exit 2; method="$2"; shift 2;;
    -H|--header)
      (($# >= 2)) || exit 2; headers+=("$2"); shift 2;;
    --data-binary)
      (($# >= 2)) || exit 2; data="$2"; shift 2;;
    -o|--output)
      (($# >= 2)) || exit 2; output="$2"; shift 2;;
    -w|--write-out)
      (($# >= 2)) || exit 2; write_out="$2"; shift 2;;
    --max-time)
      (($# >= 2)) || exit 2; [[ "$2" =~ ^[1-9][0-9]{0,3}$ ]] || exit 2; shift 2;;
    --proto)
      (($# >= 2)) || exit 2; [[ "$2" == '=https' ]] || exit 2; shift 2;;
    --tlsv1.2|--tlsv1.3|--silent|--show-error|--location|-s|-S|-sS|-f|--fail)
      [[ "$1" == -f || "$1" == --fail ]] && fail_http=1
      shift;;
    http://*|https://*)
      [[ -z "$url" ]] || { echo "multiple URLs are not supported" >&2; exit 2; }
      url="$1"; shift;;
    *)
      echo "unsupported option in strict-PQ transport adapter: $1" >&2
      exit 2;;
  esac
done

[[ "$method" == POST ]] || { echo "strict-PQ adapter permits POST only" >&2; exit 2; }
base="${XMESH_API_URL%/}"
[[ "$url" == "$base"/* ]] || { echo "request destination is not the enrolled XMesh panel" >&2; exit 2; }
path="${url#"$base"}"
case "$path" in
  /api/v1/metrics/ingest|/api/v1/node/heartbeat|/api/v1/node/restart/poll|/api/v1/node/restart/ack|/api/v1/node/desired-config) ;;
  *) echo "unregistered strict-PQ operational path" >&2; exit 2;;
esac
for header in "${headers[@]}"; do
  case "${header%%:*}" in
    Content-Type|content-type|X-XMesh-Timestamp|x-xmesh-timestamp|X-XMesh-Nonce|x-xmesh-nonce|X-XMesh-Signature|x-xmesh-signature) ;;
    *) echo "unsupported header in strict-PQ transport adapter" >&2; exit 2;;
  esac
done

body_file="$(mktemp /run/xmesh-pq-body.XXXXXXXX)"
response_file="$(mktemp /run/xmesh-pq-response.XXXXXXXX)"
status_file="$(mktemp /run/xmesh-pq-status.XXXXXXXX)"
cleanup(){ rm -f "$body_file" "$response_file" "$status_file"; }
trap cleanup EXIT
chmod 0600 "$body_file" "$response_file" "$status_file"

if [[ "$data" == @* ]]; then
  source_file="${data#@}"
  [[ -f "$source_file" && ! -L "$source_file" && -r "$source_file" ]] || {
    echo "invalid strict-PQ request body file" >&2; exit 2;
  }
  cat -- "$source_file" > "$body_file"
else
  printf '%s' "$data" > "$body_file"
fi

# Product client re-verifies durable activation, ML-DSA TLS credentials and the
# dual-signed receipt before every request. Any failure exits here: no curl,
# no alternate URL, no TLS downgrade, no classical fallback.
"$PRODUCT" request \
  --path "$path" \
  --body-file "$body_file" \
  --output-file "$response_file" \
  --status-file "$status_file"

read -r status < "$status_file"
[[ "$status" =~ ^[1-5][0-9][0-9]$ ]] || { echo "invalid tunneled HTTP status" >&2; exit 1; }

if [[ -n "$output" ]]; then
  if [[ "$output" == /dev/null ]]; then
    :
  else
    cat -- "$response_file" > "$output"
  fi
else
  cat -- "$response_file"
fi
if [[ -n "$write_out" ]]; then
  [[ "$write_out" == '%{http_code}' ]] || { echo "unsupported write-out format" >&2; exit 2; }
  printf '%s' "$status"
fi
if (( fail_http )) && (( 10#$status >= 400 )); then
  exit 22
fi

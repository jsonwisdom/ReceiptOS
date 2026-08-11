#!/usr/bin/env bash
set -euo pipefail

# Local/allowed acquisition only. No UA spoofing, retry loop, or proxy logic.
# Produces an immutable capture directory and then invokes Gate 1 as a pure verifier.

BASE_DIR="${1:-ssa_public_replay/captures}"
SCOPE_FILE="${2:-ssa_public_replay/live_scope.txt}"
CAPTURE_ID="${CAPTURE_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
ROOT="$BASE_DIR/$CAPTURE_ID"
mkdir -p "$ROOT/raw" "$ROOT/headers" "$ROOT/failures"

if [[ -e "$ROOT/manifest.jsonl" ]]; then
  echo "MUTATION_PROHIBITED: capture already exists: $ROOT" >&2
  exit 2
fi

mapfile -t URLS < <(grep -Ev '^\s*(#|$)' "$SCOPE_FILE")
[[ ${#URLS[@]} -gt 0 ]] || { echo "EMPTY_SCOPE" >&2; exit 2; }

append_json_row() {
  local outfile="$1"
  python - "$outfile" <<'PY'
import json, os, sys
out = sys.argv[1]
row = {k.lower(): v for k, v in os.environ.items() if k.startswith('R_')}
row = {k[2:]: v for k, v in row.items()}
for k in ('http_status','byte_length','curl_exit'):
    if k in row and row[k] != '': row[k] = int(row[k])
with open(out, 'a', encoding='utf-8', newline='\n') as f:
    f.write(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n')
PY
}

for url in "${URLS[@]}"; do
  body="$(mktemp)"
  hdr="$(mktemp)"
  err="$(mktemp)"
  fetched_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  set +e
  meta="$(curl --location --silent --show-error \
    --dump-header "$hdr" --output "$body" \
    --write-out $'%{http_code}\t%{content_type}\t%{url_effective}' \
    "$url" 2>"$err")"
  curl_exit=$?
  set -e

  IFS=$'\t' read -r status content_type effective_url <<<"$meta"
  status="${status:-0}"
  body_sha="$(sha256sum "$body" | awk '{print $1}')"
  header_sha="$(sha256sum "$hdr" | awk '{print $1}')"
  byte_length="$(wc -c < "$body" | tr -d ' ')"

  if [[ "$curl_exit" -ne 0 || "$status" != "200" ]]; then
    cp "$body" "$ROOT/failures/body-$body_sha" 2>/dev/null || true
    cp "$hdr" "$ROOT/failures/headers-$header_sha" 2>/dev/null || true
    export R_SCHEMA="SSA_FETCH_FAILURE_v0.1"
    export R_URL="$url" R_EFFECTIVE_URL="$effective_url" R_FETCHED_AT="$fetched_at"
    export R_HTTP_STATUS="$status" R_CONTENT_TYPE="$content_type" R_BYTE_LENGTH="$byte_length"
    export R_BODY_SHA256="$body_sha" R_RESPONSE_HEADERS_SHA256="$header_sha" R_CURL_EXIT="$curl_exit"
    export R_ERROR_CLASS="$( [[ "$curl_exit" -ne 0 ]] && echo CURL_TRANSPORT || echo HTTP_STATUS )"
    export R_ERROR_TEXT="$(tr '\n' ' ' < "$err" | head -c 1000)"
    append_json_row "$ROOT/failures/SSA_FETCH_FAILURE_v0.1.jsonl"
    echo "HALT_ACQUISITION: $url status=$status curl_exit=$curl_exit" >&2
    rm -f "$body" "$hdr" "$err"
    exit 1
  fi

  raw="$ROOT/raw/$body_sha"
  if [[ -e "$raw" ]]; then
    cmp -s "$raw" "$body" || { echo "MUTATION_PROHIBITED: $raw" >&2; exit 2; }
    rm -f "$body"
  else
    mv "$body" "$raw"
  fi
  mv "$hdr" "$ROOT/headers/$header_sha"
  rm -f "$err"

  export R_SCHEMA="SSA_FETCH_RECEIPT_v0.1"
  export R_URL="$url" R_EFFECTIVE_URL="$effective_url" R_FETCHED_AT="$fetched_at"
  export R_HTTP_STATUS="$status" R_CONTENT_TYPE="$content_type" R_BYTE_LENGTH="$byte_length"
  export R_SHA256="$body_sha" R_RAW_OBJECT="raw/$body_sha"
  export R_RESPONSE_HEADERS_SHA256="$header_sha"
  unset R_CURL_EXIT R_ERROR_CLASS R_ERROR_TEXT R_BODY_SHA256
  append_json_row "$ROOT/manifest.jsonl"
done

python ssa_public_replay/gate1.py --root "$ROOT" verify

echo "CAPTURE_ROOT=$ROOT"
echo "H_manifest=$(sha256sum "$ROOT/manifest.jsonl" | awk '{print $1}')"
echo "H_G1=$(sha256sum "$ROOT/SSA_GATE1_RECEIPT_v0.1.json" | awk '{print $1}')"

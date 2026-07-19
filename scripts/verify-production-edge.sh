#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <https-origin> [http-origin]" >&2
  exit 2
fi

https_origin=${1%/}
http_origin=${2:-${https_origin/https:/http:}}
http_origin=${http_origin%/}

parsed=$(python3 - "$https_origin" <<'PY'
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
url = urlsplit(value)
if (
    url.scheme != "https"
    or not url.hostname
    or url.username is not None
    or url.password is not None
    or url.path
    or url.query
    or url.fragment
):
    raise SystemExit("HTTPS origin must contain only scheme and authority")
try:
    port = url.port or 443
except ValueError as error:
    raise SystemExit(str(error)) from error
print(f"{url.hostname}\t{port}")
PY
)
IFS=$'\t' read -r tls_host tls_port <<<"$parsed"

work_dir=$(mktemp -d)
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

echo "Checking certificate validity for ${tls_host}:${tls_port}"
openssl s_client -connect "${tls_host}:${tls_port}" -servername "$tls_host" </dev/null 2>/dev/null \
  | openssl x509 -checkend 2592000 -noout

echo "Checking HTTPS health and HSTS"
curl --silent --show-error --fail --max-time 15 \
  --dump-header "$work_dir/https.headers" \
  --output /dev/null \
  "$https_origin/api/v1/livez"
if ! grep -Eiq '^strict-transport-security:[[:space:]]*max-age=31536000([[:space:]]|;|$)' "$work_dir/https.headers"; then
  echo "missing or insufficient Strict-Transport-Security header" >&2
  exit 1
fi

echo "Checking plaintext redirect"
redirect_status=$(curl --silent --show-error --max-time 15 \
  --output /dev/null --write-out '%{http_code}' \
  "$http_origin/api/v1/livez")
redirect_target=$(curl --silent --show-error --max-time 15 \
  --output /dev/null --write-out '%{redirect_url}' \
  "$http_origin/api/v1/livez")
if [[ "$redirect_status" != "301" && "$redirect_status" != "308" ]]; then
  echo "plaintext endpoint returned HTTP $redirect_status instead of 301/308" >&2
  exit 1
fi
if [[ "$redirect_target" != "$https_origin/api/v1/livez" ]]; then
  echo "plaintext redirect target is not the exact HTTPS URL: $redirect_target" >&2
  exit 1
fi

echo "Checking forwarding-header overwrite"
spoofed_proto_status=$(curl --silent --show-error --max-time 15 \
  --header 'X-Forwarded-Proto: http' \
  --output /dev/null --write-out '%{http_code}' \
  "$https_origin/api/v1/vault")
if [[ "$spoofed_proto_status" != "401" ]]; then
  echo "ingress did not overwrite spoofed forwarding metadata (HTTP $spoofed_proto_status)" >&2
  exit 1
fi

echo "Checking wrong-Host rejection"
wrong_host_status=$(curl --silent --show-error --max-time 15 \
  --header 'Host: attacker.invalid' \
  --output /dev/null --write-out '%{http_code}' \
  "$https_origin/api/v1/vault")
if [[ "$wrong_host_status" == "401" || ! "$wrong_host_status" =~ ^4 ]]; then
  echo "ingress did not reject an unconfigured Host (HTTP $wrong_host_status)" >&2
  exit 1
fi

echo "Checking that CORS remains disabled"
curl --silent --show-error --max-time 15 \
  --header 'Origin: https://attacker.invalid' \
  --dump-header "$work_dir/cors.headers" \
  --output /dev/null \
  "$https_origin/api/v1/livez"
if grep -Eiq '^access-control-allow-(origin|credentials|headers|methods):' "$work_dir/cors.headers"; then
  echo "public API opted into cross-origin access" >&2
  exit 1
fi

echo "Production edge contract passed for $https_origin"

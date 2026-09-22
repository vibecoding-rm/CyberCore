#!/usr/bin/env bash
set -euo pipefail

base_url="${CYBERCORE_URL:-http://127.0.0.1:8080}"
: "${CYBERCORE_API_KEY:?Define CYBERCORE_API_KEY con la clave local del operador}"

curl --fail --silent --show-error "${base_url}/health"
curl --fail --silent --show-error "${base_url}/ready"
curl --fail --silent --show-error \
  -X POST "${base_url}/v1/tools/execute" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${CYBERCORE_API_KEY}" \
  -d '{"tool":"get_mock_inventory","arguments":{"target":"192.168.10.25"}}'

#!/usr/bin/env bash
set -euo pipefail

base_url="${CYBERCORE_URL:-http://127.0.0.1:8080}"

curl --fail --silent --show-error "${base_url}/health"
curl --fail --silent --show-error \
  -X POST "${base_url}/v1/tools/execute" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"get_mock_inventory","arguments":{"target":"192.168.10.25"},"requested_by":"smoke-test"}'

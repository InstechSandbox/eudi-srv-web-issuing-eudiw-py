#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
detected_lan_ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)

detect_adb_bin() {
  for candidate in \
    "${ADB_BIN:-}" \
    "${ANDROID_SDK_ROOT:-}/platform-tools/adb" \
    "${ANDROID_HOME:-}/platform-tools/adb" \
    "$HOME/Library/Android/sdk/platform-tools/adb"
  do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  if command -v adb >/dev/null 2>&1; then
    command -v adb
    return
  fi

  printf '%s\n' "$HOME/Library/Android/sdk/platform-tools/adb"
}

if [ -n "${ISSUER_BACKEND_URL:-}" ]; then
  issuer_backend_url=$ISSUER_BACKEND_URL
elif [ -n "$detected_lan_ip" ]; then
  issuer_backend_url="https://$detected_lan_ip:5002"
else
  issuer_backend_url="https://localhost:5002"
fi

credential_configuration_id=${CREDENTIAL_CONFIGURATION_ID:-eu.europa.ec.eudi.pid_mdoc}
credential_offer_scheme=${CREDENTIAL_OFFER_SCHEME:-haip-vci://}
adb_bin=${ADB_BIN:-$(detect_adb_bin)}
android_serial=${ANDROID_SERIAL:-}
run_adb=false

adb_cmd() {
  if [ -n "$android_serial" ]; then
    "$adb_bin" -s "$android_serial" "$@"
    return
  fi

  "$adb_bin" "$@"
}

if [ "${1:-}" = "--run" ]; then
  run_adb=true
fi

offer_json=$(curl -sk "${issuer_backend_url}/credential_offer_create?credential_configuration_id=${credential_configuration_id}")

parsed=$(/usr/bin/python3 - "$offer_json" "$credential_offer_scheme" <<'PY'
import json
import sys
import urllib.parse

offer = json.loads(sys.argv[1])
scheme = sys.argv[2]

required = ["credential_issuer", "credential_configuration_ids", "grants"]
missing = [key for key in required if key not in offer]
if missing:
    raise SystemExit("Issuer response missing fields: %s\n%s" % (", ".join(missing), json.dumps(offer, indent=2)))

deeplink = f"{scheme}credential_offer?credential_offer=" + urllib.parse.quote(
    json.dumps(offer, separators=(",", ":")),
    safe=':/'
)

print("credential_issuer=" + offer["credential_issuer"])
print("credential_configuration_ids=" + ",".join(offer["credential_configuration_ids"]))
print("deeplink=" + deeplink)
PY
)

printf '%s\n' "$parsed"

if [ "$run_adb" = true ]; then
  deeplink=$(printf '%s\n' "$parsed" | awk -F= '/^deeplink=/{print substr($0,10)}')

  if [ -z "$deeplink" ]; then
    printf 'Failed to derive deeplink from issuer response\n' >&2
    exit 1
  fi

  adb_cmd shell "am start -W -a android.intent.action.VIEW -d '$deeplink'"
fi
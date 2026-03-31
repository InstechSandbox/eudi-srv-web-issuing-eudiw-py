set -euo pipefail

detect_lan_ip() {
    ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true
}

DETECTED_LAN_IP="$(detect_lan_ip)"

MYIP="${MYIP:-${DETECTED_LAN_IP:-localhost}}"
ISSUER_PORT="${ISSUER_PORT:-5002}"
AUTH_PORT="${AUTH_PORT:-5001}"
FRONTEND_PORT="${FRONTEND_PORT:-5003}"
FRONTEND_ID="${FRONTEND_ID:-5d725b3c-6d42-448e-8bfd-1eff1fcf152d}"
LOCAL_REPO_ROOT="${LOCAL_REPO_ROOT:-$(pwd -P)}"
ISSUER_CERT_FILE="${ISSUER_CERT_FILE:-server.crt}"
ISSUER_KEY_FILE="${ISSUER_KEY_FILE:-server.key}"

ISSUER_BASE="https://${MYIP}:${ISSUER_PORT}"
VERIFY_USER_ENDPOINT="https://${MYIP}:${AUTH_PORT}/verify/user"
AUTH_INTERNAL="https://127.0.0.1:${AUTH_PORT}"
FRONTEND_BASE="https://${MYIP}:${FRONTEND_PORT}"

mkdir -p /tmp/log_dev

MYIP="$MYIP" \
ISSUER_PORT="$ISSUER_PORT" \
AUTH_PORT="$AUTH_PORT" \
FRONTEND_PORT="$FRONTEND_PORT" \
FRONTEND_ID="$FRONTEND_ID" \
LOCAL_REPO_ROOT="$LOCAL_REPO_ROOT" \
python3 - <<'PY'
from pathlib import Path
import os
import re

p = Path("app/.env")
text = p.read_text()

myip = os.environ["MYIP"]
issuer_port = os.environ["ISSUER_PORT"]
auth_port = os.environ["AUTH_PORT"]
frontend_port = os.environ["FRONTEND_PORT"]
frontend_id = os.environ["FRONTEND_ID"]
local_repo_root = os.environ["LOCAL_REPO_ROOT"]

def set_env_line(text: str, key: str, value: str) -> str:
    pattern = rf'^{re.escape(key)}=.*$'
    replacement = f'{key}={value}'
    if re.search(pattern, text, flags=re.MULTILINE):
        return re.sub(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if text and not text.endswith("\n"):
        text += "\n"
    return text + replacement + "\n"

for key, value in {
    "MYIP": myip,
    "ISSUER_PORT": issuer_port,
    "AUTH_PORT": auth_port,
    "FRONTEND_PORT": frontend_port,
    "FRONTEND_ID": frontend_id,
    "LOCAL_REPO_ROOT": local_repo_root,
    "SERVICE_URL": "https://${MYIP}:${ISSUER_PORT}",
    "DEFAULT_FRONTEND": frontend_id,
    "DEFAULT_FRONTEND_URL": "https://${MYIP}:${FRONTEND_PORT}",
    "TRUSTED_CAS_PATH": "${LOCAL_REPO_ROOT}/local/cert/",
    "PRIVKEY_PATH": "${LOCAL_REPO_ROOT}/local/privKey/",
    "NONCE_KEY": "${LOCAL_REPO_ROOT}/local/privKey/nonce_rsa2048.pem",
    "CREDENTIAL_KEY": "${LOCAL_REPO_ROOT}/local/privKey/credential_request_ec.pem",
    "AUTH_SERVER_INTERNAL_URL": "https://127.0.0.1:${AUTH_PORT}",
    "VERIFY_USER_ENDPOINT": "https://${MYIP}:${AUTH_PORT}/verify/user",
    "REVOCATION_SERVICE_URL": "https://${MYIP}:${ISSUER_PORT}/token_status_list/take",
    "REVOKE_SERVICE_URL": "https://${MYIP}:${ISSUER_PORT}/token_status_list/set",
}.items():
    text = set_env_line(text, key, value)



p.write_text(text)
print("updated", p)
PY

python3 - <<PY
from pathlib import Path
import re

p = Path("app/route_oidc.py")
text = p.read_text()

text = text.replace(
    'url = "https://dev.issuer.eudiw.dev/frontend/.well-known/oauth-authorization-server"',
    'frontend_base = os.getenv("DEFAULT_FRONTEND_URL", "https://ec.dev.issuer.eudiw.dev")\\n    url = f"{frontend_base}/.well-known/oauth-authorization-server"'
)

p.write_text(text)
print("updated", p)
PY

python3 - <<PY
from pathlib import Path
import re

p = Path("app/app_config/config_countries.py")
text = p.read_text()

text = re.sub(
    r'("url":\s*)os\.getenv\("DEFAULT_FRONTEND_URL",\s*"https://ec\.dev\.issuer\.eudiw\.dev"\)',
    r'\\1os.getenv("DEFAULT_FRONTEND_URL", "https://ec.dev.issuer.eudiw.dev")',
    text
)

# Optional: normalize the default frontend ID if present in plain text blocks
text = text.replace("5d725b3c-6d42-448e-8bfd-1eff1fcf152d", "${FRONTEND_ID}")

p.write_text(text)
print("checked", p)
PY

python3 - <<PY
import json
import re
from pathlib import Path

issuer_base = "${ISSUER_BASE}"
issuer_oidc_base = f"{issuer_base}/oidc"

files = {
    Path("app/metadata_config/metadata_config.json"): issuer_base,
    Path("app/metadata_config/openid-configuration.json"): issuer_oidc_base,
    Path("app/metadata_config/oauth-authorization-server.json"): issuer_base,
}

for path, base in files.items():
    text = path.read_text()
    text = re.sub(r"https?://[^\"\s]+", lambda match: re.sub(r"^https?://[^/]+(?:/oidc)?", base, match.group(0)), text)
    path.write_text(text)
    print("updated", path)
PY

echo
echo "Issuer backend patched."
echo "Expected runtime:"
echo "  Backend   : ${ISSUER_BASE}"
echo "  OIDC local: ${AUTH_INTERNAL}"
echo "  Frontend  : ${FRONTEND_BASE}"
echo "  TLS cert  : ${ISSUER_CERT_FILE}"
echo "  TLS key   : ${ISSUER_KEY_FILE}"
echo
echo "Start backend with:"
echo "  flask --app app run --debug --host=0.0.0.0 --port=${ISSUER_PORT} --cert=${ISSUER_CERT_FILE} --key=${ISSUER_KEY_FILE}"

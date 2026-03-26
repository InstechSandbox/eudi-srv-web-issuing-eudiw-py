set -euo pipefail

MYIP="${MYIP:-192.168.0.110}"
ISSUER_PORT="${ISSUER_PORT:-5002}"
AUTH_PORT="${AUTH_PORT:-5001}"
FRONTEND_PORT="${FRONTEND_PORT:-5003}"
FRONTEND_ID="${FRONTEND_ID:-5d725b3c-6d42-448e-8bfd-1eff1fcf152d}"
ISSUER_CERT_FILE="${ISSUER_CERT_FILE:-server.crt}"
ISSUER_KEY_FILE="${ISSUER_KEY_FILE:-server.key}"

ISSUER_BASE="https://${MYIP}:${ISSUER_PORT}"
VERIFY_USER_ENDPOINT="https://${MYIP}:${AUTH_PORT}/verify/user"
AUTH_INTERNAL="http://127.0.0.1:${AUTH_PORT}"
FRONTEND_BASE="https://${MYIP}:${FRONTEND_PORT}"

mkdir -p /tmp/log_dev

python3 - <<PY
from pathlib import Path

p = Path("app/.env")
text = p.read_text()

replacements = {
    "SERVICE_URL=http://127.0.0.1:5000": f"SERVICE_URL=${ISSUER_BASE}",
    "SERVICE_URL=http://192.168.0.110:5000": f"SERVICE_URL=${ISSUER_BASE}",
    "SERVICE_URL=http://192.168.0.110:5002": f"SERVICE_URL=${ISSUER_BASE}",

    "AUTH_SERVER_INTERNAL_URL=http://host.docker.internal:6005": f"AUTH_SERVER_INTERNAL_URL=${AUTH_INTERNAL}",
    "AUTH_SERVER_INTERNAL_URL=http://127.0.0.1:6005": f"AUTH_SERVER_INTERNAL_URL=${AUTH_INTERNAL}",
    "AUTH_SERVER_INTERNAL_URL=http://192.168.0.110:5001": f"AUTH_SERVER_INTERNAL_URL=${AUTH_INTERNAL}",
    "AUTH_SERVER_INTERNAL_URL=http://127.0.0.1:5001": f"AUTH_SERVER_INTERNAL_URL=${AUTH_INTERNAL}",

    "VERIFY_USER_ENDPOINT=http://127.0.0.1:5000/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=http://192.168.0.110:5000/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=http://192.168.0.110:5002/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=http://127.0.0.1:5000/oidc/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=http://192.168.0.110:5000/oidc/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=http://192.168.0.110:5002/oidc/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://127.0.0.1:5000/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://192.168.0.110:5000/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://192.168.0.110:5002/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://127.0.0.1:5000/oidc/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://192.168.0.110:5000/oidc/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://192.168.0.110:5002/oidc/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://dev.issuer.eudiw.dev/oidc/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",
    "VERIFY_USER_ENDPOINT=https://dev.issuer.eudiw.dev/verify/user": f"VERIFY_USER_ENDPOINT=${VERIFY_USER_ENDPOINT}",

    "REVOCATION_SERVICE_URL=http://127.0.0.1:5000/token_status_list/take": f"REVOCATION_SERVICE_URL=${ISSUER_BASE}/token_status_list/take",
    "REVOCATION_SERVICE_URL=http://192.168.0.110:5000/token_status_list/take": f"REVOCATION_SERVICE_URL=${ISSUER_BASE}/token_status_list/take",
    "REVOCATION_SERVICE_URL=http://192.168.0.110:5002/token_status_list/take": f"REVOCATION_SERVICE_URL=${ISSUER_BASE}/token_status_list/take",

    "REVOKE_SERVICE_URL=http://127.0.0.1:5000/token_status_list/set": f"REVOKE_SERVICE_URL=${ISSUER_BASE}/token_status_list/set",
    "REVOKE_SERVICE_URL=http://192.168.0.110:5000/token_status_list/set": f"REVOKE_SERVICE_URL=${ISSUER_BASE}/token_status_list/set",
    "REVOKE_SERVICE_URL=http://192.168.0.110:5002/token_status_list/set": f"REVOKE_SERVICE_URL=${ISSUER_BASE}/token_status_list/set",

    "DEFAULT_FRONTEND_URL=https://ec.dev.issuer.eudiw.dev": f"DEFAULT_FRONTEND_URL=${FRONTEND_BASE}",
}
for old, new in replacements.items():
    text = text.replace(old, new)

if "DEFAULT_FRONTEND=" not in text:
    text += f"\\nDEFAULT_FRONTEND=${FRONTEND_ID}\\n"
if "DEFAULT_FRONTEND_URL=" not in text:
    text += f"\\nDEFAULT_FRONTEND_URL=${FRONTEND_BASE}\\n"

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

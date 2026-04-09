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
LOCAL_RUNTIME_DIR="${LOCAL_RUNTIME_DIR:-$LOCAL_REPO_ROOT/local/runtime}"
ISSUER_METADATA_OVERRIDES_FILE="${ISSUER_METADATA_OVERRIDES_FILE:-$LOCAL_RUNTIME_DIR/metadata_overrides.json}"
TRUSTED_CAS_PATH="${TRUSTED_CAS_PATH:-$LOCAL_REPO_ROOT/local/cert}"
LOCAL_PRIVKEY_DIR="${LOCAL_PRIVKEY_DIR:-$LOCAL_REPO_ROOT/local/privKey}"
LOCAL_UTOPIA_SIGNER_SOURCE_DIR="${LOCAL_UTOPIA_SIGNER_SOURCE_DIR:-}"
ISSUER_CERT_FILE="${ISSUER_CERT_FILE:-server.crt}"
ISSUER_KEY_FILE="${ISSUER_KEY_FILE:-server.key}"

ISSUER_BASE="https://${MYIP}:${ISSUER_PORT}"
VERIFY_USER_ENDPOINT="https://${MYIP}:${AUTH_PORT}/verify/user"
AUTH_INTERNAL="https://127.0.0.1:${AUTH_PORT}"
FRONTEND_BASE="https://${MYIP}:${FRONTEND_PORT}"

mkdir -p /tmp/log_dev
mkdir -p "$LOCAL_RUNTIME_DIR"
mkdir -p "$TRUSTED_CAS_PATH"
mkdir -p "$LOCAL_PRIVKEY_DIR"

UTOPIA_SIGNER_KEY_PATH="$LOCAL_PRIVKEY_DIR/PID-DS-0001_UT.pem"
UTOPIA_SIGNER_CERT_DER_PATH="$TRUSTED_CAS_PATH/PID-DS-0001_UT_cert.der"
UTOPIA_SIGNER_CERT_PEM_PATH="$TRUSTED_CAS_PATH/PID-DS-0001_UT_cert.pem"

seed_local_utopia_signer() {
    [[ -n "$LOCAL_UTOPIA_SIGNER_SOURCE_DIR" ]] || return 0

    local source_key="$LOCAL_UTOPIA_SIGNER_SOURCE_DIR/privKey/PID-DS-0001_UT.pem"
    local source_cert_der="$LOCAL_UTOPIA_SIGNER_SOURCE_DIR/cert/PID-DS-0001_UT_cert.der"
    local source_cert_pem="$LOCAL_UTOPIA_SIGNER_SOURCE_DIR/cert/PID-DS-0001_UT_cert.pem"

    if [[ ! -f "$UTOPIA_SIGNER_KEY_PATH" && -f "$source_key" ]]; then
        cp "$source_key" "$UTOPIA_SIGNER_KEY_PATH"
    fi

    if [[ ! -f "$UTOPIA_SIGNER_CERT_DER_PATH" && -f "$source_cert_der" ]]; then
        cp "$source_cert_der" "$UTOPIA_SIGNER_CERT_DER_PATH"
    fi

    if [[ ! -f "$UTOPIA_SIGNER_CERT_PEM_PATH" && -f "$source_cert_pem" ]]; then
        cp "$source_cert_pem" "$UTOPIA_SIGNER_CERT_PEM_PATH"
    fi
}

require_local_utopia_signer() {
    local missing=()

    [[ -f "$UTOPIA_SIGNER_KEY_PATH" ]] || missing+=("$UTOPIA_SIGNER_KEY_PATH")
    [[ -f "$UTOPIA_SIGNER_CERT_DER_PATH" ]] || missing+=("$UTOPIA_SIGNER_CERT_DER_PATH")

    if (( ${#missing[@]} == 0 )); then
        return 0
    fi

    echo "Missing required local Utopia signer assets:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    echo >&2
    echo "Set LOCAL_UTOPIA_SIGNER_SOURCE_DIR to a local issuer checkout or seed directory containing:" >&2
    echo "  privKey/PID-DS-0001_UT.pem" >&2
    echo "  cert/PID-DS-0001_UT_cert.der" >&2
    echo "Optional:" >&2
    echo "  cert/PID-DS-0001_UT_cert.pem" >&2
    exit 1
}

seed_local_utopia_signer
require_local_utopia_signer

NONCE_KEY_PATH="$LOCAL_PRIVKEY_DIR/nonce_rsa2048.pem"
CREDENTIAL_KEY_PATH="$LOCAL_PRIVKEY_DIR/credential_request_ec.pem"

if [[ ! -f "$NONCE_KEY_PATH" ]]; then
    openssl genrsa -out "$NONCE_KEY_PATH" 2048 >/dev/null 2>&1
fi

if [[ ! -f "$CREDENTIAL_KEY_PATH" ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$CREDENTIAL_KEY_PATH" >/dev/null 2>&1
fi

MYIP="$MYIP" \
ISSUER_PORT="$ISSUER_PORT" \
AUTH_PORT="$AUTH_PORT" \
FRONTEND_PORT="$FRONTEND_PORT" \
FRONTEND_ID="$FRONTEND_ID" \
LOCAL_REPO_ROOT="$LOCAL_REPO_ROOT" \
python - <<'PY'
from pathlib import Path
import os
import re

env_path = Path("app/.env")
example_path = Path("app/.env.example")

if env_path.exists():
    text = env_path.read_text()
elif example_path.exists():
    text = example_path.read_text()
else:
    raise FileNotFoundError("Neither app/.env nor app/.env.example exists")

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
    "TRUSTED_CAS_PATH": f"{local_repo_root}/local/cert/",
    "PRIVKEY_PATH": f"{local_repo_root}/local/privKey/",
    "NONCE_KEY": f"{local_repo_root}/local/privKey/nonce_rsa2048.pem",
    "CREDENTIAL_KEY": f"{local_repo_root}/local/privKey/credential_request_ec.pem",
    "AUTH_SERVER_INTERNAL_URL": "https://127.0.0.1:${AUTH_PORT}",
    "VERIFY_USER_ENDPOINT": "https://${MYIP}:${AUTH_PORT}/verify/user",
    "REVOCATION_SERVICE_URL": "https://${MYIP}:${ISSUER_PORT}/token_status_list/take",
    "REVOKE_SERVICE_URL": "https://${MYIP}:${ISSUER_PORT}/token_status_list/set",
}.items():
    text = set_env_line(text, key, value)



env_path.write_text(text)
print("updated", env_path)
PY

MYIP="$MYIP" \
ISSUER_PORT="$ISSUER_PORT" \
AUTH_PORT="$AUTH_PORT" \
FRONTEND_PORT="$FRONTEND_PORT" \
FRONTEND_ID="$FRONTEND_ID" \
LOCAL_REPO_ROOT="$LOCAL_REPO_ROOT" \
python - <<'PY'
import json
import re
import os
from pathlib import Path
from jwcrypto import jwk

issuer_base = f"https://{os.environ['MYIP']}:{os.environ['ISSUER_PORT']}"
issuer_oidc_base = f"{issuer_base}/oidc"
output_path = Path(os.environ.get("ISSUER_METADATA_OVERRIDES_FILE", f"{os.environ['LOCAL_REPO_ROOT']}/local/runtime/metadata_overrides.json"))
output_path.parent.mkdir(parents=True, exist_ok=True)
credential_key_path = Path(os.environ["LOCAL_REPO_ROOT"]) / "local/privKey/credential_request_ec.pem"

files = {
    Path("app/metadata_config/metadata_config.json"): issuer_base,
    Path("app/metadata_config/openid-configuration.json"): issuer_oidc_base,
    Path("app/metadata_config/oauth-authorization-server.json"): issuer_base,
}

override_keys = {
    "metadata_config.json": "credential_issuer_metadata",
    "openid-configuration.json": "openid_configuration",
    "oauth-authorization-server.json": "oauth_authorization_server",
}

overrides = {}

for path, base in files.items():
    text = path.read_text()
    text = re.sub(r"https?://[^\"\s]+", lambda match: re.sub(r"^https?://[^/]+(?:/oidc)?", base, match.group(0)), text)
    overrides[override_keys[path.name]] = json.loads(text)

credential_request_key = jwk.JWK.from_pem(credential_key_path.read_bytes())
credential_request_jwk = json.loads(credential_request_key.export(private_key=False))
credential_request_jwk["use"] = "enc"
credential_request_jwk["alg"] = "ECDH-ES"
overrides["credential_request_encryption_jwk"] = credential_request_jwk

output_path.write_text(json.dumps(overrides, indent=2))
print("generated", output_path)
PY

echo
echo "Issuer backend local runtime files generated."
echo "Expected runtime:"
echo "  Backend   : ${ISSUER_BASE}"
echo "  OIDC local: ${AUTH_INTERNAL}"
echo "  Frontend  : ${FRONTEND_BASE}"
echo "  Trusted CAs: ${TRUSTED_CAS_PATH}"
echo "  Local keys : ${LOCAL_PRIVKEY_DIR}"
if [[ -n "$LOCAL_UTOPIA_SIGNER_SOURCE_DIR" ]]; then
echo "  Seed signer: ${LOCAL_UTOPIA_SIGNER_SOURCE_DIR}"
fi
echo "  TLS cert  : ${ISSUER_CERT_FILE}"
echo "  TLS key   : ${ISSUER_KEY_FILE}"
echo "  Metadata  : ${ISSUER_METADATA_OVERRIDES_FILE}"
echo
echo "Start backend with:"
echo "  ISSUER_METADATA_OVERRIDES_FILE='${ISSUER_METADATA_OVERRIDES_FILE}' flask --app app run --debug --host=0.0.0.0 --port=${ISSUER_PORT} --cert=${ISSUER_CERT_FILE} --key=${ISSUER_KEY_FILE}"

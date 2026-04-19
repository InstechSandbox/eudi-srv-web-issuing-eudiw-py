#!/bin/sh

set -eu

runtime_dir="${ISSUER_RUNTIME_DIR:-/tmp/eudiw/pid-issuer-runtime}"

export TRUSTED_CAS_PATH="${TRUSTED_CAS_PATH:-${runtime_dir}/cert/}"
export PRIVKEY_PATH="${PRIVKEY_PATH:-${runtime_dir}/privKey/}"
export NONCE_KEY="${NONCE_KEY:-${runtime_dir}/privKey/nonce_rsa2048.pem}"
export CREDENTIAL_KEY="${CREDENTIAL_KEY:-${runtime_dir}/privKey/credential_request_ec.pem}"
export ISSUER_METADATA_OVERRIDES_FILE="${ISSUER_METADATA_OVERRIDES_FILE:-${runtime_dir}/metadata_overrides.json}"

python support/bootstrap_runtime.py

exec flask run --host=0.0.0.0 --port "${ISSUER_PORT:-5000}"
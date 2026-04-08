#!/bin/bash

set -euo pipefail

# Activate Python virtual environment
source .venv/bin/activate

ISSUER_PORT="${ISSUER_PORT:-5002}"
ISSUER_CERT_FILE="${ISSUER_CERT_FILE:-server.crt}"
ISSUER_KEY_FILE="${ISSUER_KEY_FILE:-server.key}"

# Start Flask backend with HTTPS on the local issuer port
python -m flask --app app run --debug --host=0.0.0.0 --port="${ISSUER_PORT}" --cert="${ISSUER_CERT_FILE}" --key="${ISSUER_KEY_FILE}"
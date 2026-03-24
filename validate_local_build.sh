#!/bin/sh

set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_dir"

venv_dir=${VENV_DIR:-$repo_dir/.venv-validate}
python_bin=${PYTHON_BIN:-python3}

"$python_bin" -m venv "$venv_dir"
. "$venv_dir/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r app/requirements.txt

if [ -f package.json ]; then
  npm install --no-fund --no-audit
  npm run build
fi

python -m compileall app tests
pytest tests/test_redirect_func.py
bash -n patch_issuer_backend_local.sh run_backend.sh

printf 'Validated issuer backend dependencies in %s\n' "$venv_dir"
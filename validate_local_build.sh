#!/bin/sh

set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_dir"

venv_dir=${VENV_DIR:-$repo_dir/.venv-validate}

select_python() {
  if [ -n "${PYTHON_BIN:-}" ]; then
    printf '%s\n' "$PYTHON_BIN"
    return
  fi

  for candidate in python3.10 python3.9 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  printf 'No suitable Python interpreter found\n' >&2
  exit 1
}

python_bin=$(select_python)

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
#!/usr/bin/env bash
# One-click launcher for macOS / Linux: ./run.sh
set -euo pipefail
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python || true)
if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/"; exit 1
fi
[ -x .venv/bin/python ] || "$PY" -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt
echo "SSE Engine is starting at http://localhost:5000 (Ctrl+C to stop)"
( sleep 3; (open http://localhost:5000 || xdg-open http://localhost:5000) >/dev/null 2>&1 || true ) &
exec .venv/bin/python app.py

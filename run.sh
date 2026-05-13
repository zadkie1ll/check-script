#!/usr/bin/env bash
set -Eeuo pipefail

BASE_URL="${VPN_VPS_CHECKER_BASE_URL:-https://raw.githubusercontent.com/USERNAME/vpn-vps-checker/main}"
WORKDIR="$(mktemp -d /tmp/vpn-vps-checker-run-XXXXXX)"
VENV_DIR="/tmp/vpn-vps-checker-venv"

cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required. Install Python 3.11+ and run again." >&2
  exit 1
fi

PYTHON_VERSION="$(python3 - <<'PY'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PY
)"

if ! python3 - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
then
  echo "Python 3.11+ is required. Found Python ${PYTHON_VERSION}." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$PWD/run.sh}")" 2>/dev/null && pwd || pwd)"

if [[ -f "$SCRIPT_DIR/check.py" && -f "$SCRIPT_DIR/targets.yaml" && -f "$SCRIPT_DIR/requirements.txt" ]]; then
  cp "$SCRIPT_DIR/check.py" "$SCRIPT_DIR/targets.yaml" "$SCRIPT_DIR/requirements.txt" "$WORKDIR/"
else
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required when run.sh is not executed from a local checkout." >&2
    exit 1
  fi
  curl -fsSL "$BASE_URL/check.py" -o "$WORKDIR/check.py"
  curl -fsSL "$BASE_URL/targets.yaml" -o "$WORKDIR/targets.yaml"
  curl -fsSL "$BASE_URL/requirements.txt" -o "$WORKDIR/requirements.txt"
fi

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
"$VENV_DIR/bin/python" -m pip install -r "$WORKDIR/requirements.txt"

cd "$WORKDIR"
"$VENV_DIR/bin/python" check.py "$@"

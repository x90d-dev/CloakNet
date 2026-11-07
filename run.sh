#!/usr/bin/env bash
# CloakNet One-Click Bootstrapper & Launcher for Linux / macOS
# Repository: https://github.com/x90d/CloakNet

set -euo pipefail
cd "$(dirname "$0")"

echo "==============================================================================="
echo "  CLOAKNET v1.4.0 - ENVIRONMENT CHECK & LAUNCHER"
echo "  Automated Layer-2 Identity Obfuscation & Local Traffic Randomizer"
echo "  Repository: https://github.com/x90d/CloakNet"
echo "==============================================================================="
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is not installed or not in PATH."
    exit 1
fi

python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" || {
    echo "[ERROR] CloakNet requires Python 3.9 or newer."
    exit 1
}

if [ ! -x ".venv/bin/python" ]; then
    echo "[SETUP] Creating isolated Python virtual environment (.venv)..."
    python3 -m venv .venv
fi

VENV_PY=".venv/bin/python"

if ! "$VENV_PY" -c "import rich, psutil" >/dev/null 2>&1; then
    echo "[SETUP] Required packages missing. Installing from requirements.txt..."
    "$VENV_PY" -m pip install --upgrade pip --quiet
    "$VENV_PY" -m pip install -r requirements.txt
    echo "[OK]    Dependencies installed successfully."
    echo ""
fi

exec "$VENV_PY" cloaknet.py "$@"

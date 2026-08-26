#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] LazyOwnBT installer"

# System dependencies
if command -v apt-get >/dev/null 2>&1; then
    echo "[*] Installing system packages..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq rlwrap python3-venv python3-pip
fi

# Python venv
if [[ ! -d "env" ]] || [[ ! -f "env/bin/pip" ]]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv env
fi

source env/bin/activate

# Install all extras (cli + web + ai + fim + utils)
echo "[*] Installing Python dependencies..."
pip install --upgrade pip
pip install -e ".[all]" 2>/dev/null || pip install -r requirements.txt

# Verify critical imports
echo "[*] Verifying imports..."
python3 -c "
import joblib, pandas, sklearn, yaml, lupa, requests, watchdog, cachetools, rich, cmd2, psutil, tabulate
print('[+] All critical imports OK')
" || {
    echo "[!] Some imports failed. Installing missing packages individually..."
    pip install joblib pandas scikit-learn pyyaml lupa requests watchdog cachetools rich cmd2 psutil tabulate
}

echo "[+] LazyOwnBT installed. Run with: rlwrap --always-readline python3 app.py"

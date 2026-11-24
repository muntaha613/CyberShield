#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
# Rebuild the engine when code changes; no pip or network dependency.
make
for candidate in     "$PWD/.venv/bin/python"     "$PWD/../CyberShield_V3_Final_Polished/.venv/bin/python"     "$PWD/../CyberShield_V3_Final/.venv/bin/python"     "$PWD/../CyberShield_V3_Integrated/.venv/bin/python"     "$PWD/../CyberShield_V3/.venv/bin/python"     "$(command -v python3)"; do
    if [ -x "$candidate" ] && "$candidate" -c 'from PySide6.QtWidgets import QApplication' >/dev/null 2>&1; then
        echo "Launching CyberShield with: $candidate"
        exec "$candidate" gui/app.py
    fi
done
echo 'PySide6 was not found in this or previous CyberShield environments.' >&2
echo 'Connect Kali to the internet and run ./setup_kali.sh, or use a previously working CyberShield .venv.' >&2
exit 1

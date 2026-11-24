#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
command -v g++ >/dev/null || { echo 'Install build-essential (g++) first'; exit 1; }
command -v python3 >/dev/null || { echo 'Install python3 first'; exit 1; }
python3 -m venv .venv || { echo 'Install python3-venv first'; exit 1; }
if ! .venv/bin/python -c 'from PySide6.QtWidgets import QApplication' >/dev/null 2>&1; then
    echo 'Installing PySide6 into the local environment (requires working internet/PyPI)...'
    if ! .venv/bin/python -m pip install -r requirements.txt; then
        echo 'Installation could not reach PyPI. ./launch.sh can still reuse a previous working CyberShield environment if present.'
    fi
fi
make
printf '\nSetup complete. Launch using: ./launch.sh\n'

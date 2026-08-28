#!/usr/bin/env bash

set -euo pipefail

VENV="$HOME/.venv"
BASHRC="$HOME/.bashrc"
PIP_URL="git+https://github.com/cselzer/looking-glass.git"
MARKER="# looking-glass venv"

if [[ "$EUID" -eq 0 ]]; then
  echo "This script must not be run as root." >&2
  echo "    sudo -u looking-glass $0" >&2
  exit 1
fi

echo "[*] Creating venv at ${VENV}..."
python3 -m venv "$VENV"
# shellcheck disable=SC1091
. "$VENV/bin/activate"

echo "[*] Wiring venv into ${BASHRC}..."
touch "$BASHRC"
if ! grep -Fq "$MARKER" "$BASHRC"; then
  cat >>"$BASHRC" <<EOF

${MARKER}
if [ -f "\$HOME/.venv/bin/activate" ]; then
  . "\$HOME/.venv/bin/activate"
fi
EOF
else
  echo "    ${BASHRC} already sources the venv"
fi

echo "[*] Installing looking-glass from GitHub..."
if ! pip install --force-reinstall "$PIP_URL"; then
  echo "[-] pip install failed." >&2
  echo >&2
  echo "    Need git and HTTPS to github.com (public repo)." >&2
  echo "    Test with: git ls-remote ${PIP_URL#git+}" >&2
  echo "    Then re-run this script." >&2
  exit 1
fi

echo
echo "[*] Done. looking-glass is on PATH in this venv."
echo "    New logins pick it up from ${BASHRC}."
echo "    looking-glass --help"

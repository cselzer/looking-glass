#!/usr/bin/env bash

set -euo pipefail

VENV="$HOME/.venv"
BASHRC="$HOME/.bashrc"
PIP_URL="git+https://github.com/cselzer/looking-glass.git"
MARKER="# looking-glass venv"
USAGE="usage: $0 [--email ADDRESS]"

EMAIL=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)
      if [[ $# -lt 2 ]]; then
        echo "$USAGE" >&2
        exit 1
      fi
      EMAIL="$2"
      shift 2
      ;;
    --email=*)
      EMAIL="${1#--email=}"
      shift
      ;;
    -h|--help)
      echo "$USAGE"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      echo "$USAGE" >&2
      exit 1
      ;;
  esac
done

if [[ "$EUID" -eq 0 ]]; then
  echo "This script must not be run as root." >&2
  echo "    runuser -u looking-glass -- $0" >&2
  exit 1
fi

EMAIL="${EMAIL#"${EMAIL%%[![:space:]]*}"}"
EMAIL="${EMAIL%"${EMAIL##*[![:space:]]}"}"
if [[ -n "$EMAIL" && "$EMAIL" != *@* ]]; then
  echo "[-] http.email must be an email address (or omit --email)." >&2
  exit 1
fi

_https_ready() {
  looking-glass https status | python3 -c '
import json, sys
info = json.load(sys.stdin)
ready = (
    bool(info.get("fullchain_exists"))
    and bool(info.get("privkey_exists"))
    and not info.get("needs_issue")
    and bool(info.get("not_after"))
)
sys.exit(0 if ready else 1)
'
}

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

echo "[*] Building datasets (ASN origin can take several minutes)..."
looking-glass build

echo "[*] Setting http.hostname from hostname -f..."
looking-glass config hostname "$(hostname -f)"

if [[ -n "$EMAIL" ]]; then
  echo "[*] Setting http.email..."
  looking-glass config set http.email "$EMAIL"
else
  echo "    http.email left blank (Let's Encrypt contact is optional)"
fi

echo "[*] Enabling HTTPS..."
looking-glass config set http.enabled true

echo "[*] Issuing Let's Encrypt certificate..."
if ! looking-glass https renew; then
  echo "[-] https renew failed." >&2
  looking-glass https logs || true
  exit 1
fi

echo "[*] Waiting for certificate (https status)..."
deadline=$((SECONDS + 300))
while true; do
  if _https_ready; then
    looking-glass https status
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "[-] Timed out waiting for a certificate." >&2
    looking-glass https status || true
    looking-glass https logs || true
    exit 1
  fi
  sleep 3
done

echo "[*] Enabling systemd --user units..."
looking-glass boot enable
looking-glass boot check

echo "[*] Waiting for intel and HTTPS..."
sleep 5
deadline=$((SECONDS + 60))
while true; do
  if looking-glass status; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "[-] looking-glass status did not become ok." >&2
    exit 1
  fi
  sleep 3
done

echo
echo "[*] Done. looking-glass is on PATH in this venv."
echo "    New logins pick it up from ${BASHRC}."
echo "    looking-glass --help"

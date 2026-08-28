#!/usr/bin/env bash

set -euo pipefail

LG_USER="looking-glass"
LG_HOME="/home/looking-glass"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "$EUID" -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

_die_hostname() {
  echo "[-] Hostname check failed: $1" >&2
  echo >&2
  echo "    This box needs a full hostname (FQDN) whose A and AAAA records" >&2
  echo "    are assigned on local interfaces (global scope, not link-local)." >&2
  echo >&2
  echo "    1. hostnamectl set-hostname s1.example.com" >&2
  echo "    2. Publish A and AAAA for that name pointing at this VM." >&2
  echo "    3. Assign both addresses on the NIC (not only fe80::)." >&2
  echo "    4. Re-run this script." >&2
  exit 1
}

_addrs() {
  # family is 4 or 6
  local family="$1"
  ip -"${family}" -o addr show scope global | awk '{print $4}' | cut -d/ -f1
}

_resolved() {
  # family is 4 or 6
  local family="$1" name="$2"
  if [[ "$family" == 4 ]]; then
    getent ahostsv4 "$name" 2>/dev/null | awk '{print $1}' | sort -u
  else
    getent ahostsv6 "$name" 2>/dev/null | awk '{print $1}' | sort -u
  fi
}

_has_match() {
  local family="$1" name="$2"
  local local_addrs resolved addr
  local_addrs="$(_addrs "$family")"
  resolved="$(_resolved "$family" "$name")"
  if [[ -z "$local_addrs" ]]; then
    return 1
  fi
  if [[ -z "$resolved" ]]; then
    return 1
  fi
  while read -r addr; do
    [[ -z "$addr" ]] && continue
    if [[ "$family" == 6 && "$addr" == fe80:* ]]; then
      continue
    fi
    if printf '%s\n' "$local_addrs" | grep -Fxq "$addr"; then
      return 0
    fi
  done <<<"$resolved"
  return 1
}

echo "[*] Checking FQDN has IPv4 and IPv6 on this box..."
FQDN="$(hostname -f 2>/dev/null || true)"
FQDN="${FQDN%%.}"
if [[ -z "$FQDN" || "$FQDN" == "localhost" || "$FQDN" != *.* ]]; then
  _die_hostname "hostname -f is '${FQDN:-empty}', not an FQDN"
fi
if ! _has_match 4 "$FQDN"; then
  _die_hostname "'${FQDN}' does not resolve to a global IPv4 address on this box"
fi
if ! _has_match 6 "$FQDN"; then
  _die_hostname "'${FQDN}' does not resolve to a global IPv6 address on this box"
fi
echo "    ${FQDN} is on this box (IPv4 and IPv6)"

echo "[*] Installing packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  unbound unbound-anchor curl ca-certificates python3-venv git ufw

if ! getent passwd "$LG_USER" >/dev/null; then
  echo "[*] Creating user ${LG_USER} (${LG_HOME})..."
  useradd --create-home --home-dir "$LG_HOME" --shell /bin/bash "$LG_USER"
else
  echo "[*] User ${LG_USER} already exists"
fi

echo "[*] Allowing unprivileged bind from port 80..."
printf 'net.ipv4.ip_unprivileged_port_start=80\n' >/etc/sysctl.d/99-looking-glass.conf
sysctl -w net.ipv4.ip_unprivileged_port_start=80

echo "[*] ufw default allow outgoing..."
ufw default allow outgoing

echo "[*] Enabling linger for ${LG_USER}..."
loginctl enable-linger "$LG_USER"

echo "[*] Setting up a local recursive DNS resolver with Unbound (no forwarders)..."

echo "[*] Preparing /var/lib/unbound..."
mkdir -p /var/lib/unbound

echo "[*] Fetching root hints..."
curl -fsSL https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints

echo "[*] Initializing DNSSEC trust anchor..."
if command -v unbound-anchor >/dev/null 2>&1; then
  # Remove any pre-seeded or broken trust anchor to avoid duplicates
  rm -f /var/lib/unbound/root.key || true
  unbound-anchor -a /var/lib/unbound/root.key || true
else
  echo "    WARNING: unbound-anchor not found, skipping trust anchor initialization."
fi

# Ensure ownership so unbound can read its state
if id unbound >/dev/null 2>&1; then
  chown -R unbound:unbound /var/lib/unbound || true
fi

CONF_DIR="/etc/unbound/unbound.conf.d"
CONF_FILE="${CONF_DIR}/recursive-local.conf"
mkdir -p "$CONF_DIR"

cat > "$CONF_FILE" <<'EOF'
server:
    # Listen only on localhost; no open resolver
    interface: 127.0.0.1
    interface: ::1
    # Restrict who can query
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    # Root hints: talk directly to root servers, no forwarders
    root-hints: "/var/lib/unbound/root.hints"
    # Rely on the global auto-trust-anchor-file from the main unbound.conf
    # (Debian default already points to /var/lib/unbound/root.key)
    # Hardening / privacy
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    # Performance / cache
    prefetch: yes
    prefetch-key: yes
    cache-min-ttl: 0
    cache-max-ttl: 86400
    # Logging
    verbosity: 1

remote-control:
    control-enable: no
EOF

echo "[*] Unbound configuration written to ${CONF_FILE}"

echo "[*] Checking Unbound configuration..."
if command -v unbound-checkconf >/dev/null 2>&1; then
  unbound-checkconf
else
  echo "    WARNING: unbound-checkconf not found, skipping config validation."
fi

echo "[*] Enabling and starting unbound..."
systemctl enable unbound
systemctl restart unbound || {
  echo "[-] Failed to start unbound. Check:"
  echo "    systemctl status unbound.service"
  echo "    journalctl -xeu unbound.service"
  exit 1
}

# Optionally adjust resolv.conf if it is not a symlink
if [[ ! -L /etc/resolv.conf ]]; then
  if [[ ! -f /etc/resolv.conf.backup-pre-unbound ]]; then
    echo "[*] Backing up /etc/resolv.conf to /etc/resolv.conf.backup-pre-unbound"
    cp /etc/resolv.conf /etc/resolv.conf.backup-pre-unbound || true
  fi
  echo "[*] Pointing /etc/resolv.conf to 127.0.0.1 and ::1"
  printf 'nameserver 127.0.0.1\nnameserver ::1\n' > /etc/resolv.conf
else
  echo "[*] /etc/resolv.conf is a symlink (likely systemd-resolved). Not touching it."
  echo "    Point your resolver at 127.0.0.1 and ::1 manually if you want to use Unbound globally."
fi

if command -v cloud-init >/dev/null 2>&1; then
  echo "[*] Waiting for cloud-init to finish before writing MOTD..."
  cloud-init status --wait
fi

MOTD_TEXT="This host is a looking glass. It runs as the ${LG_USER} user."
echo "[*] Writing /etc/motd..."
printf '%s\n' "$MOTD_TEXT" >/etc/motd
mkdir -p /etc/update-motd.d
cat >/etc/update-motd.d/99-looking-glass <<EOF
#!/bin/sh
echo
echo "${MOTD_TEXT}"
echo
EOF
chmod +x /etc/update-motd.d/99-looking-glass

echo
echo "[*] Done. This box is a looking glass; the service account is ${LG_USER}."
echo "    Next (as root): sudo -u ${LG_USER} ${SCRIPT_DIR}/bootstrap-user.sh"
echo
echo "[*] Unbound tests:"
echo "    dig @127.0.0.1 example.com +short"
echo "    dig @::1 example.com +short"
echo "    dig @127.0.0.1 google.com +dnssec +short"
echo "    dig @::1 google.com +dnssec +short"
echo
echo "[*] This Unbound instance is a full recursive resolver that talks only to the root servers."

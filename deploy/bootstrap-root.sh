#!/usr/bin/env bash

set -euo pipefail

LG_USER="looking-glass"
LG_HOME="/home/looking-glass"
LOOKING_GLASS_RAW_BASE="${LOOKING_GLASS_RAW_BASE:-https://raw.githubusercontent.com/cselzer/looking-glass/refs/heads/main/deploy}"
USAGE="usage: $0 [--email ADDRESS]"

SELF="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR=""
if [[ -f "$SELF" && "$SELF" != "bash" && "$SELF" != "-" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$SELF")" && pwd)"
fi

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
EMAIL="${EMAIL#"${EMAIL%%[![:space:]]*}"}"
EMAIL="${EMAIL%"${EMAIL##*[![:space:]]}"}"
if [[ -n "$EMAIL" && "$EMAIL" != *@* ]]; then
  echo "[-] --email must be an email address (or omit it)." >&2
  exit 1
fi

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
  if [[ -n "${FQDN:-}" && "$FQDN" == *.* ]]; then
    echo "    DNS A:    $(dig +short A "$FQDN" 2>/dev/null | tr '\n' ' ')" >&2
    echo "    DNS AAAA: $(dig +short AAAA "$FQDN" 2>/dev/null | tr '\n' ' ')" >&2
    echo "    NIC IPv4 (scope global):" >&2
    ip -4 -o addr show scope global >&2 || true
    echo "    NIC IPv6 (scope global):" >&2
    ip -6 -o addr show scope global >&2 || true
    echo >&2
  fi
  echo "    1. hostnamectl set-hostname s1.example.com" >&2
  echo "    2. Publish A and AAAA for that name pointing at this VM." >&2
  echo "    3. Assign both addresses on the NIC (not only fe80::)." >&2
  echo "    4. Re-run this script." >&2
  echo >&2
  echo "    Debian /etc/hosts often aliases the FQDN to 127.0.1.1; this" >&2
  echo "    check uses dig (DNS), not getent (NSS / hosts)." >&2
  exit 1
}

# stdin: one address per line (optional /prefix or %iface). Prints compressed public IPs.
_usable_ips() {
  python3 -c '
import ipaddress, sys
for raw in sys.stdin:
    text = raw.strip().split("%", 1)[0].split("/", 1)[0]
    if not text:
        continue
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        continue
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        continue
    print(addr.compressed)
'
}

_addrs() {
  local family="$1"
  ip -"${family}" -o addr show scope global | awk '{print $4}' | _usable_ips
}

_resolved() {
  local family="$1" name="$2"
  local qtype
  if [[ "$family" == 4 ]]; then
    qtype=A
  else
    qtype=AAAA
  fi
  dig +short "$qtype" "$name" | _usable_ips
}

_has_match() {
  local family="$1" name="$2"
  local local_addrs resolved
  local_addrs="$(_addrs "$family")"
  resolved="$(_resolved "$family" "$name")"
  if [[ -z "$local_addrs" || -z "$resolved" ]]; then
    return 1
  fi
  LOCAL_ADDRS="$local_addrs" DNS_ADDRS="$resolved" python3 -c '
import ipaddress, os, sys

def parse(blob):
    out = []
    for line in blob.splitlines():
        text = line.strip()
        if not text:
            continue
        out.append(ipaddress.ip_address(text))
    return out

local = parse(os.environ.get("LOCAL_ADDRS") or "")
dns = parse(os.environ.get("DNS_ADDRS") or "")
sys.exit(0 if any(a == b for a in local for b in dns) else 1)
'
}

echo "[*] Installing packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  unbound unbound-anchor curl ca-certificates python3-venv git ufw bind9-dnsutils

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

if ! getent passwd "$LG_USER" >/dev/null; then
  echo "[*] Creating user ${LG_USER} (${LG_HOME})..."
  useradd --create-home --home-dir "$LG_HOME" --shell /bin/bash "$LG_USER"
else
  echo "[*] User ${LG_USER} already exists"
fi

echo "[*] Allowing unprivileged bind from port 80..."
printf 'net.ipv4.ip_unprivileged_port_start=80\n' >/etc/sysctl.d/99-looking-glass.conf
sysctl -w net.ipv4.ip_unprivileged_port_start=80

echo "[*] ufw: allow outgoing; inbound 22, 80 (ACME), 5555 (HTTPS)..."
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 5555/tcp

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

echo "[*] Running user bootstrap as ${LG_USER}..."
user_src=""
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/bootstrap-user.sh" ]]; then
  user_src="$SCRIPT_DIR/bootstrap-user.sh"
else
  echo "    fetching bootstrap-user.sh from ${LOOKING_GLASS_RAW_BASE}"
  user_src="$(mktemp)"
  curl -fsSL "${LOOKING_GLASS_RAW_BASE%/}/bootstrap-user.sh" -o "$user_src"
fi
install -o "$LG_USER" -g "$LG_USER" -m 0755 \
  "$user_src" "$LG_HOME/.bootstrap-user.sh"
if [[ -z "$SCRIPT_DIR" || "$user_src" != "$SCRIPT_DIR/bootstrap-user.sh" ]]; then
  rm -f "$user_src"
fi
LG_UID="$(id -u "$LG_USER")"
LG_RUNTIME="/run/user/${LG_UID}"
if [[ -n "$EMAIL" ]]; then
  runuser -u "$LG_USER" -- env HOME="$LG_HOME" USER="$LG_USER" LOGNAME="$LG_USER" \
    XDG_RUNTIME_DIR="$LG_RUNTIME" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=${LG_RUNTIME}/bus" \
    "$LG_HOME/.bootstrap-user.sh" --email "$EMAIL"
else
  runuser -u "$LG_USER" -- env HOME="$LG_HOME" USER="$LG_USER" LOGNAME="$LG_USER" \
    XDG_RUNTIME_DIR="$LG_RUNTIME" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=${LG_RUNTIME}/bus" \
    "$LG_HOME/.bootstrap-user.sh"
fi

rm -fv "$LG_HOME/.bootstrap-user.sh"

echo
echo "[*] Done. This box is a looking glass; the service account is ${LG_USER}."
echo
echo "[*] Unbound tests:"
echo "    dig @127.0.0.1 example.com +short"
echo "    dig @::1 example.com +short"
echo "    dig @127.0.0.1 google.com +dnssec +short"
echo "    dig @::1 google.com +dnssec +short"
echo
echo "[*] This Unbound instance is a full recursive resolver that talks only to the root servers."

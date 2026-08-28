# looking-glass

A self-hosted looking glass: local RIR/IANA/ASN datasets, a Click CLI, a Unix-socket intel server, a WSGI/ASGI GUI and JSON API, a request wall, and optional ACME HTTPS.

Requires **Python 3.13+**.

## Install

Checkout:

```
pip install -e .
looking-glass --help
```

VM (Debian/Ubuntu): as root, after the FQDN has A+AAAA on the NIC. [`deploy/bootstrap-root.sh`](deploy/bootstrap-root.sh) opens guest **ufw** for 22, 80 (ACME), and 5555 (HTTPS), creates the `looking-glass` user, and runs [`deploy/bootstrap-user.sh`](deploy/bootstrap-user.sh) as that account. Let's Encrypt contact email is optional. If the provider has a **cloud firewall**, allow 80 and 5555 there too (IPv4 and IPv6).

Convenience (current `main`):

```
curl -fsSL https://raw.githubusercontent.com/cselzer/looking-glass/refs/heads/main/deploy/bootstrap-root.sh | bash
curl -fsSL https://raw.githubusercontent.com/cselzer/looking-glass/refs/heads/main/deploy/bootstrap-root.sh | bash -s -- --email you@example.com
```

Bulk: same pipe from cloud-init, pin the URL (or `LOOKING_GLASS_RAW_BASE`) to a tag or commit so a push mid-rollout does not mix versions:

```
LOOKING_GLASS_RAW_BASE=https://raw.githubusercontent.com/cselzer/looking-glass/refs/tags/v0.1.0/deploy
curl -fsSL "$LOOKING_GLASS_RAW_BASE/bootstrap-root.sh" | LOOKING_GLASS_RAW_BASE="$LOOKING_GLASS_RAW_BASE" bash
```

From a checkout: `./deploy/bootstrap-root.sh` (uses the sibling user script).

Config, datasets, caches, sessions, and certs live under `~/.looking-glass` (`config.json`, `data/`, `certs/`).

## CLI

```
looking-glass build
looking-glass validate
looking-glass lookup 1.1.1.1
looking-glass dns example.com MX
looking-glass register example
looking-glass tls example.com
looking-glass rdap 1.1.1.1
looking-glass ping 1.1.1.1
looking-glass traceroute 1.1.1.1
looking-glass lookup-server start
looking-glass wall block ip 203.0.113.0/24
looking-glass --json lookup 1.1.1.1
```

Command groups:

- **Datasets:** `build`, `validate`
- **Look up:** `lookup`, `ip`, `asn`, `rdap`, `whois`, `bgp`, `reputation`
- **DNS:** `dns`, `dnssec`, `dnstrace`, `ptr`, `apex`, `mail`, `register`
- **Path:** `ping`, `traceroute`, `mtr`, `tcptraceroute`, `tcp`, `pmtu`, `tls`, `http`
- **Intel / site:** `lookup-server`, `https`, `wall`, `cache`, `logs`, `docs`, `status`, `restart`
- **Operator:** `config`, `auth`, `boot`, `locale`

Pass `--json` (or `LOOKING_GLASS_JSON=1`) for machine output. `LOOKING_GLASS_LANG` sets the UI locale for help and HTML; JSON stays English.

## Intel server

```
looking-glass lookup-server start
looking-glass lookup-server status
looking-glass lookup-server stop
```

The intel server warms datasets and listens on `~/.looking-glass/data/lookup.sock`. The HTTP site and `looking-glass lookup` use that socket when it is up. Start does not report up until datasets are loaded.

## Boot

systemd `--user` units so intel and HTTPS start at reboot. Linger once as root, then enable as the looking-glass user:

```
loginctl enable-linger looking-glass
sudo -u looking-glass looking-glass boot enable
looking-glass boot check
looking-glass status
looking-glass restart
```

## HTTPS

The site daemon: TLS on `http.port` (default 5555) and Let's Encrypt HTTP-01 on port 80. No reverse proxy. Enable linger and `looking-glass boot enable` (see Boot) so it survives reboot.

```
looking-glass config hostname s1.example.com
looking-glass config set http.email you@example.com
looking-glass config set http.enabled true
looking-glass https start
looking-glass https status
looking-glass https logs
looking-glass https renew
looking-glass https renew --force
looking-glass tls s1.example.com -p 5555
looking-glass https stop
```

TLS listens on `http.port` (default 5555) on **both IPv4 and IPv6** (`http.bind` default `*`: `0.0.0.0` and `::`). Pin one family with `looking-glass config set http.bind 0.0.0.0` or `::`. HTTP-01 uses `http.acme_port` (default 80). Port 80 must be free and bindable as a non-root user (`net.ipv4.ip_unprivileged_port_start`). `http.email` is optional (Let's Encrypt expiry notices). Certs live in `~/.looking-glass/certs/<hostname>/`. `https status` shows bind, listen addresses, paths, expiry, and whether a renew is due. `https logs` tails the supervisor stdout/stderr. `https renew` issues without starting TLS; `--force` ignores the 30-day window. The supervisor reloads uvicorn when the cert files change. `looking-glass tls … -p 5555` inspects the live handshake.

Host **ufw** (bootstrap allows 22, 80, 5555) is not enough if the provider has a **cloud firewall**: allow **80** and **5555** on IPv4 and IPv6. After `https stop` / `https start` (or `config set http.bind '*'` if an older config still has `0.0.0.0` or `::`), check from a laptop with `nc -vz s1.example.com 5555`. If that times out, open 5555 on the cloud firewall.

## HTTP

Local demos (localhost only). The public GUI is `looking-glass https start` / `boot`.

```
looking-glass wall wsgi --host 127.0.0.1 --port 8000
looking-glass wall asgi --host 127.0.0.1 --port 8001
```

GET `/` is the HTML GUI (or a JSON lookup of the TCP peer). Tools are path-shaped: `/1.1.1.1`, `/dns/example.com/MX`, `/register/example`, `/tls/example.com`, `/ping/1.1.1.1`, `/status`.

## Wall

Allow, block, and challenge lists used in front of the HTTP app. Unknown visitors are allowed. Challenge is a first-party proof-of-work puzzle; a pass cookie lasts `wall.challenge_ttl_days` (default 5).

Lists live in `~/.looking-glass/data/wall.json`.

```
looking-glass wall block ip 203.0.113.0/24
looking-glass wall block asn 13335
looking-glass wall challenge ip 198.51.100.0/24
looking-glass wall list ip
looking-glass wall log
```

## Auth

GUI admin is a password (no username) plus API keys. An unset password disables login; it does not open admin. Keys work independently (`Authorization: Bearer`).

```
looking-glass auth password set
looking-glass auth keys create tokyo
looking-glass auth sessions clear
```

## Locale

Shipped UI catalogs live in the package. `looking-glass locale` manages operator overlays under `~/.looking-glass/locales` (`list`, `add`, `edit`, `delete`). JSON APIs stay English.

## Operator notes

This is a looking glass. Exposing the HTTP site lets visitors run ping, traceroute, MTR, TLS, HTTP inspect, and TCP checks against targets they choose. The wall restricts *who* can reach you; it does not refuse private or RFC1918 *destinations*. Put allow/block/challenge lists in place before binding past localhost.

`docs.enabled` is off by default. Leave it off unless you want `GET /docs`.

Do not commit `~/.looking-glass`. That directory holds datasets, session files, and ACME keys.

## License

MIT. See [LICENSE](LICENSE).

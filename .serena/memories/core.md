# Project core — looking-glass

Self-hosted **looking glass**: IP/domain intel, DNS, RDAP, path probes
(ping/traceroute/mtr/tls/http/tcp), a request wall, and optional ACME HTTPS.
Surfaces: a Click **CLI**, a Unix-socket **intel server**, and a **WSGI/ASGI GUI +
JSON API**.

Import package `looking_glass/`; distribution `looking-glass`. Console script
`looking-glass` → `looking_glass.cli:main` → `looking_glass/cli/entry.py`
(`cli`, `main`). Also `python -m looking_glass.cli`.

## Source map

- `looking_glass/cli/` — Click CLI. `entry.py` (full command tree +
  `_COMMAND_ORDER`), `config_cmd.py`, `auth_cmd.py`, `boot.py`, `locale_cmd.py`,
  `render.py` (`emit` / `emit_path` output helpers), `tools.py`.
- `looking_glass/intel/` — asn, asn_org, asn_prefixes, bgp, flags, iana, rdap,
  rir, whois.
- `looking_glass/intel_server/` — FastAPI/ASGI intel server listening on
  `~/.looking-glass/data/lookup.sock`. `app.py`, `pipeline.py`
  (`classify_query`, `lookup_ip`, `lookup_country`, `warmup`), `client.py`,
  `bench.py`. CLI `lookup` and the HTTP site use this socket when up.
- `looking_glass/dns/` — resolve, apex, dnssec, ptr, register, reputation (RBLs),
  trace.
- `looking_glass/net/` — host, httpinspect, mail, pmtu, probe
  (ping/traceroute), tcpcheck, tls.
- `looking_glass/wall/` — allow/block/challenge lists in front of the HTTP app.
  `lists.py`, `challenge.py` (first-party proof-of-work), `traffic.py`,
  `wrapper.py`. Data in `~/.looking-glass/data/wall.json`. Unknown visitors are
  allowed; the wall gates *who reaches you*, not probe destinations.
- `looking_glass/http/` — GUI + JSON API. `wsgi.py`, `asgi.py`, `site.py`,
  `render.py`, `admin.py`, `security.py`, `static_files.py`, `weblog.py`,
  `https_serve.py`, `acme_issue.py`, `cli_text.py`, `templates/`, `static/`.
  Tools are path-shaped: `/1.1.1.1`, `/dns/example.com/MX`, `/status`, …
- `looking_glass/auth/` — GUI admin password (no username) + bearer API keys.
  `password.py`, `keys.py`, `session.py`, `store.py`, `history.py`.
- `looking_glass/i18n/` — `catalog.py`, `click_overlay.py`, `messages.py`.
  Shipped catalogs in `looking_glass/locales/` (`en.json`, `es.json`,
  `glossary.json`). Operator overlays under `~/.looking-glass/locales`.
- `looking_glass/docs/` — `catalog.py`, `generate.py` (`GET /docs`, off by
  default via `docs.enabled`).
- Top level: `datasets.py` (`DATASETS` registry, `refresh_due_at`, `file_row`),
  `config.py` (flat dotted-key config), `cache.py`, `logrotate.py`, `observe.py`,
  `utility.py` (`atomic_write`, `get_data_dir`, `get_cache_path`).
- `tools/` — **dev/translation tooling, not shipped**: `engine.py` (batched
  translation with TM + verify), `glossary.py`, `locale.py`, `providers.py`,
  `ship_langs.py`, `tm.py`.
- `deploy/` — `bootstrap-root.sh`, `bootstrap-user.sh` (Debian/Ubuntu VM
  provisioning; systemd `--user` units; venv at `~/.venv`).
- `tests/` — 40 `test_*.py` files (see `mem:suggested_commands`,
  `mem:task_completion`).

## Invariants

- Runtime state lives in `~/.looking-glass/` (`config.json`, `data/`, `certs/`,
  `locales/`). Never commit it; `data/` is gitignored.
- Write anything under the state dir via `looking_glass.utility.atomic_write`.
- `--json` or `LOOKING_GLASS_JSON=1` → machine output. JSON APIs are always
  English regardless of locale.
- `LOOKING_GLASS_LANG` sets the UI locale for CLI help and HTML.
- Config is a **flat dotted-key** namespace (`http.port`, `http.bind`,
  `http.controller_origins`, `wall.challenge_ttl_days`, …). Go through
  `looking_glass/config.py`.
- Version is derived from git tags by setuptools-scm into the gitignored
  `looking_glass/_version.py`; `package_version()` in `looking_glass/__init__.py`.

## Further memories

- `mem:tech_stack` — Python version, runtime deps, build backend, absence of lint/type tooling.
- `mem:conventions` — code style, import style, config/output patterns, test-writing rules.
- `mem:suggested_commands` — install, CLI, GUI, and test invocations; Darwin/BSD command caveats.
- `mem:task_completion` — exact checks to run before considering a change done.

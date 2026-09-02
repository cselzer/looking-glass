# Suggested commands — looking-glass

## Setup

- `pip install -e .` — editable install; also regenerates `looking_glass/_version.py`.
- `looking-glass --help` — sanity-check the CLI wiring.

## CLI (see README for the full command list)

- `looking-glass build` — fetch/refresh IANA/RIR/ASN datasets into `~/.looking-glass/data/`.
- `looking-glass validate` — validate local datasets.
- `looking-glass lookup 1.1.1.1`, `looking-glass dns example.com MX`,
  `looking-glass rdap 1.1.1.1`, `looking-glass ping 1.1.1.1`, `looking-glass tls example.com`.
- `looking-glass lookup-server start | status | stop` — Unix-socket intel server
  (`~/.looking-glass/data/lookup.sock`); `start` reports up only once datasets are loaded.
- `looking-glass wall block ip 203.0.113.0/24`, `looking-glass wall list ip`, `looking-glass wall log`.
- Machine output: append `--json` or set `LOOKING_GLASS_JSON=1`. UI locale: `LOOKING_GLASS_LANG`.

## Local GUI (localhost demos only)

- `looking-glass wall wsgi --host 127.0.0.1 --port 8000`
- `looking-glass wall asgi --host 127.0.0.1 --port 8001`

## Tests

- Fast suite (no network):
  `python -m pytest --ignore=tests/test_live.py --ignore=tests/test_live_validation.py`
- Full suite incl. live internet tests (~1–2 min, downloads real datasets, uses a
  throwaway HOME): `python -m pytest`
- Single file: `python -m pytest tests/test_wall.py`
- Also works: `python -m unittest`

## Darwin (macOS) notes

- BSD userland: `sed -i` needs an arg — `sed -i '' …`; `ls` / `grep` / `find` are
  BSD variants (GNU-only flags absent).
- `python3` / `pip` resolve through a **pyenv shim** (currently 3.14.x).
- Probe subcommands shell out to system binaries: macOS `ping` / `traceroute`
  take different flags than Linux; there is no system `mtr`.
- `git` is standard.

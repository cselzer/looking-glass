# Conventions — looking-glass

## Code style

- `from __future__ import annotations` at the top of modules.
- Type hints throughout, but two styles coexist: older `typing.Optional/Dict/List/
  Tuple` (e.g. `cli/entry.py`) and PEP 604 `X | None` (e.g. `__init__.py`).
  Match the file you are editing.
- Short one-line module docstrings (triple-quoted).
- Explicit intra-package **relative** imports: `from ..intel import asn`,
  `from .render import emit`.
- No enforced formatter: 4-space indent, ~100–120 columns, match surroundings.

## Patterns

- Config: flat dotted keys via `looking_glass/config.py`
  (`http.port`, `wall.challenge_ttl_days`, `http.controller_origins` which accepts
  CSV or JSON-list strings, …). Add new keys through that module; the set of known
  keys is derived from leaf dotted paths of a nested default dict.
- CLI output: go through `looking_glass/cli/render.py` (`emit`, `emit_path`);
  always honor `--json` / `LOOKING_GLASS_JSON`.
- Filesystem writes under `~/.looking-glass/` use
  `looking_glass.utility.atomic_write` (+ `get_data_dir`, `get_cache_path`).
- New shipped assets (HTML templates, static files, locale JSON) must be
  registered in `[tool.setuptools.package-data]` in `pyproject.toml`.
- UI strings are localized; JSON API responses stay English.

## Tests

- `unittest.TestCase` subclasses (not pytest-native fixtures); run under pytest.
- CLI tested with `click.testing.CliRunner` invoking `looking_glass.cli.entry.cli`.
- Mock with `unittest.mock.patch`.
- Any code that touches `~/.looking-glass` must be tested against a throwaway
  `HOME` / tmpdir (see `tests/test_live.py` `setUpModule` for the pattern).
- Live/network tests live only in `tests/test_live.py` and
  `tests/test_live_validation.py`; keep new network-dependent tests there or mock.

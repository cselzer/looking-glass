# Tech stack — looking-glass

- **Language:** Python, `requires-python = ">=3.13"`. Dev machine (Darwin) runs
  CPython 3.14.x via a pyenv shim (`python3`); `.pyc` caches for both 3.13 and
  3.14 are present.
- **Build backend:** `setuptools>=64` + `setuptools-scm>=8`
  (`build-backend = "setuptools.build_meta"`). Version is dynamic, written to
  `looking_glass/_version.py` (gitignored) from git tags.
- **Packaging:** all config in `pyproject.toml`. `packages.find` includes
  `looking_glass*`. `package-data`: `looking_glass.http` → `templates/*.html`,
  `static/*`; `looking_glass.locales` → `*.json`.
- **Entry point:** `[project.scripts]` `looking-glass = "looking_glass.cli:main"`.

## Runtime dependencies (pyproject `[project.dependencies]`)

click>=8.1, rich>=13.7, Babel>=2.12, tqdm>=4.66, dnspython[dnssec]>=2.6,
cryptography>=42, Jinja2>=3.1, requests>=2.31, httpx[http2]>=0.27, aiohttp>=3.9,
pyasn>=1.6, fastapi>=0.110, uvicorn>=0.27, acme>=2.0.

`starlette` is pulled in transitively via fastapi and imported directly in some
tests (`tests/test_lookup.py`).

## Tooling

- **No** dev-dependency group, and **no** ruff / black / isort / mypy / flake8 /
  tox / nox / Makefile / pre-commit / `conftest.py` anywhere in the repo.
- Tests are `unittest` style, run under **pytest** (`.pytest_cache/` present).
  pytest is not declared as a dependency — installed ad hoc.

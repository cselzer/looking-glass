# Task completion checklist — looking-glass

There is **no** linter, formatter, or type checker configured in this repo, so
there is nothing of that kind to run. When a coding task is done:

1. **Fast test suite** (no network):
   `python -m pytest --ignore=tests/test_live.py --ignore=tests/test_live_validation.py`

2. **Live tests** — only if the change touches intel / datasets / DNS / RDAP /
   networking / dataset build:
   `python -m pytest tests/test_live.py tests/test_live_validation.py`
   (requires internet, downloads real IANA/RIR/ASN data, ~1–2 min, throwaway HOME)

3. **CLI smoke:** `looking-glass --help` still renders (catches command-tree
   wiring and i18n/click-overlay breakage).

4. If UI-facing strings changed: review the translation flow in `tools/`
   (`engine.py`, `glossary.py`) and/or `looking-glass locale`; keep
   `looking_glass/locales/en.json` and overlays consistent.

5. **Do not commit** unless the user explicitly asks. If asked, stage files by
   name and never include `~/.looking-glass` contents.

See `mem:suggested_commands` for the command details and `mem:conventions` for
style expectations.

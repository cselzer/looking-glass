"""Catalog status, dry-run, and batched translation with TM + verify."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from looking_glass.i18n.catalog import dump_catalog, load_json_file
from looking_glass.utility import atomic_write

from .glossary import (
    copy_through_dirty_keys,
    copy_through_keys,
    effective_glossary,
    glossary_for_prompt,
    verify_translation,
)
from .providers import (
    DEFAULT_READ_TIMEOUT,
    LocaleCliError,
    ProviderError,
    complete_json,
    require_api_key,
    require_provider,
    resolve_model,
)
from .ship_langs import require_ship_lang
from . import tm as tm_mod

log = logging.getLogger("looking_glass.locale")


def _progress(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def locale_label(lang: str) -> str:
    """Registry prompt line, or the raw code if it is not a ship locale."""
    from .ship_langs import get_ship_lang

    row = get_ship_lang(lang)
    if row:
        return row["prompt"]
    return (lang or "").strip()


def system_prompt(lang: str, glossary: Sequence[str]) -> str:
    terms = glossary_for_prompt(glossary)
    row = require_ship_lang(lang)
    return (
        "You translate looking-glass UI catalog strings into the target locale.\n"
        "Return a JSON object only: {\"<message-id>\": \"<translated text>\"}.\n"
        "No markdown, no commentary, no wrapper keys.\n\n"
        f"Target locale: {row['prompt']}\n"
        f"{row['style']}\n"
        f"Glossary (do not translate these exact substrings): {terms}\n\n"
        "Rules:\n"
        "- Put the translation in the JSON value. Do not rewrite message ids.\n"
        "- Click is the Python library, not a mouse click.\n"
        "- Preserve {placeholders} exactly, including {path} {ip} {cmd} {n} {value}.\n"
        "- Preserve backtick spans, --flags, ~/.looking-glass/… paths, <angle> tokens, and Click \\b.\n"
        "- Tech terms stay English. Translate surrounding prose only.\n"
    )


def load_src(path: str | Path) -> Dict[str, Dict[str, str]]:
    dest = Path(path)
    if not dest.is_file():
        raise LocaleCliError(f"source catalog not found: {dest}")
    messages = load_json_file(dest)
    if not messages:
        raise LocaleCliError(f"source catalog is empty: {dest}")
    return messages


def load_dst(path: str | Path) -> Dict[str, Dict[str, str]]:
    dest = Path(path)
    if not dest.is_file():
        return {}
    return load_json_file(dest)


def est_tokens(text: str) -> int:
    n = len((text or "").encode("utf-8"))
    if n == 0:
        return 0
    return max(1, (n + 3) // 4)


def estimate_send(
    src: Mapping[str, Mapping[str, str]],
    send: Sequence[str],
    *,
    lang: str,
    batch_size: int = 25,
    glossary_path: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Same batching as translate: glossary on every batch, unique English hashes."""
    glossary = effective_glossary(glossary_path)
    system = system_prompt(lang, glossary)
    groups = tm_mod.group_by_en_hash(src, send)
    hashes = list(groups)
    size = max(1, int(batch_size or 25))
    batches = (len(hashes) + size - 1) // size if hashes else 0
    est_in = 0
    est_out = 0
    for start in range(0, len(hashes), size):
        chunk = hashes[start : start + size]
        reps: Dict[str, str] = {}
        for digest in chunk:
            keys = groups[digest]
            rep = keys[0]
            row = src.get(rep) or {}
            reps[rep] = row.get("en") or ""
        user = json.dumps({"locale": lang, "messages": reps}, ensure_ascii=False)
        est_in += est_tokens(system) + est_tokens(user)
        est_out += est_tokens(user)
    return {
        "send": list(send),
        "send_unique": len(groups),
        "batches": batches,
        "batch_size": size,
        "est_input": est_in,
        "est_output": est_out,
        "est_tokens": est_in + est_out,
    }


def catalog_counts(
    src: Mapping[str, Mapping[str, str]],
    dst: Mapping[str, Mapping[str, str]],
    memory: Mapping[str, Any],
) -> Dict[str, Any]:
    classified = tm_mod.classify_keys(src, dst, memory)
    return {
        "keys": len(src),
        "unique": tm_mod.unique_hashes(src),
        "new": len(classified["new"]),
        "changed": len(classified["changed"]),
        "unchanged": len(classified["unchanged"]),
        "missing": len(classified["missing"]),
        "new_keys": classified["new"],
        "changed_keys": classified["changed"],
        "unchanged_keys": classified["unchanged"],
        "missing_keys": classified["missing"],
    }


def status_payload(
    src_path: str | Path,
    dst_path: Optional[str | Path] = None,
    *,
    lang: str = "en",
    tm_path: Optional[str | Path] = None,
    batch_size: int = 25,
    glossary_path: Optional[str | Path] = None,
    only_changed: bool = True,
) -> Dict[str, Any]:
    src = load_src(src_path)
    dst = load_dst(dst_path) if dst_path else {}
    memory_path = Path(tm_path) if tm_path else (tm_mod.tm_path_for(dst_path) if dst_path else None)
    memory = tm_mod.load_tm(memory_path) if memory_path else {"keys": {}}
    counts = catalog_counts(src, dst, memory)
    classified = {
        "new": counts["new_keys"],
        "changed": counts["changed_keys"],
        "unchanged": counts["unchanged_keys"],
    }
    send = tm_mod.keys_to_send(classified, only_changed=only_changed)
    glossary = effective_glossary(glossary_path)
    held = set(copy_through_keys(src, glossary))
    send = [key for key in send if key not in held]
    dirty = copy_through_dirty_keys(src, dst, glossary)
    estimate = estimate_send(
        src, send, lang=lang, batch_size=batch_size, glossary_path=glossary_path
    )
    return {
        "ok": True,
        "src": str(src_path),
        "dst": str(dst_path) if dst_path else None,
        "tm": str(memory_path) if memory_path else None,
        "lang": lang,
        **counts,
        **estimate,
        "copy_through": [key for key in src if key in held],
        "copy_through_dirty": dirty,
    }


def _merge_working(
    src: Mapping[str, Mapping[str, str]],
    dst: Mapping[str, Mapping[str, str]],
) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for key, row in dst.items():
        out[key] = {
            "en": row.get("en") or "",
            "text": row.get("text") or row.get("en") or "",
        }
    for key, row in src.items():
        en = row.get("en") or ""
        prev = out.get(key) or {}
        text = prev.get("text") or row.get("text") or en
        out[key] = {"en": en, "text": text}
    return out


def _write_dst(path: Path, lang: str, messages: Mapping[str, Mapping[str, str]]) -> None:
    atomic_write(str(path), dump_catalog(lang, dict(messages), source="en"))
    log.info("write %s", path)


def translate(
    src_path: str | Path,
    dst_path: str | Path,
    *,
    lang: str,
    provider: str,
    model: Optional[str] = None,
    only_changed: bool = True,
    glossary_path: Optional[str | Path] = None,
    batch_size: int = 25,
    tm_path: Optional[str | Path] = None,
    dry_run: bool = False,
    timeout: float = DEFAULT_READ_TIMEOUT,
    reasoning_effort: str = "high",
) -> Dict[str, Any]:
    provider = require_provider(provider)
    src = load_src(src_path)
    dst_file = Path(dst_path)
    dst = load_dst(dst_file)
    memory_path = Path(tm_path) if tm_path else tm_mod.tm_path_for(dst_file)
    memory = tm_mod.load_tm(memory_path)
    classified = tm_mod.classify_keys(src, dst, memory)
    working = _merge_working(src, dst)
    tm_keys = memory.get("keys") if isinstance(memory.get("keys"), dict) else {}
    for key in classified["unchanged"]:
        rec = tm_keys.get(key) if isinstance(tm_keys.get(key), dict) else None
        if rec and rec.get("text") and not str((dst.get(key) or {}).get("text") or "").strip():
            working[key] = {"en": src[key].get("en") or "", "text": str(rec["text"])}
    send = tm_mod.keys_to_send(classified, only_changed=only_changed)
    glossary = effective_glossary(glossary_path)
    held = copy_through_keys(src, glossary)
    held_set = set(held)
    dirty = copy_through_dirty_keys(src, dst, glossary)
    for key in held:
        en = src[key].get("en") or ""
        working[key] = {"en": en, "text": en}
    send = [key for key in send if key not in held_set]
    model_id = resolve_model(provider, model)
    groups = tm_mod.group_by_en_hash(src, send)
    estimate = estimate_send(
        src, send, lang=lang, batch_size=batch_size, glossary_path=glossary_path
    )
    payload = {
        "ok": True,
        "src": str(src_path),
        "dst": str(dst_file),
        "tm": str(memory_path),
        "lang": lang,
        "provider": provider,
        "model": model_id,
        "only_changed": only_changed,
        "keys": len(src),
        "unique": tm_mod.unique_hashes(src),
        "send": send,
        "send_unique": len(groups),
        "skipped": classified["unchanged"] if only_changed else [],
        "new": len(classified["new"]),
        "changed": len(classified["changed"]),
        "unchanged": len(classified["unchanged"]),
        "missing": len(classified["missing"]),
        "copy_through": held,
        "copy_through_dirty": dirty,
        "reasoning_effort": reasoning_effort,
        "batches": estimate["batches"],
        "batch_size": estimate["batch_size"],
        "est_input": estimate["est_input"],
        "est_output": estimate["est_output"],
        "est_tokens": estimate["est_tokens"],
    }
    if dry_run:
        log.info("dry-run send=%d unique=%d provider=%s model=%s", len(send), len(groups), provider, model_id)
        return payload

    skipped = payload["skipped"]
    for key in skipped:
        log.debug("skip %s (unchanged)", key)

    for key in held:
        tm_mod.put_tm_key(
            memory,
            key,
            en=src[key].get("en") or "",
            text=src[key].get("en") or "",
        )

    if not send:
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        _write_dst(dst_file, lang, working)
        tm_mod.save_tm(memory_path, memory)
        payload["sent"] = 0
        payload["failed"] = []
        payload["failed_reasons"] = {}
        return payload

    require_api_key(provider)
    system = system_prompt(lang, glossary)
    failed: List[str] = []
    failed_reasons: Dict[str, str] = {}

    def mark_failed(keys: Sequence[str], reason: str) -> None:
        failed.extend(keys)
        for key in keys:
            failed_reasons[key] = reason
    hashes = list(groups)
    size = max(1, int(batch_size or 25))
    n_batches = (len(hashes) + size - 1) // size
    total = len(send)
    done = 0
    for batch_i, start in enumerate(range(0, len(hashes), size), start=1):
        chunk = hashes[start : start + size]
        reps: Dict[str, str] = {}
        key_count = 0
        for digest in chunk:
            keys = groups[digest]
            key_count += len(keys)
            rep = keys[0]
            reps[rep] = src[rep].get("en") or ""
        _progress(f"⏳  batch {batch_i}/{n_batches}  sending {key_count}  ({done}/{total})")
        log.debug(
            "send batch=%d keys=%d provider=%s model=%s",
            len(reps),
            key_count,
            provider,
            model_id,
        )
        user = {"locale": lang, "messages": reps}
        try:
            translated = complete_json(
                provider,
                model_id,
                system,
                user,
                timeout=timeout,
                lang=lang,
                reasoning_effort=reasoning_effort,
            )
        except ProviderError:
            done += key_count
            raise
        for digest in chunk:
            keys = groups[digest]
            rep = keys[0]
            en = src[rep].get("en") or ""
            text = translated.get(rep)
            if not isinstance(text, str) or not text.strip():
                log.info("retry %s (empty)", rep)
                try:
                    retry = complete_json(
                        provider,
                        model_id,
                        system,
                        {"locale": lang, "messages": {rep: en}},
                        timeout=timeout,
                        lang=lang,
                        reasoning_effort=reasoning_effort,
                    )
                    text = retry.get(rep)
                except ProviderError as exc:
                    log.warning("FAIL %s provider: %s", rep, exc)
                    mark_failed(keys, f"provider: {exc}")
                    done += len(keys)
                    continue
            ok, reason = verify_translation(en, text or "", glossary)
            if not ok:
                log.info("retry %s (%s)", rep, reason)
                try:
                    retry = complete_json(
                        provider,
                        model_id,
                        system,
                        {"locale": lang, "messages": {rep: en}},
                        timeout=timeout,
                        lang=lang,
                        reasoning_effort=reasoning_effort,
                    )
                    text = retry.get(rep)
                except ProviderError as exc:
                    log.warning("FAIL %s provider: %s", rep, exc)
                    mark_failed(keys, f"provider: {exc}")
                    done += len(keys)
                    continue
                ok, reason = verify_translation(en, text or "", glossary)
            if not ok or not isinstance(text, str) or not text.strip():
                log.warning("FAIL %s %s", rep, reason or "empty")
                mark_failed(keys, reason or "empty")
                done += len(keys)
                continue
            for key in keys:
                working[key] = {"en": src[key].get("en") or "", "text": text}
                tm_mod.put_tm_key(
                    memory,
                    key,
                    en=src[key].get("en") or "",
                    text=text,
                    provider=provider,
                    model=model_id,
                )
            done += len(keys)
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        _write_dst(dst_file, lang, working)
        tm_mod.save_tm(memory_path, memory)
        log.info("write %s", memory_path)
        _progress(f"⏳  batch {batch_i}/{n_batches}  {done}/{total} keys")

    payload["sent"] = len(send) - len(failed)
    payload["failed"] = failed
    payload["failed_reasons"] = failed_reasons
    payload["ok"] = not failed
    return payload


def reset_locale(
    lang: Optional[str] = None,
    *,
    locales_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Delete LANG.json and LANG.json.tm.json. Never en. No API calls."""
    from looking_glass.i18n.catalog import normalize_lang, package_locales_dir

    from .ship_langs import require_ship_lang, ship_codes

    folder = Path(locales_dir) if locales_dir else package_locales_dir()
    if lang:
        code = normalize_lang(lang)
        if code == "en":
            raise LocaleCliError("reset never deletes en.json")
        require_ship_lang(code)
        codes = [code]
    else:
        codes = [code for code in ship_codes() if code != "en"]
    removed: List[str] = []
    missing: List[str] = []
    for code in codes:
        dest = folder / f"{code}.json"
        tm_file = tm_mod.tm_path_for(dest)
        for path in (dest, tm_file):
            if path.name == "en.json" or path.name.startswith("en.json."):
                continue
            if path.is_file():
                path.unlink()
                removed.append(str(path))
            else:
                missing.append(str(path))
    return {"ok": True, "langs": codes, "removed": removed, "missing": missing}


def configure_logging(verbose: int = 0, log_file: Optional[str] = None) -> None:
    logger = logging.getLogger("looking_glass.locale")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    if log_file:
        handler: logging.Handler = logging.FileHandler(log_file, encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)

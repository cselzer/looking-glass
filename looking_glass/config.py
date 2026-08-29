"""Operator settings in ~/.looking-glass/config.json (locale, cache TTL/GUI, dataset refresh)."""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .utility import atomic_write, get_root

DEFAULT_REFRESH: Dict[str, int] = {
    "iana": 30,
    "dns_types": 30,
    "tlds": 30,
    "rdap_dns": 30,
    "rir": 1,
    "asn_org": 7,
    "asn": 1,
}

DEFAULTS: Dict[str, Any] = {
    "locale": "en",
    "cache": {"ttl_days": 7, "gui": False},
    "refresh": dict(DEFAULT_REFRESH),
    "history": {"snapshots": -1},
    "wall": {"challenge_ttl_days": 5, "challenge_bits": 16},
    "docs": {"enabled": False},
    "mtr": {"cycles": 10, "max_cycles": 30},
    "http": {
        "enabled": False,
        "hostname": "",
        "email": "",
        "port": 5555,
        "acme_port": 80,
        "workers": 1,
        "bind": "*",
        "staging": False,
        "controller_origins": [],
    },
}

MTR_HARD_CEILING = 50
HTTP_WORKERS_MAX = 32

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def path() -> str:
    return str(Path(get_root()) / "config.json")


def lock_path() -> str:
    return path() + ".lock"


@contextmanager
def file_lock() -> Iterator[None]:
    dest = lock_path()
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    fd = os.open(dest, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _legacy_locale_path() -> Path:
    return Path(get_root()) / "locale"


def _legacy_data_file(name: str) -> Path:
    return Path(get_root()) / "data" / name


def _normalize_locale(value: Any) -> str:
    raw = str(value or "en").strip().replace("_", "-")
    if not raw:
        return "en"
    primary = raw.split(",")[0].strip().split(";")[0].strip()
    if not primary:
        return "en"
    return primary.split("-")[0].lower() or "en"


def _parse_days(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, float) and value >= 0 and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _parse_snapshots(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= -1:
        return value
    if isinstance(value, float) and value >= -1 and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("-") and text[1:].isdigit():
            parsed = int(text)
            return parsed if parsed >= -1 else None
        if text.isdigit():
            return int(text)
    return None


def _read_json(file_path: Path) -> Any:
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_legacy_locale() -> Optional[str]:
    file_path = _legacy_locale_path()
    if not file_path.is_file():
        return None
    try:
        text = file_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    if text.startswith("{"):
        data = _read_json(file_path)
        if isinstance(data, dict):
            return _normalize_locale(data.get("locale") or data.get("lang") or "")
        return None
    return _normalize_locale(text.splitlines()[0])


def _read_legacy_cache() -> Dict[str, Any]:
    data = _read_json(_legacy_data_file("cache.json"))
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Any] = {}
    days = _parse_days(data.get("ttl_days"))
    if days is not None:
        out["ttl_days"] = days
    if "gui" in data:
        out["gui"] = bool(data["gui"])
    return out


def _read_legacy_refresh() -> Dict[str, Any]:
    data = _read_json(_legacy_data_file("refresh.json"))
    if not isinstance(data, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in DEFAULT_REFRESH:
        if key not in data:
            continue
        parsed = _parse_days(data[key])
        if parsed is not None:
            out[key] = parsed
    return out


def _merge_cache(raw: Any) -> Dict[str, Any]:
    out = dict(DEFAULTS["cache"])
    if not isinstance(raw, dict):
        return out
    days = _parse_days(raw.get("ttl_days"))
    if days is not None:
        out["ttl_days"] = days
    if "gui" in raw:
        out["gui"] = bool(raw["gui"])
    return out


def _merge_refresh(raw: Any) -> Dict[str, Any]:
    out = dict(DEFAULT_REFRESH)
    if not isinstance(raw, dict):
        return out
    for key in DEFAULT_REFRESH:
        if key not in raw:
            continue
        parsed = _parse_days(raw[key])
        if parsed is not None:
            out[key] = parsed
    return out


def _merge_history(raw: Any) -> Dict[str, Any]:
    out = dict(DEFAULTS["history"])
    if not isinstance(raw, dict):
        return out
    parsed = _parse_snapshots(raw.get("snapshots"))
    if parsed is not None:
        out["snapshots"] = parsed
    return out


def _merge_wall(raw: Any) -> Dict[str, Any]:
    out = dict(DEFAULTS["wall"])
    if not isinstance(raw, dict):
        return out
    days = _parse_days(raw.get("challenge_ttl_days"))
    if days is not None and days >= 1:
        out["challenge_ttl_days"] = days
    bits = _parse_days(raw.get("challenge_bits"))
    if bits is not None and 8 <= bits <= 24:
        out["challenge_bits"] = bits
    return out


def _clamp_mtr_stored(raw: Any, default: int) -> int:
    parsed = _parse_days(raw)
    if parsed is None:
        return default
    if parsed < 1:
        return 1
    if parsed > MTR_HARD_CEILING:
        return MTR_HARD_CEILING
    return parsed


def _merge_mtr(raw: Any) -> Dict[str, Any]:
    out = dict(DEFAULTS["mtr"])
    if not isinstance(raw, dict):
        return out
    if "cycles" in raw:
        out["cycles"] = _clamp_mtr_stored(raw.get("cycles"), out["cycles"])
    if "max_cycles" in raw:
        out["max_cycles"] = _clamp_mtr_stored(raw.get("max_cycles"), out["max_cycles"])
    return out


def _parse_port(value: Any) -> Optional[int]:
    parsed = _parse_days(value if not isinstance(value, str) else value.strip())
    if parsed is None or parsed < 1 or parsed > 65535:
        return None
    return parsed


def _normalize_hostname(value: Any) -> str:
    text = str(value or "").strip().rstrip(".").lower()
    if any(ch.isspace() or ch in "/\\" for ch in text):
        raise ValueError("http.hostname must be a DNS name")
    return text


def _normalize_email(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "@" not in text or "." not in text.rsplit("@", 1)[-1]:
        raise ValueError("http.email must be an email address")
    return text


def _clamp_workers(raw: Any, default: int) -> int:
    parsed = _parse_days(raw if not isinstance(raw, str) else raw.strip())
    if parsed is None:
        return default
    if parsed < 1:
        return 1
    if parsed > HTTP_WORKERS_MAX:
        return HTTP_WORKERS_MAX
    return parsed


def _merge_http(raw: Any) -> Dict[str, Any]:
    out = dict(DEFAULTS["http"])
    out["controller_origins"] = list(out.get("controller_origins") or [])
    if not isinstance(raw, dict):
        return out
    if "enabled" in raw:
        try:
            out["enabled"] = _parse_bool(raw.get("enabled"), "http.enabled")
        except ValueError:
            pass
    if "staging" in raw:
        try:
            out["staging"] = _parse_bool(raw.get("staging"), "http.staging")
        except ValueError:
            pass
    if "hostname" in raw:
        try:
            out["hostname"] = _normalize_hostname(raw.get("hostname"))
        except ValueError:
            pass
    if "email" in raw:
        try:
            out["email"] = _normalize_email(raw.get("email"))
        except ValueError:
            pass
    port = _parse_port(raw.get("port")) if "port" in raw else None
    if port is not None:
        out["port"] = port
    acme_port = _parse_port(raw.get("acme_port")) if "acme_port" in raw else None
    if acme_port is not None:
        out["acme_port"] = acme_port
    if "workers" in raw:
        out["workers"] = _clamp_workers(raw.get("workers"), out["workers"])
    if "bind" in raw:
        bind = str(raw.get("bind") or "").strip() or out["bind"]
        out["bind"] = bind
    if "controller_origins" in raw:
        from .http.security import parse_controller_origins

        out["controller_origins"] = parse_controller_origins(raw.get("controller_origins"))
    return out


def _parse_bool(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    low = str(value).strip().lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    raise ValueError(f"{key} must be true or false")


def _merge_docs(raw: Any) -> Dict[str, Any]:
    out = dict(DEFAULTS["docs"])
    if not isinstance(raw, dict):
        return out
    if "enabled" in raw:
        try:
            out["enabled"] = _parse_bool(raw.get("enabled"), "docs.enabled")
        except ValueError:
            pass
    return out


def normalize(payload: Any) -> Dict[str, Any]:
    data = payload if isinstance(payload, dict) else {}
    return {
        "locale": _normalize_locale(data.get("locale") or DEFAULTS["locale"]),
        "cache": _merge_cache(data.get("cache")),
        "refresh": _merge_refresh(data.get("refresh")),
        "history": _merge_history(data.get("history")),
        "wall": _merge_wall(data.get("wall")),
        "docs": _merge_docs(data.get("docs")),
        "mtr": _merge_mtr(data.get("mtr")),
        "http": _merge_http(data.get("http")),
    }


def _migrate() -> Dict[str, Any]:
    merged = deepcopy(DEFAULTS)
    locale = _read_legacy_locale()
    if locale:
        merged["locale"] = locale
    cache = _read_legacy_cache()
    merged["cache"].update(cache)
    refresh = _read_legacy_refresh()
    merged["refresh"].update(refresh)
    return merged


def save(payload: Dict[str, Any]) -> str:
    dest = path()
    cleaned = normalize(payload)
    atomic_write(dest, json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n")
    return dest


def load() -> Dict[str, Any]:
    dest = Path(path())
    if not dest.is_file():
        merged = _migrate()
        try:
            save(merged)
        except OSError:
            pass
        return normalize(merged)
    data = _read_json(dest)
    if not isinstance(data, dict):
        return deepcopy(DEFAULTS)
    return normalize(data)


def _walk(payload: Dict[str, Any], dotted: str) -> Tuple[Any, str]:
    key = (dotted or "").strip()
    if not key:
        raise KeyError("empty key")
    parts = key.split(".")
    cur: Any = payload
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            raise KeyError(key)
        cur = cur[part]
    return cur, key


def get(dotted: str) -> Any:
    value, _key = _walk(load(), dotted)
    return value


def _parse_set_value(dotted: str, raw: Any) -> Any:
    key = (dotted or "").strip()
    if key == "locale":
        return _normalize_locale(raw)
    if key == "cache.gui" or key == "docs.enabled":
        return _parse_bool(raw, key)
    if key in {"http.enabled", "http.staging"}:
        return _parse_bool(raw, key)
    if key == "http.hostname":
        return _normalize_hostname(raw)
    if key == "http.email":
        return _normalize_email(raw)
    if key in {"http.port", "http.acme_port"}:
        port = _parse_port(raw if not isinstance(raw, str) else raw.strip())
        if port is None:
            raise ValueError(f"{key} must be an integer 1–65535")
        return port
    if key == "http.workers":
        parsed = _parse_days(raw if not isinstance(raw, str) else raw.strip())
        if parsed is None:
            raise ValueError("http.workers must be an integer")
        return _clamp_workers(parsed, 1)
    if key == "http.bind":
        bind = str(raw or "").strip()
        if not bind:
            raise ValueError("http.bind must be a bind address")
        return bind
    if key == "http.controller_origins":
        from .http.security import parse_controller_origins

        return parse_controller_origins(raw, strict=True)
    if key == "cache.ttl_days" or key.startswith("refresh."):
        days = _parse_days(raw if not isinstance(raw, str) else raw.strip())
        if days is None:
            raise ValueError(f"{key} must be a non-negative integer")
        if key.startswith("refresh."):
            name = key.split(".", 1)[1]
            if name not in DEFAULT_REFRESH:
                raise KeyError(key)
        return days
    if key == "history.snapshots":
        parsed = _parse_snapshots(raw if not isinstance(raw, str) else raw.strip())
        if parsed is None:
            raise ValueError("history.snapshots must be an integer >= -1")
        return parsed
    if key == "wall.challenge_ttl_days":
        days = _parse_days(raw if not isinstance(raw, str) else raw.strip())
        if days is None or days < 1:
            raise ValueError("wall.challenge_ttl_days must be an integer >= 1")
        return days
    if key == "wall.challenge_bits":
        bits = _parse_days(raw if not isinstance(raw, str) else raw.strip())
        if bits is None or bits < 8 or bits > 24:
            raise ValueError("wall.challenge_bits must be an integer 8-24")
        return bits
    if key in {"mtr.cycles", "mtr.max_cycles"}:
        parsed = _parse_days(raw if not isinstance(raw, str) else raw.strip())
        if parsed is None:
            raise ValueError(f"{key} must be an integer")
        if parsed < 1:
            return 1
        if parsed > MTR_HARD_CEILING:
            return MTR_HARD_CEILING
        return parsed
    raise KeyError(key)


def _assign(cfg: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur: Dict[str, Any] = cfg
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def apply_values(updates: Dict[str, Any]) -> Dict[str, Any]:
    parsed: List[Tuple[str, Any]] = []
    for raw_key, raw in (updates or {}).items():
        key = str(raw_key or "").strip()
        parsed.append((key, _parse_set_value(key, raw)))
    with file_lock():
        cfg = load()
        for key, value in parsed:
            _assign(cfg, key, value)
        save(cfg)
        return load()


def set_value(dotted: str, raw: Any) -> Dict[str, Any]:
    return apply_values({dotted: raw})


def docs_enabled() -> bool:
    try:
        return bool(get("docs.enabled"))
    except Exception:
        return False


def docs_generated() -> bool:
    try:
        from .docs.generate import default_docs_path

        return os.path.isfile(default_docs_path())
    except Exception:
        return False


def refresh_policy() -> Dict[str, Any]:
    dest = path()
    file_path = Path(dest)
    if not file_path.is_file():
        cfg = load()
        source = "generated"
        error = None
    else:
        data = _read_json(file_path)
        if not isinstance(data, dict):
            cfg = deepcopy(DEFAULTS)
            source = "invalid"
            error = "file must be a JSON object"
        else:
            cfg = normalize(data)
            source = "file"
            error = None
            raw_refresh = data.get("refresh") if isinstance(data.get("refresh"), dict) else {}
            days: Dict[str, Optional[int]] = {}
            invalid: List[str] = []
            for key in DEFAULT_REFRESH:
                if key not in raw_refresh:
                    days[key] = DEFAULT_REFRESH[key]
                    continue
                parsed = _parse_days(raw_refresh[key])
                if parsed is None:
                    days[key] = None
                    invalid.append(key)
                else:
                    days[key] = parsed
            return {
                "path": dest,
                "source": source,
                "days": days,
                "invalid_keys": invalid,
                "error": error,
            }
    return {
        "path": dest,
        "source": source,
        "days": dict(cfg["refresh"]),
        "invalid_keys": [],
        "error": error,
    }


def known_keys() -> List[str]:
    keys = [
        "locale",
        "cache.ttl_days",
        "cache.gui",
        "history.snapshots",
        "wall.challenge_ttl_days",
        "wall.challenge_bits",
        "docs.enabled",
        "mtr.cycles",
        "mtr.max_cycles",
        "http.enabled",
        "http.hostname",
        "http.email",
        "http.port",
        "http.acme_port",
        "http.workers",
        "http.bind",
        "http.staging",
    ]
    keys.extend(f"refresh.{name}" for name in DEFAULT_REFRESH)
    return keys

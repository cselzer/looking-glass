"""Claude / OpenAI / Grok: config, API keys, model list, JSON chat."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from looking_glass.utility import atomic_write, get_root

PROVIDERS = ("claude", "openai", "grok")

BAKED_MODELS = {
    "claude": "claude-sonnet-5",
    "openai": "gpt-5.6-sol",
    "grok": "grok-4.6",
}

ENV_KEYS = {
    "claude": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "grok": "XAI_API_KEY",
}

LIST_URLS = {
    "claude": "https://api.anthropic.com/v1/models",
    "openai": "https://api.openai.com/v1/models",
    "grok": "https://api.x.ai/v1/models",
}

CHAT_URLS = {
    "claude": "https://api.anthropic.com/v1/messages",
    "openai": "https://api.openai.com/v1/chat/completions",
    "grok": "https://api.x.ai/v1/chat/completions",
}

ANTHROPIC_VERSION = "2023-06-01"
CONNECT_TIMEOUT = 10.0
DEFAULT_READ_TIMEOUT = 3600.0
_OPENAI_SKIP = (
    "embedding",
    "whisper",
    "tts",
    "dall-e",
    "dall_e",
    "davinci",
    "babbage",
    "ada",
    "audio",
    "realtime",
    "transcribe",
    "moderation",
    "sora",
    "image",
    "computer-use",
)


class LocaleCliError(Exception):
    exit_code = 2


class MissingKeyError(LocaleCliError):
    exit_code = 2


class UnknownModelError(LocaleCliError):
    exit_code = 2


class ProviderError(LocaleCliError):
    exit_code = 3


def config_path() -> Path:
    return Path(get_root()) / "locale.json"


def default_config() -> Dict[str, Any]:
    return {
        "providers": {
            name: {"model": BAKED_MODELS[name], "api_key": None} for name in PROVIDERS
        }
    }


def load_config() -> Dict[str, Any]:
    path = config_path()
    base = default_config()
    if not path.is_file():
        return base
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return base
    if not isinstance(data, dict):
        return base
    providers = data.get("providers")
    if not isinstance(providers, dict):
        return base
    merged = default_config()
    for name in PROVIDERS:
        row = providers.get(name)
        if not isinstance(row, dict):
            continue
        dest = merged["providers"][name]
        if row.get("model"):
            dest["model"] = str(row["model"])
        if "api_key" in row:
            dest["api_key"] = row.get("api_key")
    return merged


def save_config(cfg: Dict[str, Any]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(str(path), json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    os.chmod(path, 0o600)
    return path


def require_provider(name: str) -> str:
    key = str(name or "").strip().lower()
    if key not in PROVIDERS:
        raise LocaleCliError(f"unknown provider {name!r}; use claude, openai, or grok")
    return key


def configured_model(provider: str) -> str:
    provider = require_provider(provider)
    cfg = load_config()
    row = (cfg.get("providers") or {}).get(provider) or {}
    return str(row.get("model") or BAKED_MODELS[provider])


def resolve_model(provider: str, override: Optional[str] = None) -> str:
    if override and str(override).strip():
        return str(override).strip()
    return configured_model(provider)


def key_source(provider: str) -> str:
    provider = require_provider(provider)
    env = (os.environ.get(ENV_KEYS[provider]) or "").strip()
    if env:
        return "env"
    cfg = load_config()
    row = (cfg.get("providers") or {}).get(provider) or {}
    if str(row.get("api_key") or "").strip():
        return "file"
    return "missing"


def resolve_api_key(provider: str) -> Optional[str]:
    provider = require_provider(provider)
    env = (os.environ.get(ENV_KEYS[provider]) or "").strip()
    if env:
        return env
    cfg = load_config()
    row = (cfg.get("providers") or {}).get(provider) or {}
    file_key = str(row.get("api_key") or "").strip()
    return file_key or None


def require_api_key(provider: str) -> str:
    key = resolve_api_key(provider)
    if not key:
        raise MissingKeyError(
            f"missing API key for {provider}; set {ENV_KEYS[provider]} or "
            f"python tools/locale.py configure --provider {provider} --api-key KEY"
        )
    return key


def _chat_timeout(read: float) -> Tuple[float, float]:
    return (CONNECT_TIMEOUT, max(1.0, float(read)))


def _sse_line(raw: object) -> str:
    if isinstance(raw, bytes):
        return raw.decode("utf-8")
    return str(raw)


def _openai_sse_text(res: requests.Response) -> str:
    parts: List[str] = []
    for raw in res.iter_lines(decode_unicode=False):
        line = _sse_line(raw).strip()
        if not line:
            continue
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue
        if not isinstance(chunk, dict):
            continue
        choices = chunk.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            continue
        delta = choices[0].get("delta") or {}
        if not isinstance(delta, dict):
            continue
        piece = delta.get("content")
        if isinstance(piece, str) and piece:
            parts.append(piece)
    text = "".join(parts)
    if not text:
        raise ProviderError("provider stream had no content")
    return text


def _auth_headers(provider: str, api_key: str) -> Dict[str, str]:
    if provider == "claude":
        return {
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
    return {"Authorization": f"Bearer {api_key}", "content-type": "application/json"}


def _openai_keep(item: Dict[str, Any]) -> bool:
    mid = str(item.get("id") or "").lower()
    if not mid:
        return False
    return not any(token in mid for token in _OPENAI_SKIP)


def _row_from_api(item: Dict[str, Any]) -> Dict[str, Any]:
    row: Dict[str, Any] = {"id": item.get("id")}
    for key in ("created", "created_at", "owned_by", "display_name", "type"):
        if key in item and item[key] is not None:
            row[key] = item[key]
    return row


def list_models(provider: str, *, timeout: float = 30.0) -> List[Dict[str, Any]]:
    provider = require_provider(provider)
    api_key = require_api_key(provider)
    url = LIST_URLS[provider]
    try:
        res = requests.get(url, headers=_auth_headers(provider, api_key), timeout=timeout)
        res.raise_for_status()
        data = res.json()
    except requests.RequestException as exc:
        raise ProviderError(str(exc) or exc.__class__.__name__) from exc
    except (ValueError, TypeError) as exc:
        raise ProviderError("models list was not JSON") from exc
    items = data.get("data") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ProviderError("models list had no data array")
    rows = []
    current = configured_model(provider)
    for raw in items:
        if not isinstance(raw, dict):
            continue
        if provider == "openai" and not _openai_keep(raw):
            continue
        row = _row_from_api(raw)
        if not row.get("id"):
            continue
        if row["id"] == current:
            row["mark"] = "*"
        rows.append(row)
    return rows


def model_ids(rows: List[Dict[str, Any]]) -> List[str]:
    return [str(row["id"]) for row in rows if row.get("id")]


def parse_json_object(text: str) -> Dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:]
        raw = raw.strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end < 0 or end < start:
        raise ProviderError("provider did not return a JSON object")
    try:
        data = json.loads(raw[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ProviderError("provider JSON was invalid") from exc
    if not isinstance(data, dict):
        raise ProviderError("provider JSON was not an object")
    if isinstance(data.get("messages"), dict) and all(
        isinstance(v, str) for v in data["messages"].values()
    ):
        return dict(data["messages"])
    return data


def complete_json(
    provider: str,
    model: str,
    system: str,
    user: Dict[str, Any],
    *,
    timeout: float = DEFAULT_READ_TIMEOUT,
    api_key: Optional[str] = None,
    lang: Optional[str] = None,
    reasoning_effort: str = "high",
) -> Dict[str, str]:
    provider = require_provider(provider)
    key = api_key or require_api_key(provider)
    url = CHAT_URLS[provider]
    payload = json.dumps(user, ensure_ascii=False)
    use_stream = provider in ("openai", "grok")
    effort = (reasoning_effort or "high").strip().lower()
    if effort not in ("low", "high"):
        raise LocaleCliError(f"reasoning_effort must be low or high, not {reasoning_effort!r}")
    if provider == "claude":
        body: Dict[str, Any] = {
            "model": model,
            "max_tokens": 16384,
            "system": system,
            "messages": [{"role": "user", "content": payload}],
        }
    else:
        body = {
            "model": model,
            "max_tokens": 16384,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": payload},
            ],
        }
        if use_stream:
            body["stream"] = True
        if provider == "grok":
            body["reasoning_effort"] = effort
    headers = _auth_headers(provider, key)
    if provider == "grok":
        tag = (lang or "en").strip().lower() or "en"
        headers["x-grok-conv-id"] = f"looking-glass-locale-{tag}"
    req_timeout = _chat_timeout(timeout)
    res: Optional[requests.Response] = None
    try:
        res = requests.post(
            url,
            headers=headers,
            json=body,
            timeout=req_timeout,
            stream=use_stream,
        )
        res.raise_for_status()
        if use_stream:
            text = _openai_sse_text(res)
        else:
            data = res.json()
            text = _content_text(provider, data)
    except requests.ReadTimeout as exc:
        raise ProviderError(
            f"{provider} was still thinking after {req_timeout[1]:.0f}s read timeout; "
            f"the API did not drop the connection — raise --timeout if needed"
        ) from exc
    except requests.RequestException as exc:
        raise ProviderError(str(exc) or exc.__class__.__name__) from exc
    except (ValueError, TypeError) as exc:
        raise ProviderError("provider response was not JSON") from exc
    finally:
        if res is not None:
            res.close()
    parsed = parse_json_object(text)
    out: Dict[str, str] = {}
    for key_name, value in parsed.items():
        if isinstance(value, str):
            out[str(key_name)] = value
        elif isinstance(value, dict) and isinstance(value.get("text"), str):
            out[str(key_name)] = value["text"]
    return out


def _content_text(provider: str, data: Dict[str, Any]) -> str:
    if provider == "claude":
        parts = data.get("content") or []
        return "".join(
            str(part.get("text") or "")
            for part in parts
            if isinstance(part, dict)
        )
    try:
        return str(data["choices"][0]["message"]["content"] or "")
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError("provider chat response had no content") from exc


def show_provider(provider: str) -> Dict[str, Any]:
    provider = require_provider(provider)
    return {
        "ok": True,
        "provider": provider,
        "model": configured_model(provider),
        "key_source": key_source(provider),
    }


def set_provider(
    provider: str,
    *,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    force_model: bool = False,
) -> Dict[str, Any]:
    provider = require_provider(provider)
    cfg = load_config()
    row = cfg["providers"][provider]
    if model:
        mid = str(model).strip()
        if not force_model:
            ids = model_ids(list_models(provider))
            if mid not in ids:
                raise UnknownModelError(
                    f"unknown model {mid!r} for {provider}; run python tools/locale.py models "
                    f"--provider {provider} or pass --force-model"
                )
        row["model"] = mid
    if api_key is not None:
        text = str(api_key).strip()
        row["api_key"] = text or None
    save_config(cfg)
    out = show_provider(provider)
    out["path"] = str(config_path())
    return out


def provider_status(*, timeout: float = 8.0) -> List[Dict[str, Any]]:
    rows = []
    for name in PROVIDERS:
        reachable = False
        error = None
        if key_source(name) != "missing":
            try:
                list_models(name, timeout=timeout)
                reachable = True
            except LocaleCliError as exc:
                error = str(exc)
        rows.append(
            {
                "provider": name,
                "key": "yes" if key_source(name) != "missing" else "no",
                "key_source": key_source(name),
                "model": configured_model(name),
                "reachable": reachable,
                "error": error,
            }
        )
    return rows

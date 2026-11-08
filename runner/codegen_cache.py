"""Cache validated codegen artifacts by repo commit + brief hash."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def cache_enabled() -> bool:
    return (os.environ.get("CODEGEN_CACHE") or "1").lower() not in {"0", "false", "off"}


def cache_dir() -> Path:
    root = Path(os.environ.get("TOOLPAIN_DATA_DIR") or Path(__file__).resolve().parents[1] / "data")
    path = root / "codegen_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def make_key(*, repo_url: str, commit: str, brief: str | None, kind: str) -> str:
    blob = f"{repo_url}|{commit}|{brief or ''}|{kind}|v4"
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def load_cached(key: str) -> dict[str, Any] | None:
    if not cache_enabled():
        return None
    path = cache_dir() / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def store_cached(key: str, payload: dict[str, Any]) -> None:
    if not cache_enabled():
        return
    path = cache_dir() / f"{key}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

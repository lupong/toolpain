"""Signed, expiring read-only report links (HMAC)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time


def _secret() -> bytes:
    return (os.environ.get("TOOLPAIN_SHARE_SECRET") or "toolpain-dev-share-secret").encode()


def sign_share(scan_id: str, *, ttl_sec: int = 86_400) -> tuple[str, int]:
    exp = int(time.time()) + max(60, ttl_sec)
    payload = f"{scan_id}.{exp}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    token = base64.urlsafe_b64encode(f"{payload}.{sig}".encode()).decode().rstrip("=")
    return token, exp


def share_expiry(token: str) -> int | None:
    """Unix expiry of a valid token, or None when the token is bad or expired."""
    if verify_share(token) is None:
        return None
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad).decode()
        _scan_id, exp_s, _sig = raw.rsplit(".", 2)
        return int(exp_s)
    except (ValueError, UnicodeDecodeError):
        return None


def verify_share(token: str) -> str | None:
    """Return scan_id if the token is valid and unexpired."""
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad).decode()
        scan_id, exp_s, sig = raw.rsplit(".", 2)
        exp = int(exp_s)
    except (ValueError, UnicodeDecodeError):
        return None
    if exp < int(time.time()):
        return None
    payload = f"{scan_id}.{exp}"
    expect = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(expect, sig):
        return None
    return scan_id


def compare_reports(a: dict, b: dict) -> dict:
    """Tool and finding delta between two report dicts."""
    tools_a = {t.get("name") for t in (a.get("tools") or []) if t.get("name")}
    tools_b = {t.get("name") for t in (b.get("tools") or []) if t.get("name")}
    types_a = {f.get("type") for f in (a.get("findings") or [])}
    types_b = {f.get("type") for f in (b.get("findings") or [])}
    return {
        "a": {"scan_id": a.get("scan_id"), "verdict": a.get("verdict")},
        "b": {"scan_id": b.get("scan_id"), "verdict": b.get("verdict")},
        "tools_added": sorted(tools_b - tools_a),
        "tools_removed": sorted(tools_a - tools_b),
        "finding_types_added": sorted(t for t in (types_b - types_a) if t),
        "finding_types_removed": sorted(t for t in (types_a - types_b) if t),
        "verdict_changed": a.get("verdict") != b.get("verdict"),
        "findings_added": sorted(t for t in (types_b - types_a) if t),
        "findings_removed": sorted(t for t in (types_a - types_b) if t),
        "verdict": {"a": a.get("verdict"), "b": b.get("verdict")},
    }

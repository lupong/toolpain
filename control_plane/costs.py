"""Rate-card estimate before a scan, and the priced actual after it.

Amounts are USD from ``rate_card.json``. They are not a cloud invoice.
GitHub is not called unless ``TOOLPAIN_ESTIMATE_NETWORK=1``. The three demos
use pinned sizes so tests and the intake form stay offline.
"""

from __future__ import annotations

import json
import os
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path
from typing import Any

import httpx

from control_plane.models import GITHUB_URL_RE

_CARD_PATH = Path(__file__).with_name("rate_card.json")

# size is GitHub's kilobyte field. Bands: <1 MB small, <20 MB medium, else large.
FIXTURES: dict[str, dict[str, Any]] = {
    "https://github.com/modelcontextprotocol/servers": {
        "size_kb": 800,
        "language": "TypeScript",
    },
    "https://github.com/microsoft/playwright-mcp": {
        "size_kb": 24000,
        "language": "TypeScript",
    },
    "https://github.com/andrew/playwright-mcp": {"size_kb": 24000, "language": "TypeScript"},
    "https://github.com/lupong/toolpain": {"size_kb": 500, "language": "Python"},
}


def load_rate_card() -> dict[str, Any]:
    return json.loads(_CARD_PATH.read_text(encoding="utf-8"))


def usd(value: Decimal | float | int | str) -> float:
    quantized = Decimal(str(value)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    return float(quantized)


def assumptions_for_size(size_kb: int) -> dict[str, Any]:
    mb = size_kb / 1024
    if mb < 1:
        band, tools, minutes = "small", 5, 3
    elif mb < 20:
        band, tools, minutes = "medium", 15, 8
    else:
        band, tools, minutes = "large", 40, 15
    return {
        "band": band,
        "tools": tools,
        "scanner_minutes": minutes,
        "codegen_calls": 4,
        "size_mb": usd(mb),
    }


def price_lines(
    *,
    card: dict[str, Any],
    provisioner: str,
    scanner_minutes: float,
    codegen_calls: int,
    research_calls: int,
    size_mb: float,
) -> list[dict[str, Any]]:
    rate_key = "vultr_usd_per_min" if provisioner == "vultr" else "local_usd_per_min"
    rows = [
        ("codegen", codegen_calls, Decimal(str(card["codegen_call_usd"]))),
        ("research", research_calls, Decimal(str(card["research_call_usd"]))),
        ("infra", scanner_minutes, Decimal(str(card[rate_key]))),
        ("fetch", size_mb, Decimal(str(card["fetch_usd_per_mb"]))),
    ]
    lines = []
    for code, quantity, rate in rows:
        lines.append(
            {"code": code, "quantity": quantity, "usd": usd(Decimal(str(quantity)) * rate)}
        )
    return lines


def estimate_cost(
    *,
    size_kb: int,
    language: str,
    provisioner: str,
    card: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Price a scan from repo size. Does not clone and does not call GitHub."""
    card = card or load_rate_card()
    assumed = assumptions_for_size(size_kb)
    prov = "vultr" if provisioner == "vultr" else "local"
    lines = price_lines(
        card=card,
        provisioner=prov,
        scanner_minutes=float(assumed["scanner_minutes"]),
        codegen_calls=int(assumed["codegen_calls"]),
        research_calls=int(assumed["tools"]),
        size_mb=float(assumed["size_mb"]),
    )
    return {
        "available": True,
        "rate_card": card["version"],
        "inputs": {
            "size_kb": size_kb,
            "language": language,
            "provisioner": prov,
        },
        "assumptions": assumed,
        "lines": lines,
        "total_usd": usd(sum(Decimal(str(line["usd"])) for line in lines)),
    }


def repo_metadata(repo_url: str) -> dict[str, Any] | None:
    """Pinned demo sizes, else GitHub metadata when the network flag is on."""
    url = repo_url.strip().rstrip("/")
    pinned = FIXTURES.get(url)
    if pinned:
        return dict(pinned)
    if os.environ.get("TOOLPAIN_ESTIMATE_NETWORK") != "1":
        return None
    match = GITHUB_URL_RE.match(url)
    if not match:
        return None
    api = f"https://api.github.com/repos/{match.group('owner')}/{match.group('repo')}"
    try:
        response = httpx.get(
            api,
            timeout=2.0,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "toolpain"},
        )
        if response.status_code != 200:
            return None
        body = response.json()
        return {
            "size_kb": int(body.get("size") or 0),
            "language": str(body.get("language") or "unknown"),
        }
    except (httpx.HTTPError, ValueError, TypeError):
        return None


def build_estimate(repo_url: str, provisioner: str) -> dict[str, Any]:
    meta = repo_metadata(repo_url)
    if not meta:
        return {"available": False, "detail": "Estimate unavailable"}
    return estimate_cost(
        size_kb=int(meta["size_kb"]),
        language=str(meta.get("language") or "unknown"),
        provisioner=provisioner,
    )


def price_actual(
    *,
    card: dict[str, Any],
    provisioner: str,
    duration_sec: float,
    repo_bytes: int,
    codegen_calls: int,
    research_calls: int,
    probe_rounds: int,
    runtime: str | None,
    estimate: dict[str, Any] | None,
) -> dict[str, Any]:
    minutes = max(0.0, duration_sec) / 60
    size_mb = max(0, repo_bytes) / (1024 * 1024)
    prov = "vultr" if provisioner == "vultr" else "local"
    lines = price_lines(
        card=card,
        provisioner=prov,
        scanner_minutes=minutes,
        codegen_calls=codegen_calls,
        research_calls=research_calls,
        size_mb=size_mb,
    )
    actual_total = usd(sum(Decimal(str(line["usd"])) for line in lines))
    estimate_total = None
    if estimate and estimate.get("available") and estimate.get("total_usd") is not None:
        estimate_total = usd(estimate["total_usd"])
    delta = (
        None
        if estimate_total is None
        else usd(Decimal(str(actual_total)) - Decimal(str(estimate_total)))
    )
    delta_pct = None
    if delta is not None and estimate_total:
        delta_pct = usd(Decimal(str(delta)) / Decimal(str(estimate_total)) * Decimal(100))
    return {
        "rate_card": card["version"],
        "estimate": estimate if estimate and estimate.get("available") else None,
        "actual": {
            "total_usd": actual_total,
            "lines": lines,
            "meters": {
                "duration_sec": round(duration_sec, 3),
                "repo_bytes": repo_bytes,
                "codegen_calls": codegen_calls,
                "research_calls": research_calls,
                "probe_rounds": probe_rounds,
                "provisioner": prov,
                "runtime": runtime,
            },
        },
        "delta_usd": delta,
        "delta_pct": delta_pct,
    }

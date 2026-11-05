"""`toolpain scan` talks to a running control plane and prints the report."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def scan_payload(
    repo: str,
    ref: str,
    protocol: str,
    brief: str | None,
    prefer_subdir: str | None,
    mcp_url: str | None,
    upstream_url: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"repo_url": repo, "ref": ref, "protocol": protocol}
    if brief:
        body["scan_brief"] = brief
    if prefer_subdir:
        body["prefer_subdir"] = prefer_subdir
    if mcp_url:
        body["mcp_url"] = mcp_url
    if upstream_url:
        body["upstream_url"] = upstream_url
    return body


def _request(
    method: str,
    url: str,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> Any:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Api-Token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode()
    return json.loads(raw) if raw else {}


def scan_main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="toolpain scan")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--ref", default="main")
    parser.add_argument("--brief", default=None)
    parser.add_argument("--protocol", default="auto", choices=["auto", "stdio", "http", "sse"])
    parser.add_argument("--prefer-subdir", default=None)
    parser.add_argument("--mcp-url", default=None)
    parser.add_argument("--upstream-url", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-token", default=None)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--share", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)

    base = (args.base_url or os.environ.get("CONTROL_PLANE_URL") or "http://127.0.0.1:8000").rstrip("/")
    token = args.api_token or os.environ.get("TOOLPAIN_API_TOKEN")
    payload = scan_payload(
        args.repo,
        args.ref,
        args.protocol,
        args.brief,
        args.prefer_subdir,
        args.mcp_url,
        args.upstream_url,
    )
    try:
        created = _request("POST", f"{base}/api/scans", payload, token)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        print(f"scan create failed: {exc.code} {detail}", file=sys.stderr)
        raise SystemExit(1) from exc

    scan_id = str(created["id"])
    deadline = time.time() + args.timeout
    status = str(created.get("status") or "queued")
    while status not in {"done", "failed", "cancelled", "timeout"}:
        if time.time() > deadline:
            print(f"scan {scan_id} still {status}", file=sys.stderr)
            raise SystemExit(2)
        time.sleep(1)
        current = _request("GET", f"{base}/api/scans/{scan_id}", token=token)
        status = str(current.get("status") or status)

    if status != "done":
        print(f"scan {scan_id} {status}", file=sys.stderr)
        raise SystemExit(2)

    report = _request("GET", f"{base}/api/scans/{scan_id}/report", token=token)
    if args.as_json:
        print(json.dumps(report, indent=2))
    else:
        print(json.dumps({"id": scan_id, "verdict": report.get("verdict")}, indent=2))

    if args.share:
        shared = _request("POST", f"{base}/api/scans/{scan_id}/share", token=token)
        print(base + str(shared.get("url") or ""))

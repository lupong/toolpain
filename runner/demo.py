"""make demo — run decoy-trap-server scan and print verdict."""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

from runner.main import run_scan

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    scan_id = f"s_{uuid.uuid4().hex[:8]}"
    report = run_scan(
        scan_id=scan_id,
        repo_url="https://github.com/lupong/toolpain",
        ref="main",
        local_path=ROOT / "demo" / "decoy-trap-server",
        sandbox="fake",
    )
    out = ROOT / "data" / "reports" / f"{scan_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"Wrote {out}")
    print(f"verdict={report['verdict']} decoy_reads={report['stats']['decoy_reads']}")
    assert report["verdict"] == "flagged"
    assert report["stats"]["decoy_reads"] >= 1
    assert any(f.get("type") == "decoy_read_and_egress" for f in report["findings"])


if __name__ == "__main__":
    main()

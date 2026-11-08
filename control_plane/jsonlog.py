"""One JSON object per log line, with the scan id when the line belongs to a scan."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from control_plane.redaction import redact_text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "level": record.levelname.lower(),
            "msg": redact_text(record.getMessage()),
            "scan_id": str(getattr(record, "scan_id", "") or ""),
            "stage": str(getattr(record, "stage", "") or ""),
            "error_code": str(getattr(record, "error_code", "") or ""),
        }
        return json.dumps(payload, default=str)


def install_json_logs() -> None:
    logger = logging.getLogger("toolpain")
    logger.setLevel(logging.INFO)
    if any(isinstance(getattr(handler, "formatter", None), JsonFormatter) for handler in logger.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False

"""Log redaction for Vultr API key patterns and BYO secrets."""

from __future__ import annotations

import logging
import re

# Vultr personal access tokens are typically long hex-ish / alphanumeric strings.
# Also redact common env-style keys.
KEY_PATTERNS = [
    re.compile(r"(?i)(vultr[_\-]?api[_\-]?key\s*[=:]\s*)([A-Za-z0-9_\-]{16,})"),
    re.compile(r"(?i)(authorization:\s*bearer\s+)([A-Za-z0-9_\-\.]{16,})"),
    re.compile(r"\b([A-Fa-f0-9]{40,64})\b"),  # long hex tokens
]


def redact_text(text: str) -> str:
    out = text
    for pat in KEY_PATTERNS:
        out = pat.sub(
            lambda m: (
                (m.group(1) + "***REDACTED***")
                if m.lastindex and m.lastindex >= 2
                else "***REDACTED***"
            ),
            out,
        )
    return out


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_text(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_text(a) if isinstance(a, str) else a for a in record.args
                )
        return True


def install_redaction(logger: logging.Logger | None = None) -> None:
    target = logger or logging.getLogger()
    filt = RedactingFilter()
    target.addFilter(filt)
    for handler in logging.root.handlers:
        handler.addFilter(filt)

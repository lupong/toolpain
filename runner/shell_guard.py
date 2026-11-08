"""Validate LLM-generated launch shell scripts before they run in the sandbox image."""

from __future__ import annotations

import re

from runner.safe_argv import TOKEN_RE

FORBIDDEN_SUBSTR = (
    "$(",
    "`",
    "|",
    ";",
    "&&",
    "||",
    ">",
    "<",
    "curl",
    "wget",
    "nc ",
    "ncat",
    "bash -c",
    "python -c",
    "perl -e",
    "ruby -e",
    "/dev/tcp",
    "base64",
    "chmod",
    "chown",
    "sudo",
)


class ShellGuardError(ValueError):
    pass


_EXEC_RE = re.compile(
    r"^(?:exec\s+)?((?:/app/)?[A-Za-z0-9_./+-]+)((?:\s+[A-Za-z0-9_./+=:@%-]+)*)\s*$"
)


def validate_launch_script(source: str) -> str:
    text = source.replace("\r\n", "\n").strip() + "\n"
    if len(text) > 4_000:
        raise ShellGuardError("launch script too large")
    lower = text.lower()
    for bad in FORBIDDEN_SUBSTR:
        if bad in lower:
            raise ShellGuardError(f"launch script contains forbidden pattern: {bad!r}")

    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines or len(lines) > 8:
        raise ShellGuardError("launch script must have 1–8 non-comment lines")

    for ln in lines:
        m = _EXEC_RE.match(ln.strip())
        if not m:
            raise ShellGuardError(f"launch line not allowlisted: {ln!r}")
        cmd = m.group(1)
        rest = (m.group(2) or "").split()
        for tok in [cmd, *rest]:
            if not TOKEN_RE.match(tok) and not tok.startswith("/app/"):
                # allow /app/ paths with TOKEN_RE-ish chars
                if not re.match(r"^/app/[A-Za-z0-9_./+-]+$", tok):
                    raise ShellGuardError(f"launch token not allowlisted: {tok!r}")

    if not text.startswith("#!"):
        text = "#!/bin/sh\n" + text
    return text


_SETUP_LINE = re.compile(r"^[A-Za-z0-9_./+=:@%-]+(?:\s+[A-Za-z0-9_./+=:@%-]+)*$")


def validate_setup_script(source: str) -> str:
    """A per-repo build script. One command per line, no shell operators.

    The command name is not tied to a language. The sandbox runs the script as-is.
    """
    text = source.replace("\r\n", "\n").strip() + "\n"
    if len(text) > 8_000:
        raise ShellGuardError("setup script too large")
    lower = text.lower()
    for bad in FORBIDDEN_SUBSTR:
        if bad in lower:
            raise ShellGuardError(f"setup script contains forbidden pattern: {bad!r}")

    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines or len(lines) > 40:
        raise ShellGuardError("setup script must have 1–40 non-comment lines")
    for ln in lines:
        if not _SETUP_LINE.match(ln.strip()):
            raise ShellGuardError(f"setup line not allowlisted: {ln!r}")
        if any(part == ".." for tok in ln.split() for part in tok.split("/")):
            raise ShellGuardError("setup path must stay inside the build")

    if not text.startswith("#!"):
        text = "#!/bin/sh\n" + text
    return text

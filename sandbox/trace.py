"""Parse ``strace -f -ttt`` output into normalised :class:`TraceEvent` objects.

Supports both epoch timestamps (``-ttt``, preferred) and wall-clock ``HH:MM:SS.ffffff``
(``-tt``; needs ``base_date_epoch`` to anchor the day), with or without ``-f`` pid prefixes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sandbox.models import TraceEvent

FILE_SYSCALLS = {
    "open",
    "openat",
    "openat2",
    "creat",
    "stat",
    "lstat",
    "newfstatat",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "mkdir",
    "mkdirat",
    "rmdir",
    "chmod",
    "fchmodat",
    "chdir",
    "truncate",
}
NET_SYSCALLS = {"connect", "bind", "listen", "sendto", "sendmsg", "accept", "accept4"}
PROC_SYSCALLS = {"execve", "execveat", "clone", "clone3", "fork", "vfork", "kill", "tgkill"}
ALL_SYSCALLS = FILE_SYSCALLS | NET_SYSCALLS | PROC_SYSCALLS

_LINE_RE = re.compile(
    r"^(?:\[pid\s+(?P<pid1>\d+)\]|(?P<pid2>\d+))?\s*"
    r"(?P<ts>\d+:\d+:\d+(?:\.\d+)?|\d{9,}(?:\.\d+)?)\s+"
    r"(?P<name>[a-z_0-9]+)\((?P<rest>.*)$"
)
_RET_RE = re.compile(r"\)\s+=\s+(?P<ret>-?\d+|\?|0x[0-9a-f]+)(?:\s+(?P<err>[A-Z0-9_]+)\s+\(.*?\))?")
_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_PORT_RE = re.compile(r"sin6?_port=htons\((\d+)\)")
_V4_RE = re.compile(r'sin_addr=inet_addr\("([^"]+)"\)')
_V6_RE = re.compile(r'inet_pton\(AF_INET6, "([^"]+)"')
_UNIX_RE = re.compile(r'sun_path="([^"]*)"')
_FAMILY_RE = re.compile(r"sa_family=(AF_[A-Z0-9]+)")
_FLAGS_RE = re.compile(r"\b(O_[A-Z_|0-9]+)")
_ARGV_RE = re.compile(r"\[(.*?)\]")


def _parse_ts(raw: str, base_date_epoch: float) -> float:
    if ":" in raw:
        h, m, s = raw.split(":")
        return base_date_epoch + int(h) * 3600 + int(m) * 60 + float(s)
    return float(raw)


def _strings(text: str) -> list[str]:
    return [m.group(1) for m in _STRING_RE.finditer(text)]


def _args_text(rest: str) -> str:
    """Argument text before the trailing ``) = ret`` (or ``<unfinished ...>``)."""
    idx = rest.rfind(") = ")
    if idx != -1:
        return rest[:idx]
    return re.sub(r"\s*<unfinished \.\.\.>$", "", rest).rstrip(")")


def _file_event(name: str, args: str, base: dict[str, Any]) -> TraceEvent:
    strings = _strings(args)
    path = strings[0] if strings else None
    flags = _FLAGS_RE.search(args)
    return TraceEvent(
        **base,
        kind="file",
        path=path,
        flags=flags.group(1) if flags else None,
        detail=f'{name}("{path}")' if path else f"{name}({args[:80]})",
    )


def _net_event(name: str, args: str, base: dict[str, Any]) -> TraceEvent | None:
    family = _FAMILY_RE.search(args)
    port = _PORT_RE.search(args)
    addr: str | None = None
    for rx in (_V4_RE, _V6_RE, _UNIX_RE):
        m = rx.search(args)
        if m:
            addr = m.group(1)
            break
    if addr is None and name in {"sendto", "sendmsg", "accept", "accept4"}:
        return None  # no destination: nothing to learn
    fam = family.group(1) if family else None
    port_num = int(port.group(1)) if port else None
    target = f"{addr}:{port_num}" if addr and port_num is not None else (addr or "")
    return TraceEvent(
        **base,
        kind="net",
        family=fam,
        addr=addr,
        port=port_num,
        path=addr if fam == "AF_UNIX" else None,
        detail=f"{name} {target}".strip(),
    )


def _proc_event(name: str, args: str, base: dict[str, Any]) -> TraceEvent:
    is_exec = name.startswith("execve")
    strings = _strings(args)
    path = strings[0] if strings and is_exec else None
    argv: list[str] = []
    if is_exec:
        m = _ARGV_RE.search(args)
        argv = _strings(m.group(1)) if m else []
    shown = " ".join(argv) if argv else (path or "")
    return TraceEvent(**base, kind="proc", path=path, argv=argv, detail=f"{name} {shown}".strip())


def parse_line(line: str, base_date_epoch: float = 0.0) -> TraceEvent | None:
    """Parse one strace line; ``None`` for syscalls we do not care about or resumed halves."""
    m = _LINE_RE.match(line.strip())
    if not m or "resumed>" in line:
        return None
    name, rest = m.group("name"), m.group("rest")
    if name not in ALL_SYSCALLS:
        return None
    ret = _RET_RE.search(rest)
    base: dict[str, Any] = {
        "ts": _parse_ts(m.group("ts"), base_date_epoch),
        "pid": int(m.group("pid1") or m.group("pid2") or 0),
        "syscall": name,
        "ret": ret.group("ret") if ret else None,
        "error": ret.group("err") if ret else None,
    }
    args = _args_text(rest)
    if name in FILE_SYSCALLS:
        return _file_event(name, args, base)
    if name in NET_SYSCALLS:
        return _net_event(name, args, base)
    return _proc_event(name, args, base)


def parse_strace_text(text: str, base_date_epoch: float = 0.0) -> list[TraceEvent]:
    events = (parse_line(line, base_date_epoch) for line in text.splitlines())
    return sorted((e for e in events if e), key=lambda e: e.ts)


def parse_strace_file(path: Path, base_date_epoch: float = 0.0) -> list[TraceEvent]:
    return parse_strace_text(path.read_text(encoding="utf-8", errors="replace"), base_date_epoch)


NOISE_PREFIXES = (
    "/usr/",
    "/lib",
    "/proc/",
    "/sys/",
    "/dev/",
    "/etc/ld.so",
    "/etc/localtime",
    "/etc/ssl/",
    "/etc/nsswitch",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/gai.conf",
    "/etc/host.conf",
    "/etc/passwd",
    "/etc/mime",
    "/opt/",
    "/bin/",
    "/sbin/",
    "/trace/",
)
NOISE_FRAGMENTS = ("site-packages", "__pycache__", "/dist-packages/", ".pyc", "pyvenv.cfg")


def is_noise_path(path: str | None) -> bool:
    """True for interpreter/loader files that every process touches."""
    if not path:
        return True
    if any(path.startswith(p) for p in NOISE_PREFIXES):
        return True
    return any(f in path for f in NOISE_FRAGMENTS)

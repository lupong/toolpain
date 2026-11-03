"""Pydantic models for sandbox observations (syscall trace events, sinkhole records)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

TraceKind = Literal["file", "net", "proc"]
SinkholeProto = Literal["dns", "http", "tls", "tcp"]


class TraceEvent(BaseModel):
    """One observed syscall, normalised: ``{ts, pid, kind, detail}`` plus parsed fields."""

    ts: float
    pid: int
    kind: TraceKind
    detail: str
    syscall: str = ""
    path: str | None = None
    addr: str | None = None
    port: int | None = None
    family: str | None = None
    ret: str | None = None
    error: str | None = None
    flags: str | None = None
    argv: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def is_write(self) -> bool:
        flags = self.flags or ""
        return any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))


class SinkholeRecord(BaseModel):
    """One thing the sinkhole saw: a DNS query, an HTTP request, a TLS SNI, or a bare TCP hit."""

    ts: float
    proto: SinkholeProto
    host: str = ""
    port: int | None = None
    src_ip: str = ""
    request_line: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    data: str = ""
    qtype: str = ""

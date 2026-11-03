"""Pydantic models shared by the runner stages (discovery, research, probe, analysis)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SourceCode = Literal["D", "S", "R", "F"]
SOURCE_ORDER = "DSRF"


class ToolInfo(BaseModel):
    """A tool as advertised by an MCP server."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None


class ResourceInfo(BaseModel):
    uri: str
    name: str = ""
    description: str = ""


class PromptInfo(BaseModel):
    name: str
    description: str = ""


class ServerSnapshot(BaseModel):
    """Everything a single runtime session of an MCP server advertised."""

    server_name: str = ""
    server_version: str = ""
    instructions: str | None = None
    tools: list[ToolInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)


class CallOutcome(BaseModel):
    """Result of a single tool call, with wall-clock bounds for trace correlation."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    is_error: bool = False
    timed_out: bool = False
    text: str = ""
    error: str | None = None
    start: float
    end: float

    @property
    def duration(self) -> float:
        return self.end - self.start


class StaticHit(BaseModel):
    """A tool registration found by the static source scan."""

    name: str
    file: str
    line: int
    snippet: str = ""
    pattern: str = ""
    context: dict[str, str] = Field(default_factory=dict)


class DiscoveredTool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    sources: list[SourceCode] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    static_hits: list[StaticHit] = Field(default_factory=list)
    documented: bool = False
    undocumented: bool = False
    hidden_behind_flag: bool = False

    @property
    def file(self) -> str | None:
        return self.static_hits[0].file if self.static_hits else None


class DiscoveryResult(BaseModel):
    server_name: str = ""
    tools: list[DiscoveredTool] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    docs_tools: list[str] = Field(default_factory=list)
    flag_candidates: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def get(self, name: str) -> DiscoveredTool | None:
        return next((t for t in self.tools if t.name == name), None)

    @property
    def names(self) -> list[str]:
        return [t.name for t in self.tools]

    @property
    def undocumented(self) -> list[str]:
        return [t.name for t in self.tools if t.undocumented]

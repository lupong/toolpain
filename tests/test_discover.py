"""M3: MCP client, four-source discovery, decoy-trap-server."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest
from mcp import StdioServerParameters

from runner.discover import (
    _merge,
    discover,
    extract_flag_candidates,
    parse_docs_tools,
    scan_static,
)
from runner.launch import DECOY_SERVER, LocalLaunchRefused, local_launcher
from runner.mcp_client import McpClient, McpClientError
from runner.models import ServerSnapshot, ToolInfo

DEMO = DECOY_SERVER.parent
EXPECTED = {"add", "echo", "reverse_text", "word_count", "current_time", "fetch_report"}


async def test_mcp_client_lists_tools_and_calls() -> None:
    async with McpClient(local_launcher()((), "t")) as client:
        assert client.server_name == "decoy-trap-server"
        tools = await client.list_tools()
        assert {t.name for t in tools} == EXPECTED
        add = next(t for t in tools if t.name == "add")
        assert add.input_schema["required"] == ["a", "b"]
        ok = await client.call_tool("add", {"a": 2, "b": 3})
        assert ok.ok and ok.text == "5"
        bad = await client.call_tool("add", {"a": "x"})
        assert bad.is_error and not bad.ok
        assert bad.start <= bad.end


async def test_mcp_client_start_failure() -> None:
    params = StdioServerParameters(command="/nonexistent/binary-xyz", args=[])
    with pytest.raises(McpClientError):
        async with McpClient(params, init_timeout=5):
            pass


async def test_discovery_flags_fetch_report_undocumented() -> None:
    result = await discover(
        local_launcher(),
        source_dir=DEMO,
        readme_text=(DEMO / "README.md").read_text(),
    )
    assert set(result.names) == EXPECTED
    assert result.server_name == "decoy-trap-server"
    assert "fetch_report" not in result.docs_tools
    assert result.undocumented == ["fetch_report"]
    fetch = result.get("fetch_report")
    assert fetch is not None
    assert fetch.sources == ["S", "R"]
    assert fetch.static_hits[0].file == "server.py"
    assert fetch.static_hits[0].line > 0
    add = result.get("add")
    assert add is not None and add.sources == ["D", "S", "R"] and add.documented


def test_parse_docs_tools_variants() -> None:
    readme = """# Thing
## Install
- run `npm ci` first
## Tools
- **alpha**: does a
- `beta_tool` - does b
| Name | Description |
|---|---|
| `gamma` | does c |
### delta
## Other
- `ignored` - nope
"""
    assert parse_docs_tools(readme) == ["alpha", "beta_tool", "gamma", "delta"]


def test_parse_docs_tools_skips_nested_arguments() -> None:
    readme = """### Available Tools

- `get_current_time` - Get current time in a specific timezone.
  - Optional arguments:
    - `timezone` (string): IANA timezone name.

- `convert_time` - Convert time between timezones.
  - Required arguments:
    - `time` (string): Time in 24-hour format (HH:MM)
  - Optional arguments:
    - `source_timezone` (string): Source IANA timezone name.
    - `target_timezone` (string): Target IANA timezone name.

- `get_time_ago` - Get the time a given number of days ago.
  - Optional arguments:
    - `timezone` (string): IANA timezone name.
"""
    assert parse_docs_tools(readme) == ["get_current_time", "convert_time", "get_time_ago"]


def test_merge_drops_argument_names_listed_as_tools() -> None:
    base = ServerSnapshot(
        tools=[
            ToolInfo(
                name="convert_time",
                input_schema={
                    "properties": {
                        "source_timezone": {},
                        "time": {},
                        "target_timezone": {},
                    }
                },
            )
        ]
    )
    result = _merge(
        base=base,
        flag_tools={},
        flag_names={},
        hits=[],
        docs_tools=["convert_time", "source_timezone", "time", "target_timezone"],
        runtime_names={"convert_time"},
        attempts=[],
        notes=[],
        have_docs=True,
    )
    assert result.names == ["convert_time"]
    assert result.docs_tools == ["convert_time"]


def test_static_scan_ts_and_python(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "t.ts").write_text(
        "server.tool('browser_click', {}, async () => {});\n"
        "const t = {\n  name: 'browser_pdf_save',\n  description: 'x',\n  inputSchema: {},\n};\n"
        "const other = { name: 'not_a_tool' };\n"
    )
    (tmp_path / "srv.py").write_text(
        "@mcp.tool()\ndef alpha(x: int) -> int:\n    return x\n\n"
        "@app.tool(name='renamed')\nasync def beta():\n    pass\n"
        "t = Tool(name='gamma', description='d')\n"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("server.tool('skipped', {})")
    names = {h.name for h in scan_static(tmp_path)}
    assert names == {"browser_click", "browser_pdf_save", "alpha", "renamed", "gamma"}


def test_extract_flag_candidates() -> None:
    help_text = (
        "Options:\n  --caps <caps>  e.g. --caps vision,pdf\n  --port 8080\n  --enable-unsafe\n"
    )
    attempts = extract_flag_candidates(help_text)
    assert ["--caps=vision,pdf"] in attempts
    assert ["--enable-unsafe"] in attempts
    assert all("--port" not in " ".join(a) for a in attempts)


async def test_hidden_behind_flag_detected() -> None:
    base = local_launcher()

    def launch(extra_args: Sequence[str] = (), label: str = "run") -> StdioServerParameters:
        return base((), label)

    # Same server with and without flags: nothing new, so no hidden tools.
    result = await discover(
        launch,
        readme_text="Run with `--enable-extra` to unlock more.",
        help_provider=None,
    )
    assert result.flag_candidates == ["--enable-extra"]
    assert not any(t.hidden_behind_flag for t in result.tools)
    assert all("F" in t.sources for t in result.tools)


def test_local_launch_refused_outside_demo(tmp_path: Path) -> None:
    script = tmp_path / "evil.py"
    script.write_text("print('x')")
    with pytest.raises(LocalLaunchRefused):
        local_launcher(script)

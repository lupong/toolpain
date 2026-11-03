# Decisions

| Date | Decision | Reason |
|---|---|---|
| 2026-11-03 | Docker present; `runsc` absent → `RUNTIME=runc` mode | Env detection on build machine. Gap: no gVisor isolation; use strace + internal network + cap-drop. |
| 2026-11-03 | Use Python 3.12 via `python3.12` in Makefile | Spec requires 3.12; system also has 3.13/3.14. |
| 2026-11-03 | Port existing root design files into `design/` then `web/` | Design already uploaded; keep class names per Part 1.8 / design README. |
| 2026-11-03 | Default `PROVISIONER=fake` and `LLM_MODE=fake` | No Vultr keys in env; everything must run offline with tests green. |
| 2026-11-03 | GitHub repo `lupong/toolpain` (public) | User requested repo named toolpain in their GitHub account. |
| 2026-11-03 | Authored `docs/ARCHITECTURE.md` from megaprompt §2.2–2.4 | Spec referenced the file but it was not in the upload; synthesize from Part 2. |
| 2026-11-03 | decoy-trap-server uses `mcp.server.mcpserver.MCPServer` (mcp 2.x name for FastMCP) with a `FastMCP` import fallback | Installed `mcp` is 2.3; `mcp.server.fastmcp` no longer exists. |
| 2026-11-03 | `fetch_report` has no env/path override; locally the decoy file is simply absent | Keeps the safety contract literal: one fixed decoy path, one fixed sinkhole host. |
| 2026-11-03 | `runner/launch.local_launcher` refuses scripts outside `demo/` | Scanned servers must only ever run in a container; local run is demo/test-only. |
| 2026-11-03 | Discovery tool-name docs extraction: regex in fake mode (Tools-section bullets/tables/sub-headings + snake_case bullets); LLM extractor optional | Matches spec (fake mode = regex on README). |
| 2026-11-03 | Fork drift baseline for the demo = `demo/decoy-trap-server/upstream_tools.json` | No real upstream for the demo; honest tools are the "upstream" version. |

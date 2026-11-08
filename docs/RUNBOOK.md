# ToolPain runbook

One entry per scan error code. The code is on the scan, in the diagnostics tab, and on the failure note IT pastes into the ticket.

## invalid_repo

The GitHub URL is not `https://github.com/owner/repo`. Ask IT to paste the repository link again. Nothing was cloned.

## repo_unavailable

The clone failed because the repo is private, missing, or GitHub refused the fetch. ToolPain scans public repos. Confirm the URL in a browser without being logged in.

## ref_missing

The branch, tag, or commit is not on that repo. Check the ref on the ticket and scan `main` if the named ref was a typo.

## build_failed

The server image did not build. Open Diagnostics and read the build log excerpt. The usual cause is a missing package, a private registry, or a Dockerfile that expects a network at runtime. The debug bundle's `runner.stderr` is the same log with secrets removed.

## launch_failed

The image built, but the MCP process did not stay up. Read the launch command in Diagnostics. A bad `launch.sh`, a missing entrypoint, or a server that exits when stdin is quiet will land here.

## no_mcp_server

The repo does not look like an MCP server: no language ToolPain can build and no launch command. Point the scan at the package subdirectory, or give a scan brief that names the server package.

## probe_timeout

A tool call did not return before the probe limit. The tool stays `not_observed`. If it hangs on a prompt or a network call, that call was contained. Re-scan only after the server has a timeout of its own.

## report_invalid

The runner finished but the report did not match the contract. Nothing was stored as a successful scan. Download the debug bundle and look at `report.json` for the payload that was rejected.

## provision_failed

The scanner VM did not become ready. For a local run, Docker is not responding. For Vultr, the instance did not report ready and the reaper deletes anything left behind. Check `/api/system` for runtime and the reaper.

## vm

Same panel as provision failure: the scanner VM never became ready or was lost mid-scan. Confirm Vultr status and the reaper; re-scan after the instance path is healthy.

## byo_rejected

The Vultr key was refused. It is not stored. The key needs to be valid, and its IP allow-list must include the address ToolPain used.

## cancelled

Someone cancelled the scan. The environment was destroyed. Scan again if the ticket still needs a result.

## internal

The runner hit an unexpected error. The message is redacted. Use the debug bundle and the JSON log line with this `scan_id`. Do not paste raw runner output into the ticket until it has been through the bundle.

# Decisions

| Date | Decision | Reason |
|---|---|---|
| 2026-11-03 | Docker present; `runsc` absent → `RUNTIME=runc` mode | Env detection on build machine. Gap: no gVisor isolation; use strace + internal network + cap-drop. |
| 2026-11-03 | Use Python 3.12 via `python3.12` in Makefile | Spec requires 3.12; system also has 3.13/3.14. |
| 2026-11-03 | Port existing root design files into `design/` then `web/` | Design already uploaded; keep class names per Part 1.8 / design README. |
| 2026-11-03 | Default `PROVISIONER=fake` and `LLM_MODE=fake` | No Vultr keys in env; everything must run offline with tests green. |
| 2026-11-03 | GitHub repo `lupong/toolpain` (public) | User requested repo named toolpain in their GitHub account. |
| 2026-11-03 | Authored `docs/ARCHITECTURE.md` from megaprompt §2.2–2.4 | Spec referenced the file but it was not in the upload; synthesize from Part 2. |

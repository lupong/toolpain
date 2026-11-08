#!/usr/bin/env bash
# Shared ToolPain install — same recipe for laptop, control plane, and scanner bake.
#
# Usage:
#   ./infra/install_toolpain.sh                 # install into ./ .venv (dev extras)
#   ./infra/install_toolpain.sh /opt/toolpain   # production path on a VM
#   TOOLPAIN_INSTALL_DEV=0 ./infra/install_toolpain.sh /opt/toolpain
#
# Rules:
# - Never copy a .venv from another machine (Mac → Linux will break).
# - Always create the venv on the target OS, then pip install from this tree.
# - Refuse to finish unless `import runner.main` works.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$ROOT}"
TARGET="$(cd "$TARGET" && pwd)"
DEV="${TOOLPAIN_INSTALL_DEV:-}"
if [[ -z "$DEV" ]]; then
  # Default: dev extras on a repo checkout that looks local; prod on /opt/toolpain.
  if [[ "$TARGET" == "/opt/toolpain" ]]; then
    DEV=0
  else
    DEV=1
  fi
fi

PYTHON_BIN="${TOOLPAIN_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  for candidate in python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
fi
if [[ -z "$PYTHON_BIN" ]]; then
  echo "error: need python3.12+ on PATH" >&2
  exit 1
fi

ver="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
"$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' || {
  echo "error: Python >= 3.12 required (found $ver via $PYTHON_BIN)" >&2
  exit 1
}

if [[ ! -f "$TARGET/pyproject.toml" ]]; then
  echo "error: $TARGET has no pyproject.toml — clone/copy the repo first" >&2
  exit 1
fi

echo "toolpain install target=$TARGET python=$PYTHON_BIN ($ver) dev=$DEV"

# Always rebuild the venv on the *current* machine. Cross-host venvs are not portable.
rm -rf "$TARGET/.venv"
"$PYTHON_BIN" -m venv "$TARGET/.venv"
# shellcheck disable=SC1091
source "$TARGET/.venv/bin/activate"
python -m pip install -U pip

if [[ "$DEV" == "1" ]]; then
  python -m pip install -e "${TARGET}[dev]"
else
  python -m pip install -e "$TARGET"
fi

# Hard gate: the scanner dies in ~200ms without this.
python - <<'PY'
import importlib
import pathlib
import sys

errors = []
try:
    import runner.main  # noqa: F401
except Exception as exc:  # noqa: BLE001 — surface anything that would kill cloud-init
    errors.append(f"import runner.main failed: {exc!r}")

# Catch corrupt-bake failure mode: truncated non-init .py modules.
# Empty ``__init__.py`` files are normal package markers — ignore them.
site = pathlib.Path(sys.prefix) / "lib"
zeros = [
    p
    for p in site.rglob("*.py")
    if "site-packages" in p.parts
    and p.name != "__init__.py"
    and p.stat().st_size == 0
][:20]
if zeros:
    errors.append(
        "zero-byte packages in venv (corrupt install): "
        + ", ".join(str(p.relative_to(site)) for p in zeros)
    )

# pydantic / mcp are load-bearing for the runner.
for mod in ("pydantic", "mcp", "httpx"):
    try:
        importlib.import_module(mod)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"import {mod} failed: {exc!r}")

if errors:
    print("VERIFY FAILED:", file=sys.stderr)
    for line in errors:
        print(f"  - {line}", file=sys.stderr)
    raise SystemExit(1)
print("verify_ok: runner.main + deps importable")
PY

echo "install_ok: $TARGET/.venv"
echo "activate: source $TARGET/.venv/bin/activate"

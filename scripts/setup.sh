#!/usr/bin/env bash
# =========================================================================
#  APTS — one-command host setup (Phase 1 packaging).
#
#  Idempotent: safe to re-run. Checks prerequisites (Docker daemon reachable,
#  Python >= 3.11), creates a .venv, installs the host Runner package into it
#  (`pip install -e .`), and generates the local secrets/certs via `make certs`.
#
#  After this: `make up` to start the backend, then
#  `apts run --target <url> --scope <domain>` (or drive it from Claude Code
#  via .mcp.json).
# =========================================================================
set -euo pipefail

# Resolve repo root from this script's location, so cwd does not matter.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Docker installed AND daemon reachable ----------------------------
command -v docker >/dev/null 2>&1 \
  || die "Docker is not installed. Install Docker + 'docker compose' v2 and retry (on WSL, Docker Desktop)."
docker info >/dev/null 2>&1 \
  || die "Docker is installed but the daemon is not reachable. Start Docker (on WSL, start Docker Desktop) and retry."
say "Docker OK ($(docker --version))"

# --- 2. Python >= 3.11 ---------------------------------------------------
PYTHON="${APTS_PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 \
  || die "Python interpreter '$PYTHON' not found. Install Python >= 3.11 (or set APTS_PYTHON=/path/to/python3.11)."
"$PYTHON" - <<'PYEOF' || die "Python >= 3.11 is required (found an older interpreter). Install Python 3.11+ or set APTS_PYTHON."
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)
PYEOF
say "Python OK ($("$PYTHON" --version 2>&1))"

# --- 3. Virtualenv (create if missing) -----------------------------------
VENV="$ROOT/.venv"
if [ ! -x "$VENV/bin/python" ]; then
  say "Creating virtualenv at .venv"
  "$PYTHON" -m venv "$VENV"
else
  say "Reusing existing virtualenv at .venv"
fi

# --- 4. Install the host Runner package (editable) -----------------------
say "Upgrading pip"
"$VENV/bin/python" -m pip install --upgrade pip >/dev/null
say "Installing APTS host Runner (pip install -e .) — this may take a while"
"$VENV/bin/python" -m pip install -e "$ROOT"

# --- 5. Secrets + certs (idempotent; no-ops if already present) ----------
say "Generating local secrets/certs (make certs)"
make certs

# --- 6. Next steps -------------------------------------------------------
cat <<'EOF'

==> Setup complete.

Next steps:
  1. Start the backend containers (Postgres + mcp-native tools server):
         make up

  2. Start an authorized target reachable from mcp-native, e.g.:
         docker run -d --name juice --hostname juice-shop \
           --network apts-lean_apts-lean-net bkimminich/juice-shop:v17.1.1

  3. Run an engagement (activate the venv first, or use .venv/bin/apts):
         source .venv/bin/activate
         apts run --target http://juice-shop:3000 --scope juice-shop

  Or drive the harness from Claude Code over MCP (.mcp.json is shipped):
         make up      # backend must be up first

EOF

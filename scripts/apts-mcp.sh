#!/usr/bin/env bash
# Entry point for Claude Code (or any MCP client) to spawn the APTS harness
# control server over stdio. Referenced by .mcp.json. Sets the env the Runner
# needs, then execs the server. Every var is overridable from the environment.
#
# Requires the backend up first: `make up` (Postgres + mcp-native) and a target.
set -euo pipefail

# Resolve repo root from this script's location, so cwd does not matter.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Langfuse creds (gitignored), if present, so Claude Code's runs are traced too.
# shellcheck disable=SC1091
[ -f tokens/langfuse.env ] && . ./tokens/langfuse.env

export APTS_MCP_URL="${APTS_MCP_URL:-http://127.0.0.1:9000/mcp}"
export APTS_STORAGE="${APTS_STORAGE:-postgres}"
export APTS_CONFIG_DIR="${APTS_CONFIG_DIR:-$ROOT/config}"
export APTS_REPORT_DIR="${APTS_REPORT_DIR:-$ROOT/reports}"
# LLM: the pipeline's worker model (keep this a cheap model — Claude Code/Sonnet
# only DRIVES the harness; it never runs the per-stage LLM work).
export APTS_LLM_KEY_FILE="${APTS_LLM_KEY_FILE:-$ROOT/tokens/aws_llm.key}"
export APTS_LOOP_LLM_URL="${APTS_LOOP_LLM_URL:-https://bedrock-mantle.eu-north-1.api.aws/v1/chat/completions}"
export APTS_LOOP_LLM_MODEL="${APTS_LOOP_LLM_MODEL:-qwen.qwen3-coder-480b-a35b-instruct}"
# DB (postgres mode)
export APTS_DB_HOST="${APTS_DB_HOST:-localhost}"
export APTS_DB_PORT="${APTS_DB_PORT:-5432}"
export APTS_DB_USER="${APTS_DB_USER:-apts}"
export APTS_DB_NAME="${APTS_DB_NAME:-apts}"
export APTS_DB_PASSWORD_FILE="${APTS_DB_PASSWORD_FILE:-$ROOT/tokens/db_password.txt}"
export APTS_TRUST_BUNDLE="${APTS_TRUST_BUNDLE:-$ROOT/certs/database.crt}"

PY="${APTS_PYTHON:-$ROOT/.venv/bin/python}"
exec "$PY" -m apts.serve --transport stdio --storage "$APTS_STORAGE"

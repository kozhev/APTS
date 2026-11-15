# =========================================================================
#  APTS — EASY-RUN Makefile for the single-process host Runner (ADDITIVE)
#
#  Two containers (make tools / make db) + one host process (make run).
#  See CLAUDE.md for the full walkthrough.
#
#  Quick start (no DB, fastest):
#      make setup
#      make tools
#      make run-nodb TARGET=http://127.0.0.1:3000 SCOPE=127.0.0.1
#
#  Persistent engagements (Postgres):
#      make setup
#      make db
#      make tools
#      make run TARGET=http://127.0.0.1:3000 SCOPE=127.0.0.1
# =========================================================================

# Interpreter used for the host Runner process (override: make run PYTHON=python3.11)
PYTHON    ?= python3

# LLM endpoint — defaults match docker-compose.yml. Override on the command line.
LLM_URL   ?= https://bedrock-mantle.eu-north-1.api.aws/v1/chat/completions
LLM_MODEL ?= qwen.qwen3-coder-480b-a35b-instruct

COMPOSE   := docker compose -f docker-compose.lean.yml

# Path to your sqlmap checkout, mounted read-only into mcp-native. Defaults to
# the repo-relative ./.sqlmap (absent by default → sqlmap tool unavailable).
# Override: make tools SQLMAP_DIR=/path/to/sqlmap
SQLMAP_DIR ?= ./.sqlmap
# Exported so `docker compose` (in the tools target) picks it up from the env.
export SQLMAP_DIR

# Engagement parameters (make vars).
TARGET    ?=
SCOPE     ?=
OBJECTIVE ?=
RESUME    ?=

# Port for the harness MCP control server (make serve / serve-nodb).
PORT      ?= 9100

# Exploit-stage parallelism. The real lab fronts 10 load-balanced Juice Shop
# replicas, so the upstream default is 10. The lean stack runs ONE target
# instance, and 10 concurrent sqlmap/xss proofs OOM-crash it ("JS heap out of
# memory" → Exited 139). Keep this low for a single-instance target; raise it
# only if you scale the target out. Override: make run EXPLOIT_CONCURRENCY=5 ...
EXPLOIT_CONCURRENCY ?= 3

SCOPE_ARG  = $(if $(strip $(SCOPE)),--scope "$(SCOPE)",)
OBJ_ARG    = $(if $(strip $(OBJECTIVE)),--objective "$(OBJECTIVE)",)
RESUME_ARG = $(if $(strip $(RESUME)),--resume "$(RESUME)",)

# Env common to both run modes. Host-side file paths resolve against this repo.
COMMON_ENV = \
  APTS_MCP_URL=http://127.0.0.1:9000/mcp \
  APTS_LLM_KEY_FILE=$(CURDIR)/tokens/aws_llm.key \
  APTS_LOOP_LLM_URL="$(LLM_URL)" \
  APTS_LOOP_LLM_MODEL="$(LLM_MODEL)" \
  APTS_CONFIG_DIR=$(CURDIR)/config \
  APTS_REPORT_DIR=$(CURDIR)/reports \
  APTS_EXPLOIT_CONCURRENCY=$(EXPLOIT_CONCURRENCY)

# DB connection env (postgres mode). host=localhost matches the database.crt
# SAN (DNS:localhost); verify-full is validated against certs/database.crt.
DB_ENV = \
  APTS_DB_HOST=localhost \
  APTS_DB_PORT=5432 \
  APTS_DB_USER=apts \
  APTS_DB_NAME=apts \
  APTS_DB_PASSWORD_FILE=$(CURDIR)/tokens/db_password.txt \
  APTS_TRUST_BUNDLE=$(CURDIR)/certs/database.crt

# Langfuse tracing — optional, fails open. If tokens/langfuse.env exists (gitignored;
# holds LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY / LANGFUSE_HOST), source it so every
# run/serve emits traces. Absent → runs proceed untraced, exactly as before.
LANGFUSE_SRC = [ -f tokens/langfuse.env ] && . ./tokens/langfuse.env;

.PHONY: help setup certs tools db run run-nodb serve serve-nodb down logs require-target

help:
	@echo "APTS easy-run targets:"
	@echo "  make setup                         install host Runner deps (requirements-runner.txt)"
	@echo "  make db                            start Postgres (127.0.0.1:5432), schema auto-init"
	@echo "  make tools                         start mcp-native tools server (127.0.0.1:9000/mcp)"
	@echo "  make run     TARGET=.. SCOPE=..    run an engagement in Postgres mode"
	@echo "  make run-nodb TARGET=.. SCOPE=..   run an engagement in memory mode (no DB)"
	@echo "  make serve                         launch the harness MCP control server (postgres, port 9100)"
	@echo "  make serve-nodb                    launch the harness MCP control server (memory, core tools only)"
	@echo "  make down                          stop the lean stack"
	@echo "  make logs                          tail the lean stack logs"
	@echo ""
	@echo "Vars: TARGET= SCOPE= [OBJECTIVE=] [RESUME=] [PORT=] [LLM_URL=] [LLM_MODEL=] [SQLMAP_DIR=]"

# --- host dependencies ---------------------------------------------------
setup:
	$(PYTHON) -m pip install -r requirements-runner.txt

# --- one-time secrets/certs (idempotent) ---------------------------------
# generate_password.sh and generate_certs.sh are both no-ops if their output
# already exists. certs/database.key is gitignored, so a fresh checkout needs
# this before the DB can serve TLS.
certs:
	@[ -s tokens/db_password.txt ] || bash bootstrap/generate_password.sh
	@[ -f certs/database.key ] || bash bootstrap/generate_certs.sh
	@[ -f certs/trust-bundle.pem ] || bash bootstrap/generate_certs.sh

# --- containers ----------------------------------------------------------
tools: certs
	$(COMPOSE) up -d mcp-native

db: certs
	$(COMPOSE) up -d database
	@echo "database up on 127.0.0.1:5432 (schema init runs automatically on a fresh volume)"

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=100

# --- engagements ---------------------------------------------------------
require-target:
	@test -n "$(strip $(TARGET))" || { \
	  echo "ERROR: set TARGET=<url>  e.g.  make run TARGET=http://127.0.0.1:3000 SCOPE=127.0.0.1"; \
	  exit 1; }

# Postgres mode — persistent engagement state. Requires `make db` + `make tools`.
run: require-target
	$(LANGFUSE_SRC) $(COMMON_ENV) $(DB_ENV) APTS_STORAGE=postgres \
	  $(PYTHON) -m apts.cli run --target "$(TARGET)" $(SCOPE_ARG) --storage postgres $(OBJ_ARG) $(RESUME_ARG)

# Memory mode — no DB needed. Requires `make tools` only.
run-nodb: require-target
	$(LANGFUSE_SRC) $(COMMON_ENV) APTS_STORAGE=memory \
	  $(PYTHON) -m apts.cli run --target "$(TARGET)" $(SCOPE_ARG) --storage memory $(OBJ_ARG) $(RESUME_ARG)

# --- harness MCP control server (an agent drives the Runner over MCP) -----
# serve.py binds 0.0.0.0:$(PORT) (streamable-HTTP /mcp) — it has no host flag,
# so it listens on all interfaces; see CLAUDE.md. Override the port with PORT=.

# Postgres mode — the real path: all 7 core control tools + the DB-backed query
# tools. Requires `make db` + `make tools` up first.
serve:
	$(LANGFUSE_SRC) $(COMMON_ENV) $(DB_ENV) APTS_STORAGE=postgres \
	  $(PYTHON) -m apts.serve --storage postgres --port $(PORT)

# Memory mode — ephemeral, core control tools only (no DB-backed query tools).
# Requires `make tools` only.
serve-nodb:
	$(LANGFUSE_SRC) $(COMMON_ENV) APTS_STORAGE=memory \
	  $(PYTHON) -m apts.serve --storage memory --no-db-tools --port $(PORT)

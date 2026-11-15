# APTS — Easy Run (single host process + lean containers)

APTS runs the pentest pipeline as **one host Python process** (`python -m apts.cli run ...`)
that talks to **two containers**: a tools server (`mcp-native`) and, optionally, Postgres.
The pipeline has five stages: **recon → vuln → mitre → exploit → adviser**.
The lean path is additive (`docker-compose.lean.yml`, `Makefile`, `requirements-runner.txt`);
the full `docker-compose.yml` still exists.

## Prerequisites
- **Docker** + `docker compose` v2 (daemon running — on WSL, start Docker Desktop).
- **Python 3.11** on the host (for the Runner process; a virtualenv is recommended).
- **LLM key** at `tokens/aws_llm.key` (already present in this repo; a Bedrock-compatible key).
- `tokens/db_password.txt` and `certs/` are generated automatically by `make` on first use
  (`bootstrap/generate_password.sh`, `bootstrap/generate_certs.sh`). `certs/database.key` is
  gitignored, so a fresh checkout regenerates it — this is why DB mode runs `make certs` first.
- **sqlmap** checkout for SQL-injection proofs. Set `SQLMAP_DIR` to your sqlmap
  checkout — e.g. `make tools SQLMAP_DIR=/path/to/sqlmap`. It defaults to the
  repo-relative `./.sqlmap`, which does not exist by default: if `SQLMAP_DIR`
  does not point at a real sqlmap checkout the sqlmap tool is simply unavailable,
  and every other tool still works.

## Install the host deps
```bash
python3 -m venv .venv && source .venv/bin/activate   # recommended
make setup                                           # pip install -r requirements-runner.txt
```

## Two run modes

### A) No-DB / memory mode (fastest, nothing persisted)
```bash
make tools                                           # start mcp-native (127.0.0.1:9000/mcp)
make run-nodb TARGET=http://127.0.0.1:3000 SCOPE=127.0.0.1
```

### B) Postgres mode (persistent engagement state, resumable)
```bash
make db                                              # start Postgres (127.0.0.1:5432), schema auto-init
make tools                                           # start mcp-native
make run TARGET=http://127.0.0.1:3000 SCOPE=127.0.0.1
```
Resume a prior engagement: `make run RESUME=<engagement_id> TARGET=... SCOPE=...`

Stop everything: `make down`  ·  Tail logs: `make logs`

## Harness / agent control
There are two run surfaces:

- **(a) Direct CLI** — `python -m apts.cli run ...` (the `make run` / `make run-nodb`
  targets above): a one-shot engagement that runs to completion and writes the report.
- **(b) MCP control server** — `make serve` launches `python -m apts.serve`, an MCP
  (streamable-HTTP) server that an agent (Claude Code / any MCP client) connects to and
  drives: `create_engagement`, `engagement_status`, `list_artifacts`, `get_artifact`,
  `get_report`, `stop_engagement`, `resume_engagement`, plus DB-backed query tools.

```bash
make db && make tools     # must both be up first for a real (postgres) run
make serve                # postgres mode, all tools, port 9100

# ephemeral alternative (no DB, core control tools only):
make tools
make serve-nodb           # memory mode (--storage memory --no-db-tools)
```

- **Port:** default **9100** — override with `PORT=` (e.g. `make serve PORT=9200`);
  `serve.py` also honours `APTS_CONTROL_MCP_PORT`. The MCP endpoint is at `/mcp`.
- **Bind address:** binds **`127.0.0.1` (loopback only)** by default, so only this
  machine can reach the control server. Override with `--host 0.0.0.0` (or
  `APTS_CONTROL_MCP_HOST=0.0.0.0`) only if an agent on another host must connect — and
  firewall the port if you do.
- **Modes:** **postgres is the real path** — the 7 core control tools *and* the DB-backed
  query tools (`list_engagements`, `get_loot`, `get_recon_*`, `search_run`, ...). Memory
  mode (`serve-nodb`) exposes **only the 7 core control tools** and persists nothing;
  `resume_engagement` is postgres-only.
- **Env:** `make serve` exports the same env as `make run` (`APTS_STORAGE=postgres`, the
  `APTS_DB_*` set, `APTS_MCP_URL`, the LLM vars, `APTS_CONFIG_DIR`/`APTS_REPORT_DIR`), so
  `make db` + `make tools` must be running for a real postgres engagement.

## How the Runner reaches the tools container (the critical seam)
`mcp-native` serves genuine MCP over plain HTTP at **`http://127.0.0.1:9000/mcp`**.
**It performs no authentication of its own** — there is no bearer token or mTLS on the
server (see `mcp_native/server.py`; the `mcp-native.token` secret it mounts is used only by
the `sandbox_run` tool to call the sandbox container, which the lean stack does not run).
So the host Runner connects with a plain MCP client and **no credentials**. The only env it
needs is `APTS_MCP_URL=http://127.0.0.1:9000/mcp` (set by `make run` / `make run-nodb`).

Note: the `script` pipeline stage has been removed — the pipeline is now
recon → vuln → mitre → exploit → adviser (exploit does the critical work; the adviser
produces the report). The `sandbox_run` tool is in any case unavailable in the lean stack
because no sandbox container runs. All other tools (http_request, crawler, recon lookup,
sqlmap, katana/ffuf, ATT&CK/HackTricks lookup) work.

## Environment the Runner reads (all set for you by the Makefile)
| Var | Value (lean) | Meaning |
|-----|--------------|---------|
| `APTS_STORAGE` | `postgres` / `memory` | storage backend (`run` vs `run-nodb`) |
| `APTS_MCP_URL` | `http://127.0.0.1:9000/mcp` | tools server |
| `APTS_DB_HOST` | `localhost` | matches the `DNS:localhost` SAN on `database.crt` |
| `APTS_DB_PORT` / `_USER` / `_NAME` | `5432` / `apts` / `apts` | DB connection |
| `APTS_DB_PASSWORD_FILE` | `tokens/db_password.txt` | DB password (file, never an env value) |
| `APTS_TRUST_BUNDLE` | `certs/database.crt` | TLS root for `sslmode=verify-full` |
| `APTS_LLM_KEY_FILE` | `tokens/aws_llm.key` | LLM bearer key (file) |
| `APTS_LOOP_LLM_URL` | `https://bedrock-mantle.eu-north-1.api.aws/v1/chat/completions` | LLM endpoint (`LLM_URL=`) |
| `APTS_LOOP_LLM_MODEL` | `qwen.qwen3-coder-480b-a35b-instruct` | model id (`LLM_MODEL=`) |
| `APTS_CONFIG_DIR` | `config/` | scope allowlist etc. |
| `APTS_REPORT_DIR` | `reports/` | Adviser writes the final report here |

DB mode uses TLS `verify-full` (hard-wired in `shared/db.py`): the lean Postgres serves with
`ssl=on` using `certs/database.crt`/`.key`, the host connects as `localhost` (in the cert SAN),
and the cert is its own self-signed root via `APTS_TRUST_BUNDLE=certs/database.crt`. The lean
DB copies the cert/key to a postgres-owned path at startup, so **no `chown` of the host key is
needed**.

## Scanning an external target (proxy option)
The lean network is a normal bridge, so you can point `--target` straight at an authorised
external URL. To keep the scan behind a single controlled egress (as the full stack does),
use the **`proxy`** reverse-proxy pattern from `docker-compose.yml`: it fronts the real site
so scanners target the proxy, not the internet directly. Bring it up from the full compose:
```bash
APTS_PROXY_UPSTREAM=https://authorized-target.example.com \
  docker compose up -d proxy
```
then run against it (the proxy listens on `proxy:8080` inside Docker; publish a loopback port
or attach it to `apts-lean-net` to reach it from the host Runner). **Only ever point it at a
target you are authorised to test.**

## Files in this lean layer
- `docker-compose.lean.yml` — `mcp-native` + `database` only.
- `Makefile` — `setup`, `tools`, `db`, `run`, `run-nodb`, `down`, `logs`.
- `requirements-runner.txt` — pinned host-process deps.

## Drive it from Claude Code (MCP entry point)

The repo ships `.mcp.json`, so Claude Code auto-discovers an **`apts`** MCP server
(it spawns `scripts/apts-mcp.sh` over stdio — no port, no separate process to
manage). Claude Code (on Sonnet) then *drives* the harness; the pipeline's
per-stage LLM work still runs on the cheap worker model (`APTS_LOOP_LLM_MODEL`),
so **your Claude plan is never billed for the hundreds of pipeline calls** — only
the handful of orchestration turns.

**One-time setup**
```bash
make setup          # host venv + deps
make up             # Postgres + mcp-native (the backend the harness needs)
# start a target reachable from mcp-native, e.g. on the apts-lean network:
docker run -d --name juice --hostname juice-shop \
  --network apts-lean_apts-lean-net bkimminich/juice-shop:v17.1.1
```
If Claude Code doesn't pick up `.mcp.json` automatically:
`claude mcp add apts -- bash scripts/apts-mcp.sh`

**The flow (what Claude Code calls)**
1. `apts_health` — confirm the backend is up (call this first; it points you to
   `make up` if not).
2. `apts_capabilities` — what a run needs.
3. `create_engagement(target_url="http://juice-shop:3000", domains=["juice-shop"],
   objective="...")` — returns an `engagement_id`, pipeline starts in the background.
4. `engagement_status(id)` — poll until `completed` (watch `per_agent`).
5. `get_report(id)` for the client report; `get_artifact(id, stage)`,
   `get_recon_findings(id)`, `get_loot(id)`, `search_run(id, query)` to drill in.
6. `stop_engagement(id)` / `resume_engagement(id)` to control a long run.

The server binds nothing on the network in stdio mode. For an external target,
front it with the reverse proxy (`APTS_PROXY_UPSTREAM=...`, see above) and point
`create_engagement` at the proxy.

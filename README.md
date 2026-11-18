# APTS — Agentic Web-Application Penetration Testing

APTS is an autonomous, agent-driven system that penetration-tests web applications
end to end. It maps an app's attack surface, reasons about where the weaknesses
are, drives real security tools to exploit and prove them, and writes up the
results — as a pipeline of specialized agents, each responsible for one stage of a
real pentest workflow.

---

## What it does

A run flows through these stages. Each one hands a structured result to the next.

### 1. Probe — the initial surface map
Every run starts with **probe**: a first pass over the target that builds an
**AssetMap** — a structured summary of the web app's surface. It records the
app's routes, the inputs on each page, and the API requests the app makes. Probe
is the shared starting point; everything downstream reasons from this map.

### 2. Recon — the exploration agent
The **recon agent** takes probe's AssetMap and decides how to explore further. It
reasons about which parts of the surface are worth investigating and drives the
relevant MCP tools for the job — `ffuf` for content and parameter discovery,
crawlers for deeper routes, and the other tools on the server — then reads what
they return and summarizes it into **findings**: the concrete leads worth testing.

### 3. Vuln — hypothesis matching (RAG)
For each finding, the **vuln agent** runs a retrieval-augmented pass over a vector
database of security knowledge — the **HackTricks** corpus, for now. It pulls the
techniques relevant to that finding and proposes candidate **vulnerability
hypotheses**: what might be wrong at this point in the app, and how you would test
it. Speculation is welcome here — the next stage is what separates a real
vulnerability from a guess.

### 4. Exploit — the proof loop
The **exploit agent** turns hypotheses into attempts. It runs an agentic loop:
reason about the target, call an MCP tool against it (an HTTP request, `sqlmap`, an
XSS attempt, …), read what came back, and decide the next move — iterating until it
has exploited and proven the vulnerability, or ruled it out.

The loop is not a blind retry. It carries **hints and guidance** that steer the
agent's tool calls: coaching drawn from what has already been tried, nudges away
from dead ends and repeated calls, the exact request a finding sits on, and
context about the target's stack. That guidance is what makes the agent converge
on a working exploit instead of flailing — and what lets it recognize when a
hypothesis simply does not hold.

### 5. Script & sandbox — proof-of-concept, safely
For a proven vulnerability, APTS can produce a proof-of-concept script and run it
inside a **hardened sandbox** — an isolated execution environment that keeps
untrusted, attack-shaped code away from your host. PoC code runs contained, never
on your machine.

### 6. Reporting
The **reporting agent** compiles the proven findings into a client-facing report:
it groups related findings, ranks them by severity and impact, attaches the
evidence (the requests and responses that proved each one), maps them to MITRE
ATT&CK, and writes remediation guidance.

---

## How it's built

- **Agents over tools.** Each stage is an agentic loop over an LLM. The agent
  thinks, calls a tool, reads the result, and decides the next move.
- **Tools over MCP.** The security tooling — crawlers, `ffuf`, `sqlmap`, the
  knowledge base, the sandbox, and more — lives behind a native **Model Context
  Protocol (MCP)** server, so the agents are decoupled from the tools they drive.
- **Structured artifacts.** Stages pass typed artifacts (AssetMap → findings →
  hypotheses → proofs → report), so results stay machine-readable the whole way.
- **Two ways to run it.** As a single-process pipeline (the `apts` runner), or
  driven by an AI coding agent (Claude Code / Codex) that calls the stages and
  tools over MCP.

---

## Quick start

**Prerequisites:** Docker + `docker compose`, Python 3.11+, and an LLM API key
(an OpenAI-compatible endpoint; the pipeline is provider-agnostic).

```bash
./scripts/setup.sh          # venv + dependencies + local secrets/certs
make up                     # start the tools server + database (containers)
# start a target to test (e.g. a local OWASP Juice Shop), then:
apts run --target http://TARGET:PORT --scope TARGET
```

Run without a database (ephemeral, nothing persisted):

```bash
apts run --target http://TARGET:PORT --scope TARGET --storage memory
```

### Drive it from Claude Code / Codex
The repo ships an `.mcp.json`, so an AI coding agent picks up the APTS tools
automatically. Ask it to recon or pentest a target and it drives the stages for
you. See [CLAUDE.md](CLAUDE.md) for the full flow.

---

## Project layout

| Path | What's there |
|------|--------------|
| `apts/` | The runner and entry points — the single-process pipeline + the MCP control server |
| `agent/services/workers/` | The stage agents (recon, vuln, exploit, …) |
| `mcp_native/` | The MCP tools server (crawlers, ffuf, sqlmap, knowledge base, sandbox) |
| `shared/` | Shared core — pipeline definition, data models, LLM client, scope rules |
| `.claude/` | Claude Code subagents and the pentest skill |
| `docker-compose.lean.yml` | The lean stack: tools server + database |
| `Makefile` | `setup`, `up`, `run`, `serve`, … |

---

## Safety & scope

APTS is for **authorized** testing only. Every outbound request is scope-checked,
credentials only ever reach in-scope hosts, and proof-of-concept code runs in the
sandbox. Only ever point it at a target you have permission to assess.

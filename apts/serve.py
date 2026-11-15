"""Harness entry point: an MCP control server wired to the in-process Runner.

This is the launchable twin of ``orchestrator/mcp_control.py``. That module is
the control surface for the networked full stack — its ``create_engagement`` /
``resume_engagement`` dispatch over mTLS HTTP to the agent microservices. This
module serves the SAME shape of control surface, but drives the single-process
:class:`apts.runner.Runner` directly, so Claude Code (or any MCP client) connects
over MCP and has full runtime control of a run that happens inside this process.

    python -m apts.serve [--port 9100] [--storage postgres|memory]

Two groups of tools are registered:

1. **Core control tools — storage-backed, work in BOTH postgres and memory**
   (``create_engagement``, ``engagement_status``, ``list_artifacts``,
   ``get_artifact``, ``get_report``, ``stop_engagement``, ``resume_engagement``).
   These are defined here. The control server and the Runner share ONE storage
   instance (selected by ``APTS_STORAGE``), so a run's status and artifacts are
   readable in-process — even in memory mode, where nothing is persisted.

2. **Rich query tools — DB-backed, reused from ``orchestrator.mcp_control`` as is**
   (``apts_capabilities``, ``list_engagements``, ``get_directives``, ``get_loot``,
   ``get_recon_findings`` / ``_summary`` / ``_peek``, ``get_probe_summary``,
   ``search_run``). They query Postgres directly, so they are **postgres-mode
   only**; in memory mode they have no database to read. Their logic is not
   duplicated — they are imported and re-registered unchanged.

Import discipline. The MCP transport (``mcp.server.mcpserver.MCPServer``) and the
DB-backed tool module are imported **lazily**, only inside :func:`build_server` /
:func:`serve`. Importing ``apts.serve`` itself pulls in nothing heavier than
pydantic, so the control logic can be exercised with fakes and no
langchain / mcp / database present — which is exactly what the harness proof test
does.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from typing import Any, Callable
from uuid import UUID, uuid4

from shared.models import Scope
from shared.pipeline import CHAIN
from apts.runner import Runner, RunSpec
from apts.storage import MemoryStorage, PostgresStorage, get_storage

log = logging.getLogger("apts.serve")

ARTIFACT_CHARS = 8000  # cap a returned artifact so it never floods the chat model


# --------------------------------------------------------------------------- #
# The control object: shared storage + the Runner tasks it launches
# --------------------------------------------------------------------------- #

class HarnessControl:
    """Drives the in-process Runner and exposes the core control tools.

    One instance owns one storage backend and the set of background
    ``engagement_id -> asyncio.Task`` runs launched against it. Because the Runner
    is handed this same storage, everything a run writes (artifacts, per-stage
    status) is immediately visible to the control tools here — no second source of
    truth to reconcile.
    """

    def __init__(self, storage: Any = None, *,
                 runner_factory: Callable[[Any], Runner] | None = None,
                 use_model_directives: bool = True) -> None:
        self._storage = storage if storage is not None else get_storage()
        self._runner_factory = runner_factory
        self._use_model_directives = use_model_directives
        self._tasks: dict[str, asyncio.Task] = {}
        # In-process view of each engagement the control server knows about:
        # target, overall status, and (for a finished run) its RunResult/error.
        self._meta: dict[str, dict[str, Any]] = {}

    # -- helpers ------------------------------------------------------------ #

    @property
    def storage(self) -> Any:
        return self._storage

    @staticmethod
    def _uuid(value: str) -> UUID | None:
        try:
            return UUID(str(value))
        except (ValueError, TypeError):
            return None

    def _runner(self) -> Runner:
        if self._runner_factory is not None:
            return self._runner_factory(self._storage)
        return Runner(self._storage, use_model_directives=self._use_model_directives)

    def task_for(self, engagement_id: str) -> asyncio.Task | None:
        return self._tasks.get(str(engagement_id))

    # -- core tools --------------------------------------------------------- #

    async def create_engagement(
        self,
        target_url: str,
        domains: list[str],
        allow_paths: list[str] | None = None,
        deny_paths: list[str] | None = None,
        objective: str | None = None,
        token: str | None = None,
        credentials: dict[str, Any] | None = None,
        scan_mode: str = "default",
        stop_after: str = "",
    ) -> dict[str, Any]:
        """Build the RunSpec, launch ``Runner.run`` as a tracked background task,
        and return the new engagement_id immediately (the run proceeds in the
        background; poll it with ``engagement_status``).

        Args:
            target_url: Target base URL, e.g. "http://app.example.com/".
            domains: In-scope hosts; must cover the target host.
            allow_paths / deny_paths: Optional path-prefix allow/deny lists.
            objective: Optional free-text brief folded into every stage's directive.
            token: Optional bearer token — sent to in-scope hosts as an
                Authorization header and a "token" cookie (a convenience over
                building ``credentials`` by hand).
            credentials: Optional {"headers":{...},"cookies":[...],"basic_auth":{...}}.
            scan_mode: recon breadth — default | thorough | page.
            stop_after: pause the pipeline — '' | probe | recon.
        """
        scan_mode = (scan_mode or "default").strip().lower()
        if scan_mode not in ("default", "thorough", "page"):
            return {"error": f"scan_mode must be default|thorough|page, got {scan_mode!r}"}
        stop_after = (stop_after or "").strip().lower()
        if stop_after not in ("", "probe", "recon"):
            return {"error": f"stop_after must be ''|probe|recon, got {stop_after!r}"}
        if not target_url or not str(target_url).strip():
            return {"error": "target_url is required"}
        if not domains:
            return {"error": "at least one in-scope domain is required"}

        creds: dict[str, Any] = dict(credentials or {})
        if token:
            token = token.strip()
            headers = dict(creds.get("headers") or {})
            headers.setdefault("Authorization", f"Bearer {token}")
            cookies = list(creds.get("cookies") or [])
            if not any((c or {}).get("name") == "token" for c in cookies):
                cookies.append({"name": "token", "value": token})
            creds["headers"] = headers
            creds["cookies"] = cookies

        engagement_id = uuid4()
        key = str(engagement_id)
        spec = RunSpec(
            target_url=str(target_url),
            scope=Scope(domains=domains or [], allow_paths=allow_paths or [],
                        deny_paths=deny_paths or []),
            objective=(objective or "").strip(),
            credentials=creds,
            scan_mode=scan_mode,
            stop_after=stop_after,
            engagement_id=engagement_id,
        )
        self._meta[key] = {"engagement_id": key, "target_url": spec.target_url,
                           "objective": spec.objective, "status": "running",
                           "scan_mode": scan_mode, "stop_after": stop_after,
                           "error": None, "result": None}

        task = asyncio.create_task(self._run(key, spec))
        self._tasks[key] = task

        return {"engagement_id": key, "status": "running",
                "message": "Engagement started; the pipeline is running in-process."}

    async def _run(self, key: str, spec: RunSpec) -> None:
        """Background body: run the pipeline, then record the outcome in meta."""
        meta = self._meta[key]
        try:
            result = await self._runner().run(spec)
            meta["result"] = result
            meta["status"] = {"complete": "completed", "paused": "paused",
                              "failed": "failed"}.get(result.status, result.status)
            if result.status == "failed":
                meta["error"] = result.reason
        except asyncio.CancelledError:
            # stop_engagement cancelled us; the status is set there. Swallow so the
            # task ends cleanly (a background task with no awaiter).
            meta["status"] = "cancelled"
            return
        except Exception as exc:  # noqa: BLE001 — surface, don't crash the server
            log.exception("engagement %s failed: %s", key, exc)
            meta["status"] = "failed"
            meta["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            # Push this engagement's buffered Langfuse spans promptly rather than
            # waiting on the exporter's batch timer (no-op when Langfuse is off).
            try:
                from shared.llm import flush
                flush()
            except Exception:  # noqa: BLE001 — observability must never break a run
                pass

    async def engagement_status(self, engagement_id: str) -> dict[str, Any]:
        """Overall status + which stages are done / running, from shared storage."""
        eid = self._uuid(engagement_id)
        if eid is None:
            return {"error": f"not a valid engagement id: {engagement_id!r}"}
        key = str(eid)
        done = self._storage.completed_stages(eid)
        statuses = self._storage.stage_statuses(eid)
        meta = self._meta.get(key)
        if meta is None and not done and not statuses:
            # Unknown to this process and nothing in the store either.
            fallback = self._db_overall(eid)
            if fallback is None:
                return {"error": f"no such engagement: {engagement_id}"}
            meta = fallback
        per_agent: dict[str, str] = {}
        for a in CHAIN:
            per_agent[a] = "done" if a in done else statuses.get(a, "pending")
        current = next((a for a in CHAIN
                        if per_agent[a] in ("started", "running")), None)
        overall = (meta or {}).get("status") or self._derive_overall(eid, done)
        return {"engagement_id": key,
                "target_url": (meta or {}).get("target_url"),
                "status": overall, "current_agent": current,
                "per_agent": per_agent, "completed": list(done),
                "error": (meta or {}).get("error")}

    def _derive_overall(self, eid: UUID, done: list[str]) -> str:
        if CHAIN and CHAIN[-1] in done:
            return "completed"
        return "unknown"

    def _db_overall(self, eid: UUID) -> dict[str, Any] | None:
        """Postgres-only fallback: read the engagement row so a restarted harness
        can still answer status for a run it did not itself launch."""
        if not isinstance(self._storage, PostgresStorage):
            return None
        try:
            from shared.db import get_conn
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT target_url, status FROM engagements WHERE id=%s",
                            (str(eid),))
                row = cur.fetchone()
            if row is None:
                return None
            status = {"complete": "completed", "running": "running",
                      "failed": "failed", "cancelled": "cancelled"}.get(row[1], row[1])
            return {"engagement_id": str(eid), "target_url": row[0],
                    "status": status, "error": None}
        except Exception:  # noqa: BLE001
            return None

    async def list_artifacts(self, engagement_id: str) -> dict[str, Any]:
        """List which stages have produced an artifact (in pipeline order) + sizes."""
        eid = self._uuid(engagement_id)
        if eid is None:
            return {"error": f"not a valid engagement id: {engagement_id!r}"}
        artifacts = []
        for agent in CHAIN:
            payload = self._storage.load(eid, agent)
            if payload is None:
                continue
            artifacts.append({"agent": agent,
                              "size_chars": len(json.dumps(payload, default=str))})
        return {"engagement_id": str(eid), "artifacts": artifacts}

    async def get_artifact(self, engagement_id: str, agent: str,
                           query: str | None = None) -> dict[str, Any]:
        """Fetch one stage's stored artifact — whole, or only the items matching
        ``query`` (case-insensitive) when the artifact is large."""
        eid = self._uuid(engagement_id)
        if eid is None:
            return {"error": f"not a valid engagement id: {engagement_id!r}"}
        if agent not in CHAIN:
            return {"error": f"unknown stage {agent!r}; expected one of {CHAIN}"}
        payload = self._storage.load(eid, agent)
        if payload is None:
            return {"error": f"{agent} has produced no artifact yet for this engagement"}
        summary = ", ".join(f"{len(v)} {k}" for k, v in payload.items()
                            if isinstance(v, (list, dict)) and v) or "empty artifact"
        if query:
            matches = _search_artifact(payload, query)
            return {"engagement_id": str(eid), "agent": agent, "summary": summary,
                    "query": query, "match_count": len(matches), "matches": matches}
        text = json.dumps(payload, default=str)
        truncated = len(text) > ARTIFACT_CHARS
        return {"engagement_id": str(eid), "agent": agent, "summary": summary,
                "truncated": truncated,
                "hint": ("artifact truncated — call again with query=<text> to search it"
                         if truncated else None),
                "artifact": payload if not truncated else text[:ARTIFACT_CHARS]}

    async def get_report(self, engagement_id: str) -> dict[str, Any]:
        """Return the adviser's client report as Markdown (from shared storage)."""
        eid = self._uuid(engagement_id)
        if eid is None:
            return {"error": f"not a valid engagement id: {engagement_id!r}"}
        payload = self._storage.load(eid, "adviser")
        if payload is None:
            return {"error": "no report yet — the adviser stage has not produced one"}
        try:
            from agent.services.report_renderer import render_markdown
            from shared.models import EngagementReport
            md = render_markdown(EngagementReport(**payload))
            return {"engagement_id": str(eid), "format": "markdown", "markdown": md}
        except Exception as exc:  # noqa: BLE001 — fall back to the raw artifact
            log.warning("could not render report for %s: %s", eid, exc)
            return {"engagement_id": str(eid), "format": "json", "report": payload,
                    "note": f"markdown render unavailable ({type(exc).__name__})"}

    async def stop_engagement(self, engagement_id: str) -> dict[str, Any]:
        """Cancel the background run and mark the engagement cancelled.

        Cooperative: a stage already executing runs to completion inside the
        worker, but the pipeline advances no further."""
        eid = self._uuid(engagement_id)
        if eid is None:
            return {"error": f"not a valid engagement id: {engagement_id!r}"}
        key = str(eid)
        meta = self._meta.get(key)
        if meta is None:
            return {"error": f"no such engagement: {engagement_id}"}
        if meta["status"] not in ("running", "paused"):
            return {"engagement_id": key, "status": meta["status"],
                    "message": f"engagement was already {meta['status']}; nothing to stop"}
        task = self._tasks.get(key)
        if task is not None and not task.done():
            task.cancel()
        meta["status"] = "cancelled"
        meta["error"] = None
        done = set(self._storage.completed_stages(eid))
        for agent in CHAIN:
            if agent not in done:
                self._storage.record_status(eid, agent, "cancelled")
        return {"engagement_id": key, "status": "cancelled",
                "message": "Engagement cancelled; no further stages will run."}

    async def resume_engagement(self, engagement_id: str) -> dict[str, Any]:
        """Resume a run, skipping already-completed stages.

        Postgres only: resume replays from the persisted store, so it needs a
        durable backend. In memory mode nothing persists, so there is nothing to
        resume — a clear message is returned instead.
        """
        eid = self._uuid(engagement_id)
        if eid is None:
            return {"error": f"not a valid engagement id: {engagement_id!r}"}
        key = str(eid)
        if isinstance(self._storage, MemoryStorage):
            return {"engagement_id": key, "status": "unsupported",
                    "message": ("resume is postgres-only: the memory backend persists "
                                "nothing across a run, so there is no stored state to "
                                "resume. Start the harness with --storage postgres.")}
        task = self._tasks.get(key)
        if task is not None and not task.done():
            return {"engagement_id": key, "status": "running",
                    "message": "engagement is still running; nothing to resume"}
        spec = self._spec_for_resume(eid)
        if spec is None:
            return {"error": f"cannot resume {engagement_id}: no stored engagement found"}
        self._meta[key] = {"engagement_id": key, "target_url": spec.target_url,
                           "objective": spec.objective, "status": "running",
                           "scan_mode": spec.scan_mode, "stop_after": spec.stop_after,
                           "error": None, "result": None}
        task = asyncio.create_task(self._run(key, spec))
        self._tasks[key] = task
        done = self._storage.completed_stages(eid)
        return {"engagement_id": key, "status": "resumed",
                "skipping": list(done),
                "message": f"resumed; skipping already-completed stages: {', '.join(done) or '(none)'}"}

    def _spec_for_resume(self, eid: UUID) -> RunSpec | None:
        """Reconstruct the RunSpec for a resume — from in-process meta if we still
        have it, else from the persisted ``engagements`` row (postgres)."""
        meta = self._meta.get(str(eid))
        if meta is not None and meta.get("result") is not None:
            # We launched it this process; rebuild from meta (+ scope from the store
            # is not needed — the completed stages drive what runs next).
            return RunSpec(target_url=meta["target_url"], scope=Scope(),
                           objective=meta.get("objective", ""),
                           scan_mode=meta.get("scan_mode", "default"),
                           stop_after=meta.get("stop_after", ""), engagement_id=eid)
        try:
            from shared.db import get_conn
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT target_url, scope, objective, credentials "
                            "FROM engagements WHERE id=%s", (str(eid),))
                row = cur.fetchone()
            if row is None:
                return None
            target_url, scope, objective, credentials = row
            return RunSpec(target_url=target_url,
                           scope=Scope(**(scope or {})),
                           objective=objective or "",
                           credentials=credentials or {},
                           engagement_id=eid)
        except Exception as exc:  # noqa: BLE001
            log.warning("resume spec reconstruction failed for %s: %s", eid, exc)
            return None


# --------------------------------------------------------------------------- #
# Module-level control singleton + the thin tool wrappers that get registered
# --------------------------------------------------------------------------- #

# The one control instance the registered tools delegate to. ``serve`` / tests set
# it; a wrapper called before then lazily makes one over the default storage.
control: HarnessControl | None = None


def get_control() -> HarnessControl:
    global control
    if control is None:
        control = HarnessControl(get_storage())
    return control


async def create_engagement(target_url: str, domains: list[str],
                            allow_paths: list[str] | None = None,
                            deny_paths: list[str] | None = None,
                            objective: str | None = None, token: str | None = None,
                            credentials: dict[str, Any] | None = None,
                            scan_mode: str = "default", stop_after: str = "") -> dict[str, Any]:
    """Validate parameters, create the engagement, and start the in-process pipeline."""
    return await get_control().create_engagement(
        target_url, domains, allow_paths, deny_paths, objective, token,
        credentials, scan_mode, stop_after)


async def engagement_status(engagement_id: str) -> dict[str, Any]:
    """Report overall + per-stage status of an engagement (from shared storage)."""
    return await get_control().engagement_status(engagement_id)


async def list_artifacts(engagement_id: str) -> dict[str, Any]:
    """List which stages have produced an artifact, with sizes."""
    return await get_control().list_artifacts(engagement_id)


async def get_artifact(engagement_id: str, agent: str,
                       query: str | None = None) -> dict[str, Any]:
    """Fetch one stage's artifact — whole, or pass query=<text> to search a large one."""
    return await get_control().get_artifact(engagement_id, agent, query)


async def get_report(engagement_id: str) -> dict[str, Any]:
    """Return the adviser client report as Markdown."""
    return await get_control().get_report(engagement_id)


async def stop_engagement(engagement_id: str) -> dict[str, Any]:
    """Cancel an engagement (cooperative stop)."""
    return await get_control().stop_engagement(engagement_id)


async def resume_engagement(engagement_id: str) -> dict[str, Any]:
    """Resume a run, skipping completed stages (postgres only)."""
    return await get_control().resume_engagement(engagement_id)


async def apts_health() -> dict[str, Any]:
    """Check the harness backend before running: is the DB and the tools server up?

    Call this first if another tool errors. It reports whether the storage DB and
    the mcp-native tools container are reachable, so a backend that is not running
    (`make up`) shows up as a clear status instead of an opaque tool failure.
    """
    out: dict[str, Any] = {"storage": (os.environ.get("APTS_STORAGE") or "postgres").lower()}
    if out["storage"] == "postgres":
        try:
            from shared.db import get_conn
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
            out["database"] = "ok"
        except Exception as exc:  # noqa: BLE001
            out["database"] = f"unreachable: {type(exc).__name__}: {str(exc)[:120]}"
    else:
        out["database"] = "n/a (memory mode)"
    url = os.environ.get("APTS_MCP_URL", "")
    out["tools_url"] = url
    if url:
        try:
            import httpx
            r = httpx.get(url, timeout=5.0)
            # Any HTTP status means the server answered — the /mcp endpoint returns
            # 400/406 to a plain GET, so reachability (not the code) is the signal.
            out["tools"] = f"reachable (HTTP {r.status_code})"
        except Exception as exc:  # noqa: BLE001
            out["tools"] = f"unreachable: {type(exc).__name__}: {str(exc)[:120]}"
    else:
        out["tools"] = "APTS_MCP_URL not set"
    out["ready"] = (out["database"] in ("ok", "n/a (memory mode)")
                    and str(out["tools"]).startswith("reachable"))
    if not out["ready"]:
        out["hint"] = "Backend not fully up. Run `make up` (starts Postgres + mcp-native)."
    return out


def _search_artifact(payload: dict, query: str, limit: int = 25) -> list[dict]:
    """Items from the artifact's list sections whose JSON contains ``query``."""
    q = query.lower()
    matches: list[dict] = []
    for key, value in payload.items():
        if isinstance(value, list):
            for item in value:
                if q in json.dumps(item, default=str).lower():
                    matches.append({"section": key, "item": item})
                    if len(matches) >= limit:
                        return matches
        elif isinstance(value, (str, int, float)) and q in str(value).lower():
            matches.append({"section": key, "item": value})
    return matches[:limit]


# --------------------------------------------------------------------------- #
# The tool registry (names available WITHOUT importing mcp or the DB tools)
# --------------------------------------------------------------------------- #

# Core, storage-backed control tools defined in this module.
CORE_TOOLS: dict[str, str] = {
    "apts_health": ("Check the backend is up (storage DB + mcp-native tools server) "
                    "before running. Call this first if another tool errors."),
    "create_engagement": ("Validate parameters, create the engagement, and start "
                          "the in-process pipeline (returns the engagement_id)."),
    "engagement_status": ("Report overall + per-stage status of an engagement, "
                          "from the shared storage (works in memory and postgres)."),
    "list_artifacts": "List which stages have produced an artifact, with sizes.",
    "get_artifact": ("Fetch one stage's artifact — whole, or query=<text> to return "
                     "only matching items from a large artifact."),
    "get_report": "Return the adviser client report as Markdown.",
    "stop_engagement": "Cancel an engagement's background run (cooperative stop).",
    "resume_engagement": ("Resume a run, skipping already-completed stages "
                          "(postgres only)."),
}

# Rich query tools reused verbatim from orchestrator.mcp_control. DB-backed →
# postgres-mode only. Names/descriptions are listed here so the registry is known
# without importing that (mcp- and DB-touching) module.
DB_TOOLS: dict[str, str] = {
    "apts_capabilities": "Explain what APTS can do and which parameters a run needs.",
    "list_engagements": "List recent engagements (newest first) with ids and status.",
    "get_directives": ("Show the directive each stage was dispatched with, plus the "
                       "objective — audit how steering shaped the run."),
    "get_loot": ("Return the exploit stage's collected loot (credentials, tokens, DB "
                 "info, ...) with full values."),
    "get_recon_findings": ("Return recon's graded findings, highest grade first; "
                           "grade= to filter."),
    "get_recon_summary": "Return recon's attack-surface summary + surface counts.",
    "get_recon_peek": ("Return recon's Phase-0.5 peek behaviour map (per route: "
                       "inputs, buttons, on-load XHR)."),
    "get_probe_summary": ("Return the Phase-0/0.5 surface map (summary, counts, API "
                          "paths, peek) a probe/recon produced."),
    "search_run": ("Search the full raw run data (artifacts + execution trace) for a "
                   "substring and return the surrounding text."),
}

# Every tool name the harness server registers. DB-backed tools are reused as-is.
ALL_TOOL_NAMES: list[str] = list(CORE_TOOLS) + list(DB_TOOLS)

_CORE_FNS: dict[str, Callable] = {
    "apts_health": apts_health,
    "create_engagement": create_engagement,
    "engagement_status": engagement_status,
    "list_artifacts": list_artifacts,
    "get_artifact": get_artifact,
    "get_report": get_report,
    "stop_engagement": stop_engagement,
    "resume_engagement": resume_engagement,
}


# --------------------------------------------------------------------------- #
# Build + serve (lazy imports: mcp and the DB-tool module only touched here)
# --------------------------------------------------------------------------- #

def build_server(storage: Any = None, *, include_db_tools: bool = True,
                 name: str = "apts-harness-control"):
    """Create the MCP server, register the core tools (and, when available, the
    DB-backed query tools), and return ``(server, registered_tool_names)``.

    Importing ``mcp`` and ``orchestrator.mcp_control`` happens here, not at module
    import, so ``apts.serve`` stays importable with only pydantic installed.
    """
    from mcp.server.mcpserver import MCPServer

    global control
    if storage is not None:
        control = HarnessControl(storage)
    elif control is None:
        control = get_control()

    server = MCPServer(
        name=name,
        instructions=("Control an in-process APTS engagement: create it, check "
                      "status, read each stage's artifact, stop or resume it. The "
                      "core tools work in memory or postgres mode; the recon/loot/"
                      "directive/search query tools are postgres-mode only."),
    )
    registered: list[str] = []
    for nm, desc in CORE_TOOLS.items():
        server.tool(description=desc)(_CORE_FNS[nm])
        registered.append(nm)

    if include_db_tools:
        try:
            from orchestrator import mcp_control as mc  # imports mcp + touches DB
            for nm, desc in DB_TOOLS.items():
                fn = getattr(mc, nm, None)
                if fn is None:
                    continue
                server.tool(description=desc)(fn)
                registered.append(nm)
        except Exception as exc:  # noqa: BLE001 — DB tools are optional (postgres only)
            log.warning("DB-backed query tools not registered (%s): core tools only",
                        exc)

    log.info("apts harness control tools: %s", ", ".join(registered))
    return server, registered


def serve(port: int | None = None, storage_kind: str | None = None, *,
          include_db_tools: bool = True, host: str | None = None,
          transport: str = "http") -> None:
    """Build and run the harness MCP control server.

    ``transport="stdio"`` speaks MCP over stdin/stdout — the mode Claude Code (or
    any MCP client that spawns a subprocess) uses. ``transport="http"`` (default)
    serves streamable-HTTP on ``host:port``.

    Defaults to postgres (the real path for long, resumable runs); pass
    ``storage_kind="memory"`` or ``--storage memory`` for a quick ephemeral run.
    """
    kind = (storage_kind or os.environ.get("APTS_STORAGE") or "postgres").strip().lower()
    storage = get_storage(kind)

    if isinstance(storage, PostgresStorage):
        try:
            from orchestrator.mcp_control import _ensure_schema
            _ensure_schema()  # idempotent column adds on an older DB
        except Exception as exc:  # noqa: BLE001 — never block startup on migration
            log.warning("schema ensure skipped: %s", exc)

    global control
    control = HarnessControl(storage)
    server, registered = build_server(storage=storage, include_db_tools=include_db_tools)

    if transport == "stdio":
        # Claude Code (or any MCP client) spawns this process and speaks MCP over
        # stdin/stdout. Logs already go to stderr (see main), so they never corrupt
        # the protocol channel.
        log.info("serving apts harness control MCP over stdio (storage=%s, tools=%d)",
                 kind, len(registered))
        server.run(transport="stdio")
        return

    port = port or int(os.environ.get("APTS_CONTROL_MCP_PORT", "9100"))
    # Loopback by default: the control server drives real scans, so it must not be
    # reachable from the network unless the operator explicitly opts in with --host.
    host = host or os.environ.get("APTS_CONTROL_MCP_HOST", "127.0.0.1")
    log.info("serving apts harness control MCP on %s:%d (storage=%s, tools=%d)",
             host, port, kind, len(registered))
    server.run(transport="streamable-http", host=host, port=port)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="apts.serve",
        description="Serve the APTS harness MCP control server (drives the in-process Runner).")
    parser.add_argument("--port", type=int, default=None,
                        help="port to serve on (default APTS_CONTROL_MCP_PORT or 9100)")
    parser.add_argument("--storage", choices=["postgres", "memory"], default=None,
                        help="storage backend; overrides APTS_STORAGE (harness default: postgres)")
    parser.add_argument("--no-db-tools", action="store_true",
                        help="register only the core control tools (skip the DB-backed query tools)")
    parser.add_argument("--host", default=None,
                        help="bind address for http transport (default APTS_CONTROL_MCP_HOST "
                             "or 127.0.0.1 — loopback; pass 0.0.0.0 to expose on all interfaces)")
    parser.add_argument("--transport", choices=["stdio", "http"], default="http",
                        help="stdio = spawned by an MCP client (Claude Code); "
                             "http = streamable-HTTP on host:port (default)")
    args = parser.parse_args(argv)

    import logging as _logging
    import sys as _sys
    # Logs MUST go to stderr: on stdio transport, stdout is the MCP protocol channel.
    _logging.basicConfig(level=_logging.INFO, stream=_sys.stderr)
    serve(port=args.port, storage_kind=args.storage,
          include_db_tools=not args.no_db_tools, host=args.host, transport=args.transport)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

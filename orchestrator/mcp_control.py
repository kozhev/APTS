"""The orchestrator's control surface, as a native MCP server.

This is what the Composer (and any MCP client) drives to run APTS end to end
without touching an agent directly: describe capabilities, create an engagement,
check its status, stop it, and read back the artifacts each stage produced. It
runs inside the orchestrator container as a third server (alongside the public
:8443 and admin :8080 FastAPI apps), so "the orchestrator is the single
interface and controller" holds literally.

Deliberately self-contained. The tools talk to the shared store with their own
connections and do the recon kickoff with their own HTTP client, rather than
reaching into ``orchestrator.main``'s runtime globals — those belong to the
public app's event loop, and this server runs in its own thread with its own
loop. The small amount of duplicated SQL (the engagement + per-agent seed) is
the price of that isolation; the pipeline shape still comes from
``shared.pipeline`` so the two cannot disagree about the chain.

Cancellation is cooperative: ``stop_engagement`` marks the engagement (and its
not-yet-finished stages) cancelled, and the orchestrator's driven advancement
refuses to launch the next stage once an engagement is no longer ``running``. A
stage already executing runs to completion; its result is simply not advanced.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from shared import pipeline, trace
from shared.db import audit, get_conn

log = logging.getLogger("orchestrator.mcp_control")

CHAIN = list(pipeline.CHAIN)
ARTIFACT_CHARS = 8000  # cap a returned artifact so it never floods the chat model


# --------------------------------------------------------------------------- #
# Small store helpers (own connections; safe from this server's own loop)
# --------------------------------------------------------------------------- #

def _uuid(value: str) -> UUID | None:
    try:
        return UUID(str(value))
    except (ValueError, TypeError):
        return None


def _ensure_schema() -> None:
    """Idempotently add columns introduced after the initial schema.

    A DB created before ``engagements.objective`` existed keeps working without a
    manual reinit. Runs at import and again from the orchestrator's lifespan; both
    are guarded by ``IF NOT EXISTS`` so repeating is a no-op. Never blocks startup —
    a migration failure is logged and the run proceeds (objective stays empty)."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("ALTER TABLE engagements "
                        "ADD COLUMN IF NOT EXISTS objective TEXT NOT NULL DEFAULT ''")
            cur.execute("ALTER TABLE engagements ADD COLUMN IF NOT EXISTS "
                        "credentials JSONB NOT NULL DEFAULT '{}'")
    except Exception as exc:  # noqa: BLE001 — never block startup on a migration
        log.warning("schema migration (engagements columns) skipped: %s", exc)


def _status(engagement_id: UUID) -> dict[str, Any] | None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT target_url, status, created_at, completed_at "
            "FROM engagements WHERE id = %s", (str(engagement_id),))
        row = cur.fetchone()
        if not row:
            return None
        target_url, status, created_at, completed_at = row
        cur.execute(
            "SELECT agent, status, retry_count, last_error "
            "FROM engagement_state WHERE engagement_id = %s", (str(engagement_id),))
        per_agent = {a: {"status": s, "retry_count": rc, "last_error": err}
                     for a, s, rc, err in cur.fetchall()}
    # Present the stages in pipeline order, and name the one running now.
    ordered = {a: per_agent.get(a, {"status": "pending"}) for a in CHAIN}
    current = next((a for a in CHAIN
                    if ordered[a]["status"] in ("started", "running")), None)
    return {"engagement_id": str(engagement_id), "target_url": target_url,
            "status": status, "current_agent": current, "per_agent": ordered,
            "created_at": str(created_at) if created_at else None,
            "completed_at": str(completed_at) if completed_at else None}


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

async def apts_capabilities() -> dict[str, Any]:
    """Explain what APTS is and what it needs to start an engagement.

    Call this to answer "what can you do?" and to know which parameters to
    collect from the user before creating an engagement."""
    return {
        "summary": ("APTS is an AI-agentic penetration-testing pipeline for web "
                    "targets. You (the orchestrator) are the only interface: the "
                    "user talks to you, and you drive the agents. You can run the "
                    "FULL pipeline, or stop short of exploiting: PROBE the site "
                    "(map the attack surface, no findings), or RECON only (graded "
                    "recon findings, no exploitation) — both resume later with "
                    "resume_engagement. You can also scope a run to a single PAGE. "
                    "Offer these when a user only wants to look, not attack."),
        "pipeline": [
            {"stage": "recon", "does": "crawl the target and map the attack surface"},
            {"stage": "vuln", "does": "hypothesise concrete, testable weaknesses"},
            {"stage": "mitre", "does": "map each weakness to MITRE ATT&CK techniques"},
            {"stage": "exploit", "does": "prove or disprove each weakness on the live target"},
            {"stage": "adviser", "does": "produce the grouped, impact-ranked client report"},
        ],
        "required_to_start": {
            "target_url": "the target's base URL, e.g. http://app.example.com/",
            "domains": "in-scope host(s); must cover the target host",
        },
        "optional": {
            "objective": "free-text brief steering the whole run (what to concentrate "
                         "on, ignore, or which vuln classes to emphasise); advisory, "
                         "does not narrow scope",
            "token": "access/bearer token for an authenticated run (sent to "
                     "in-scope hosts as a header and a cookie)",
            "allow_paths": "path prefixes to include",
            "deny_paths": "path prefixes to exclude",
            "scan_mode": "recon breadth: 'default' (normal), 'thorough' (deepest), or "
                         "'page' (crawl ONLY the target_url — pass the page itself as "
                         "target_url, e.g. http://host/#/login)",
            "stop_after": "pause for inspection: '' (full run), 'probe' (map the surface "
                          "only, no findings), or 'recon' (full recon then pause before "
                          "vuln). Resume with resume_engagement.",
        },
        "run_types": [
            {"name": "Probe", "what": "map the attack surface only — no findings, no "
             "exploitation; pauses for inspection",
             "how": "create_engagement(stop_after='probe'); then get_probe_summary; "
             "resume_engagement to continue"},
            {"name": "Recon only", "what": "graded recon findings, no exploitation; "
             "pauses before the vuln stage",
             "how": "create_engagement(stop_after='recon'); then get_recon_findings / "
             "get_recon_summary; resume_engagement to run vuln+exploit+report"},
            {"name": "Single page", "what": "test just one page/route",
             "how": "create_engagement(scan_mode='page', target_url=<the page, e.g. "
             ".../#/login>)"},
            {"name": "Full pentest", "what": "end to end: recon → vuln → exploit → "
             "report (default)",
             "how": "create_engagement()  (optionally scan_mode='thorough' for deepest)"},
        ],
        "note": "All run types are ONE create_engagement call — pick stop_after / "
                "scan_mode from what the user asks. Decide intent before calling.",
        "intent_hints": {
            "just probe the site / what's here": "create_engagement(stop_after='probe'); "
                "then get_probe_summary. resume_engagement to go further.",
            "crawl and show me the recon findings": "create_engagement(stop_after='recon'); "
                "then get_recon_findings / get_recon_summary. resume_engagement for vuln+.",
            "test this one page / this login page": "create_engagement(scan_mode='page', "
                "target_url=<the page, e.g. .../#/login>)",
            "deep / thorough scan": "create_engagement(scan_mode='thorough')",
            "focus on X / ignore Y": "pass it in objective (advisory steer)",
        },
        "actions": ["create_engagement", "resume_engagement", "list_engagements",
                    "engagement_status", "stop_engagement", "list_artifacts",
                    "get_artifact", "get_directives", "get_loot",
                    "get_recon_summary", "get_recon_findings", "get_recon_peek",
                    "get_probe_summary", "get_report", "search_run"],
    }


async def engagement_status(engagement_id: str) -> dict[str, Any]:
    """Report the current status of an engagement and each stage.

    Returns the overall status, which stage is running now (current_agent), and a
    per-agent map of pending/running/completed/failed/skipped/cancelled."""
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    status = _status(eid)
    return status or {"error": f"no such engagement: {engagement_id}"}


async def stop_engagement(engagement_id: str) -> dict[str, Any]:
    """Cancel an engagement. Cooperative: the running stage finishes but the
    pipeline advances no further, and remaining stages are marked cancelled."""
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE engagements SET status='cancelled', completed_at=NOW() "
            "WHERE id=%s AND status='running' RETURNING id", (str(eid),))
        if cur.fetchone() is None:
            cur.execute("SELECT status FROM engagements WHERE id=%s", (str(eid),))
            row = cur.fetchone()
            if row is None:
                return {"error": f"no such engagement: {engagement_id}"}
            return {"engagement_id": str(eid), "status": row[0],
                    "message": f"engagement was already {row[0]}; nothing to stop"}
        cur.execute(
            "UPDATE engagement_state SET status='cancelled', updated_at=NOW() "
            "WHERE engagement_id=%s AND status IN ('pending','started','running')",
            (str(eid),))
    audit("orchestrator", "engagement_cancelled", engagement_id=str(eid))
    trace.record_for(eid, "orchestrator", "engagement_cancelled", {})
    return {"engagement_id": str(eid), "status": "cancelled",
            "message": "Engagement cancelled; no further stages will run."}


async def list_engagements(limit: int = 10, status: str | None = None) -> dict[str, Any]:
    """List recent engagements, newest first — so you can find the latest one and
    its id without the user repeating it.

    Returns each engagement's id, target, status, current stage, and created_at,
    plus ``latest`` (the newest engagement's id). Call this whenever the user says
    "the latest", "my last run", "which engagements", or refers to one without an id.

    Args:
        limit: How many recent engagements to return (default 10).
        status: Optional filter — e.g. "running", "complete", "failed", "cancelled".
    """
    limit = max(1, min(int(limit or 10), 50))
    with get_conn() as conn, conn.cursor() as cur:
        if status:
            cur.execute("SELECT id, target_url, status, created_at FROM engagements "
                        "WHERE status=%s ORDER BY created_at DESC LIMIT %s",
                        (status, limit))
        else:
            cur.execute("SELECT id, target_url, status, created_at FROM engagements "
                        "ORDER BY created_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
    items = []
    for eid, target, st, created in rows:
        cur_agent = None
        if st == "running":
            s = _status(eid)
            cur_agent = s.get("current_agent") if s else None
        items.append({"engagement_id": str(eid), "target_url": target,
                      "status": st, "current_agent": cur_agent,
                      "created_at": str(created)})
    return {"engagements": items,
            "latest": items[0]["engagement_id"] if items else None,
            "count": len(items)}


async def list_artifacts(engagement_id: str) -> dict[str, Any]:
    """List which stages have produced an artifact, newest first, with sizes."""
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT agent, char_length(payload::text), written_at "
            "FROM agent_results WHERE engagement_id=%s ORDER BY written_at",
            (str(eid),))
        rows = cur.fetchall()
    return {"engagement_id": str(eid),
            "artifacts": [{"agent": a, "size_chars": n, "written_at": str(w)}
                          for a, n, w in rows]}


def _search_artifact(payload: dict, query: str, limit: int = 25) -> list[dict]:
    """Return items from the artifact's list-valued sections that match ``query``
    (case-insensitive substring over each item's JSON), tagged with their section."""
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


async def get_artifact(engagement_id: str, agent: str,
                       query: str | None = None) -> dict[str, Any]:
    """Fetch one stage's artifact — whole, or searched.

    Without ``query``: a short ``summary`` (member counts) plus the artifact,
    capped so a large result does not flood the conversation (``truncated`` flags it).
    With ``query``: only the items matching that text (across the artifact's list
    sections), so you can search a big artifact instead of paging the whole thing —
    e.g. get_artifact(id, "exploit", query="SQL") returns just the SQL findings.

    Args:
        engagement_id: The engagement's id.
        agent: The stage to read — one of recon, vuln, mitre, exploit, script, adviser.
        query: Optional case-insensitive text to search for within the artifact.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    if agent not in CHAIN:
        return {"error": f"unknown stage {agent!r}; expected one of {CHAIN}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT payload FROM agent_results WHERE engagement_id=%s AND agent=%s",
            (str(eid), agent))
        row = cur.fetchone()
    if row is None:
        return {"error": f"{agent} has produced no artifact yet for this engagement"}
    payload = row[0]
    summary = ", ".join(f"{len(v)} {k}" for k, v in payload.items()
                        if isinstance(v, (list, dict)) and v) or "empty artifact"
    if query:
        matches = _search_artifact(payload, query)
        return {"engagement_id": str(eid), "agent": agent, "summary": summary,
                "query": query, "match_count": len(matches), "matches": matches}
    text = json.dumps(payload, default=str)
    truncated = len(text) > ARTIFACT_CHARS
    # Full JSON object when it fits; otherwise a capped JSON string (the caller gets
    # the head of the artifact plus truncated=True — then use query= to search it).
    artifact: Any = payload if not truncated else text[:ARTIFACT_CHARS]
    return {"engagement_id": str(eid), "agent": agent, "summary": summary,
            "truncated": truncated,
            "hint": "artifact truncated — call again with query=<text> to search it"
                    if truncated else None,
            "artifact": artifact}


async def get_directives(engagement_id: str) -> dict[str, Any]:
    """Show the directive each stage was actually dispatched with, in order.

    This is how you audit steering: the operator gives ONE objective, and the
    orchestrator composes a directive per stage from it plus the previous stage's
    output. This returns the engagement's objective and each stage's composed
    directive (recon's from kickoff, the rest from each advance, plus any retry),
    so you can see how the objective shaped the run and compare it to what each
    agent did. Empty ``directives`` means the run has not advanced past that stage
    yet.

    Args:
        engagement_id: The engagement's id.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT objective FROM engagements WHERE id=%s", (str(eid),))
        row = cur.fetchone()
        if row is None:
            return {"error": f"no such engagement: {engagement_id}"}
        objective = row[0] or ""
        cur.execute(
            "SELECT event_type, payload FROM agent_trace WHERE engagement_id=%s "
            "AND event_type IN ('kickoff','advance','retry_launched') ORDER BY id",
            (str(eid),))
        rows = cur.fetchall()
    directives: list[dict[str, Any]] = []
    for event_type, payload in rows:
        payload = payload or {}
        directive = payload.get("directive")
        if not directive:
            continue
        # kickoff carries the recon directive; advance/retry name the target stage.
        stage = (payload.get("to") or payload.get("agent")
                 or ("recon" if event_type == "kickoff" else "?"))
        # A non-recon kickoff repeats the directive its 'advance' row already has,
        # so keep kickoff only for recon (the one stage with no advance row).
        if event_type == "kickoff" and stage != "recon":
            continue
        directives.append({"stage": stage, "event": event_type,
                           "directive": directive})
    return {"engagement_id": str(eid), "objective": objective,
            "directives": directives, "count": len(directives)}


async def get_loot(engagement_id: str) -> dict[str, Any]:
    """Return the interesting data the exploit stage collected, with FULL values.

    Loot is the model's labelled shortlist (credentials, tokens, DB type, user
    info, etc.); values are stored whole, so this is where you read a specific
    captured value in full. If a value still looks abbreviated (the model wrote it
    with an ellipsis), use search_run to pull the exact bytes from the raw
    transcript instead.

    Args:
        engagement_id: The engagement's id.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload->'loot' FROM agent_results "
                    "WHERE engagement_id=%s AND agent='exploit'", (str(eid),))
        row = cur.fetchone()
    if row is None:
        return {"error": "exploit has produced no artifact yet for this engagement"}
    loot = row[0] or []
    return {"engagement_id": str(eid), "count": len(loot), "loot": loot}


async def get_probe_summary(engagement_id: str) -> dict[str, Any]:
    """The Phase-0/0.5 surface map a probe (or any recon) produced: the summary, surface
    counts, the API/file paths, and the peek behaviour map (per route: inputs + on-load
    XHR). Use it to show "what's on this site" before/without grading findings.

    Args:
        engagement_id: The engagement's id.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload FROM agent_results "
                    "WHERE engagement_id = %s AND agent = 'recon'", (str(eid),))
        row = cur.fetchone()
    if row is None:
        return {"error": "recon has produced no artifact yet for this engagement"}
    p = row[0] or {}
    counts = {k: len(p.get(k) or []) for k in
              ("endpoints", "api_paths", "observed_requests", "findings", "peek")}
    return {"engagement_id": str(eid), "mode": p.get("mode"),
            "stop_after": p.get("stop_after", ""), "summary": p.get("summary", ""),
            "counts": counts, "api_paths": (p.get("api_paths") or [])[:80],
            "peek": p.get("peek", [])}


async def get_report(engagement_id: str) -> dict[str, Any]:
    """Return the adviser's client report rendered as Markdown — for the composer to
    OPEN it (render MD->HTML in a new window) and offer an .md / .html download. Empty
    with an error until the adviser stage has produced a report.

    Args:
        engagement_id: The engagement's id.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload FROM agent_results "
                    "WHERE engagement_id = %s AND agent = 'adviser'", (str(eid),))
        row = cur.fetchone()
    if row is None:
        return {"error": "no report yet — the adviser stage has not produced one"}
    from agent.services.report_renderer import render_markdown
    from shared.models import EngagementReport
    try:
        md = render_markdown(EngagementReport(**(row[0] or {})))
    except Exception as exc:  # noqa: BLE001 — a malformed stored report must not 500
        return {"error": f"could not render report: {type(exc).__name__}: {exc}"}
    return {"engagement_id": str(eid), "format": "markdown", "markdown": md}


async def get_recon_findings(engagement_id: str, grade: str | None = None) -> dict[str, Any]:
    """Return recon's GRADED findings (what/where/category/grade/reason), highest grade
    first — recon's ranked lead list that the vuln stage assesses. Pass
    grade=high|medium|low to filter.

    Args:
        engagement_id: The engagement's id.
        grade: Optional grade filter (high/medium/low).
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload->'findings' FROM agent_results "
                    "WHERE engagement_id=%s AND agent='recon'", (str(eid),))
        row = cur.fetchone()
    if row is None:
        return {"error": "recon has produced no artifact yet for this engagement"}
    findings = row[0] or []
    rank = {"high": 0, "medium": 1, "low": 2}
    if grade:
        findings = [f for f in findings
                    if str(f.get("grade") or "").lower() == grade.lower()]
    findings = sorted(findings, key=lambda f: rank.get(str(f.get("grade") or "").lower(), 3))
    return {"engagement_id": str(eid), "count": len(findings), "findings": findings}


async def get_recon_summary(engagement_id: str) -> dict[str, Any]:
    """Return recon's attack-surface summary plus the surface counts (endpoints,
    api_paths, observed requests, graded findings) — the quick 'what did recon find'.

    Args:
        engagement_id: The engagement's id.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload FROM agent_results "
                    "WHERE engagement_id=%s AND agent='recon'", (str(eid),))
        row = cur.fetchone()
    if row is None:
        return {"error": "recon has produced no artifact yet for this engagement"}
    p = row[0] or {}
    counts = {k: len(p.get(k) or []) for k in
              ("endpoints", "api_paths", "observed_requests", "findings", "forms")}
    return {"engagement_id": str(eid), "summary": p.get("summary") or "",
            "mode": p.get("mode"), "pages_crawled": p.get("pages_crawled"),
            "counts": counts}


async def get_recon_peek(engagement_id: str) -> dict[str, Any]:
    """Return recon's Phase-0.5 peek behaviour map: per route, the inputs (type+name),
    buttons, and the XHR/fetch calls it fires on load — how recon 'understood' each
    page before deciding what to crawl. Empty if this run predates peek persistence.

    Args:
        engagement_id: The engagement's id.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT payload->'peek' FROM agent_results "
                    "WHERE engagement_id=%s AND agent='recon'", (str(eid),))
        row = cur.fetchone()
    if row is None:
        return {"error": "recon has produced no artifact yet for this engagement"}
    peek = row[0] or []
    return {"engagement_id": str(eid), "count": len(peek), "peek": peek}


async def search_run(engagement_id: str, query: str,
                     agent: str | None = None, limit: int = 20) -> dict[str, Any]:
    """Search the FULL raw data of a run for a substring and return matching windows.

    This is how you read exact values without loading a whole run into the chat:
    it searches every stage's stored artifact AND the execution trace (which holds
    the raw tool requests/responses — full response bodies, headers, tool output),
    and returns a window of text around each match so a complete value (a full
    token, a response body) comes back intact. Generic: it matches raw text, it
    does not care what the value is.

    Use it to recover any exact value the human-facing summaries shortened — search
    a distinctive fragment you already have (the start of a token, an endpoint, a
    field name) and read the surrounding bytes.

    Args:
        engagement_id: The engagement's id.
        query: Case-insensitive substring to find in the raw run data.
        agent: Optional stage to restrict the search to (recon, vuln, mitre,
            exploit, script, adviser).
        limit: Max windows to return (default 20).
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    q = (query or "").strip()
    if not q:
        return {"error": "query is required"}
    if agent is not None and agent not in CHAIN:
        return {"error": f"unknown stage {agent!r}; expected one of {CHAIN}"}
    limit = max(1, min(int(limit or 20), 50))
    like = f"%{q}%"
    win_before, win_len = 200, 4000   # window: a little before the hit, plenty after
    matches: list[dict[str, Any]] = []
    with get_conn() as conn, conn.cursor() as cur:
        # Stored artifacts.
        sql = ("SELECT agent, substring(payload::text FROM "
               "greatest(1, position(%s in lower(payload::text)) - %s) FOR %s) "
               "FROM agent_results WHERE engagement_id=%s AND payload::text ILIKE %s")
        params: list[Any] = [q.lower(), win_before, win_len, str(eid), like]
        if agent:
            sql += " AND agent=%s"
            params.append(agent)
        sql += " ORDER BY agent"
        cur.execute(sql, params)
        for a, window in cur.fetchall():
            matches.append({"source": "artifact", "agent": a, "window": window})
        # Execution trace — the raw tool I/O lives here.
        sql2 = ("SELECT agent, event_type, substring(payload::text FROM "
                "greatest(1, position(%s in lower(payload::text)) - %s) FOR %s) "
                "FROM agent_trace WHERE engagement_id=%s AND payload::text ILIKE %s")
        params2: list[Any] = [q.lower(), win_before, win_len, str(eid), like]
        if agent:
            sql2 += " AND agent=%s"
            params2.append(agent)
        sql2 += " ORDER BY id LIMIT %s"
        params2.append(limit)
        cur.execute(sql2, params2)
        for a, ev, window in cur.fetchall():
            matches.append({"source": "trace", "agent": a, "event": ev,
                            "window": window})
    return {"engagement_id": str(eid), "query": q,
            "match_count": len(matches), "matches": matches[:limit],
            "hint": "each window is raw text around a hit; widen your query "
                    "fragment if a value looks cut off" if matches else
                    "no matches — try a shorter/different fragment"}


# --------------------------------------------------------------------------- #
# Schema bootstrap
#
# These query functions are reused as-is by ``apts.serve`` (the launchable twin),
# which imports them and registers them on its own MCP server. This module no
# longer stands up a server of its own.
# --------------------------------------------------------------------------- #

_ensure_schema()   # add engagements.objective on an older DB before first use

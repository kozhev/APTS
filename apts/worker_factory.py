"""Build one stage's worker, for the in-process runner.

This is the additive twin of ``agent/main.py:build_worker``. That function reads
the stage from ``AGENT_NAME`` and hands the exploit/script/adviser workers a
hardcoded ``AgentResultRepository``; here ``make_worker(name, storage)`` takes
the stage by name and the *storage backend* by argument, so the same workers run
against Postgres or an in-memory dict without change. The ``LLM_BACKED`` /
``TOOL_BACKED`` sets and the per-stage construction are duplicated verbatim (not
imported) to keep ``agent/main.py`` untouched.

The three workers that take a ``results`` repo (exploit, script, adviser) only
ever call ``.load(engagement_id, agent)`` on it, which both storage backends
expose — so the backend stands in for the repository exactly.

Each worker is imported inside its own branch: constructing one stage never
drags in the others' heavy dependencies (LangGraph, the MCP client, …), which is
what lets the runner be exercised with injected fakes and no such deps present.
"""
from __future__ import annotations

from typing import Any

from agent.services.workers.base import Worker
from shared.pipeline import CHAIN

# Mirrors agent/main.py. Together these must cover every stage in CHAIN.
LLM_BACKED = {"vuln", "mitre", "exploit", "adviser"}
TOOL_BACKED = {"recon"}


def make_worker(name: str, storage: Any) -> Worker:
    """Return the worker for stage ``name``, wired to ``storage``.

    ``storage`` is any object exposing ``load(engagement_id, agent)`` (an
    :class:`apts.storage.Storage` backend). Only exploit/script/adviser use it;
    the others ignore it.
    """
    if name not in CHAIN:
        raise ValueError(f"{name!r} is not a pipeline stage; expected one of {CHAIN}")

    if name in TOOL_BACKED:
        if name == "recon":
            from agent.services.workers.recon.recon_worker import ReconWorker
            return ReconWorker()
        raise RuntimeError(f"{name!r} is marked tool-backed but has no worker")

    if name not in LLM_BACKED:
        raise RuntimeError(
            f"{name!r} is in the pipeline but is neither tool-backed nor "
            f"LLM-backed; it has no worker")

    if name == "vuln":
        from agent.services.workers.vuln.vuln_worker import VulnWorker
        return VulnWorker()
    if name == "mitre":
        from agent.services.workers.mitre.mitre_worker import MitreWorker
        return MitreWorker()
    if name == "exploit":
        # Reads the vuln register back from the store (MITRE sits between this
        # stage and the artifact it needs).
        from agent.services.workers.exploit.exploit_worker import ExploitWorker
        return ExploitWorker(storage)
    if name == "adviser":
        # Reads every stage's artifact and writes the deliverable to disk.
        from agent.repositories.report_repository import ReportRepository
        from agent.services.workers.adviser.adviser_worker import AdviserWorker
        return AdviserWorker(storage, ReportRepository())

    raise RuntimeError(f"{name!r} is marked LLM-backed but has no worker")


__all__ = ["make_worker", "LLM_BACKED", "TOOL_BACKED"]

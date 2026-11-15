"""The single-process pipeline runner.

Walks ``shared.pipeline.CHAIN`` in order and runs each stage in *this* process:
it loads the previous stage's stored artifact, authors the stage directive the
way the orchestrator does, builds the stage worker, awaits it, persists the
result, and marks the stage done — then moves on. It replaces the networked
hand-off (agent → orchestrator → agent over mTLS) with a plain function call,
while reusing the exact pieces the networked system uses: the chain ordering and
criticality from ``shared.pipeline``, the stage ``Worker`` implementations, the
storage contract the workers already expect, and the orchestrator's directive
logic.

Failure handling follows §2.2.4, as the orchestrator implements it:

* a stage that raises :class:`WorkFailed` is retried, counting the failures;
* once the count exceeds ``MAX_RETRIES`` the stage is exhausted — if it is a
  *critical* stage (recon, vuln) the whole run stops; otherwise the run
  continues with whatever partial results are already stored (a non-critical
  stage that never produced an artifact simply hands an empty upstream to the
  next stage, exactly as the DB-backed chain would).

Resume: given an engagement id whose store already holds some stages, those
stages are skipped and the run continues from the first unfinished one. With
``PostgresStorage`` this survives a process restart; with ``MemoryStorage`` it is
meaningful only within one process (nothing persists a restart).

Design note — injectability. ``worker_factory`` and ``directive_author`` default
to the real implementations but can be overridden, and both are imported lazily,
so the runner can be driven end-to-end with fakes and no LangGraph / MCP / DB /
LLM present. That is what the smoke test uses to prove the control flow.
"""
from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from uuid import UUID, uuid4

from shared.models import Scope
from shared.pipeline import CHAIN, MAX_RETRIES, is_critical, previous_agent

from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("apts.runner")

# Sentinels distinguishing the two exhausted-retry outcomes from a real artifact.
_FAILED_STOP = object()      # critical stage exhausted retries -> stop the run
_FAILED_CONTINUE = object()  # non-critical stage exhausted retries -> continue


@dataclass
class RunSpec:
    """One engagement's inputs. The runner's analogue of ``EngagementSpec``.

    ``engagement_id`` set means *resume that engagement* (skip stages already in
    the store); unset means a fresh run with a new id.
    """
    target_url: str
    scope: Scope = field(default_factory=Scope)
    objective: str = ""
    credentials: dict[str, Any] = field(default_factory=dict)
    scan_mode: str = "default"
    stop_after: str = ""
    engagement_id: UUID | None = None


@dataclass
class RunResult:
    """What a run produced: its id, outcome, and which stages did what."""
    engagement_id: UUID
    status: str = "running"            # running | complete | failed | paused
    completed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed_stages: list[str] = field(default_factory=list)
    stopped_stage: str | None = None   # the critical stage that stopped the run
    reason: str = ""


# A directive author: (agent, prev_agent, upstream, objective) -> str | awaitable
DirectiveAuthor = Callable[[str, "str | None", dict, str], "str | Awaitable[str]"]


class Runner:
    """Runs the whole pipeline in one process."""

    def __init__(self, storage: Any, *,
                 worker_factory: Callable[[str, Any], Any] | None = None,
                 directive_author: DirectiveAuthor | None = None,
                 use_model_directives: bool = True,
                 progress: Callable[..., None] | None = None) -> None:
        self._storage = storage
        self._worker_factory = worker_factory
        self._directive_author = directive_author
        self._use_model_directives = use_model_directives
        self._progress = progress or (lambda *a, **k: None)

    # ------------------------------------------------------------------ #
    # Lazy defaults — kept out of import time so a run with injected fakes
    # needs no worker / directive dependencies installed.
    # ------------------------------------------------------------------ #

    def _make_worker(self, name: str) -> Any:
        if self._worker_factory is not None:
            return self._worker_factory(name, self._storage)
        from apts.worker_factory import make_worker
        return make_worker(name, self._storage)

    async def _author(self, agent: str, prev_agent: str | None,
                      upstream: dict[str, Any], objective: str) -> str:
        if self._directive_author is not None:
            out = self._directive_author(agent, prev_agent, upstream, objective)
            return await out if inspect.isawaitable(out) else out
        from apts import directives
        return await directives.author_directive(
            agent, prev_agent, upstream, objective,
            use_model=self._use_model_directives)

    # ------------------------------------------------------------------ #
    # Entry point
    # ------------------------------------------------------------------ #

    async def run(self, spec: RunSpec) -> RunResult:
        engagement_id = spec.engagement_id or uuid4()
        resuming = spec.engagement_id is not None
        self._storage.ensure_engagement(engagement_id, spec)

        already_done = list(self._storage.completed_stages(engagement_id))
        result = RunResult(engagement_id=engagement_id,
                           completed=list(already_done))
        self._progress("run_start", engagement_id=str(engagement_id),
                       target=spec.target_url, resuming=resuming,
                       already_done=already_done)

        for agent in CHAIN:
            if agent in already_done:
                result.skipped.append(agent)
                self._progress("stage_skipped", agent=agent)
                continue

            prev = previous_agent(agent)
            upstream = (self._storage.load(engagement_id, prev) or {}) if prev else {}
            directive = await self._author(agent, prev, upstream, spec.objective)
            ctx = WorkContext(
                engagement_id=engagement_id,
                target_url=spec.target_url,
                scope=spec.scope,
                upstream=upstream,
                directive=directive,
                credentials=spec.credentials,
                scan_mode=spec.scan_mode,
                stop_after=spec.stop_after,
            )
            self._progress("stage_start", agent=agent, critical=is_critical(agent))
            self._storage.record_status(engagement_id, agent, "started")

            outcome = await self._run_stage(agent, ctx)

            if outcome is _FAILED_STOP:
                self._storage.record_status(engagement_id, agent, "failed")
                result.failed_stages.append(agent)
                result.status = "failed"
                result.stopped_stage = agent
                result.reason = f"critical stage {agent!r} failed {MAX_RETRIES} retries"
                self._progress("stage_failed", agent=agent, fatal=True)
                self._progress("run_failed", agent=agent, reason=result.reason)
                return result

            if outcome is _FAILED_CONTINUE:
                self._storage.record_status(engagement_id, agent, "failed")
                result.failed_stages.append(agent)
                self._progress("stage_failed", agent=agent, fatal=False)
                continue  # non-critical: carry on with partial results

            # Success: persist, then mark done.
            artifact = outcome
            self._storage.save(engagement_id, agent, artifact)
            result.completed.append(agent)
            self._progress("stage_done", agent=agent,
                           summary=_summarise(artifact))

            if spec.stop_after and _should_pause_after(agent, spec.stop_after):
                result.status = "paused"
                result.stopped_stage = agent
                result.reason = f"stop_after={spec.stop_after}"
                self._progress("run_paused", after=agent,
                               stop_after=spec.stop_after)
                return result

        result.status = "complete"
        self._progress("run_complete", completed=result.completed)
        return result

    # ------------------------------------------------------------------ #
    # One stage, with the retry budget
    # ------------------------------------------------------------------ #

    async def _run_stage(self, agent: str, ctx: WorkContext) -> Any:
        """Run ``agent``'s worker, retrying on :class:`WorkFailed`.

        Returns the artifact dict on success, or one of the ``_FAILED_*``
        sentinels once retries are exhausted. A non-``WorkFailed`` exception is a
        genuine crash, not a stage declaring failure, so it propagates rather
        than being silently retried.
        """
        worker = self._make_worker(agent)
        failures = 0
        while True:
            try:
                return await worker(ctx)
            except WorkFailed as exc:
                failures += 1
                self._progress("stage_retry", agent=agent, attempt=failures,
                               max_retries=MAX_RETRIES, error=str(exc))
                # Matches the orchestrator: stop once the failure count exceeds
                # the retry budget (initial attempt + MAX_RETRIES retries).
                if failures > MAX_RETRIES:
                    log.error("%s exhausted retries (%d)", agent, MAX_RETRIES)
                    return _FAILED_STOP if is_critical(agent) else _FAILED_CONTINUE


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _summarise(artifact: dict[str, Any]) -> str:
    """A short human line about a stage's artifact — counts its collections.

    Same shape as ``RunProvider._summarise`` / the orchestrator's summariser, so
    the runner's progress reads like the networked system's flow file.
    """
    if not isinstance(artifact, dict):
        return "a result"
    parts = [f"{len(v)} {k}" for k, v in artifact.items()
             if isinstance(v, (list, dict)) and v]
    return ", ".join(parts[:5]) or "empty artifact"


def _should_pause_after(agent: str, stop_after: str) -> bool:
    """Whether the run should pause after ``agent``.

    Mirrors ``orchestrator.main._paused_after``: only recon carries a pause
    marker today, for ``stop_after`` of ``probe`` (surface only) or ``recon``.
    """
    return agent == "recon" and stop_after in ("probe", "recon")


__all__ = ["Runner", "RunSpec", "RunResult"]

"""Storage for the in-process runner — two backends behind one interface.

The networked system persists every stage's artifact to Postgres through
``AgentResultRepository`` (``save(engagement_id, agent, payload)`` /
``load(engagement_id, agent)``). The exploit, script and adviser workers read
earlier stages back through that same ``.load(...)``. The runner needs the
identical contract, plus a little progress/resume bookkeeping, and it needs it to
work either against the real database *or* entirely in memory for a throwaway
run.

So this module defines one :class:`Storage` protocol and two implementations:

* :class:`PostgresStorage` — wraps the existing repositories; persistent and
  therefore resumable across process restarts.
* :class:`MemoryStorage` — a plain in-process dict; a restart discards it.

Both expose exactly the ``save`` / ``load`` a worker's ``results`` repo exposes,
so either can be handed to ``ExploitWorker(storage)`` et al. unchanged.

``get_storage(kind)`` selects one, driven by the ``APTS_STORAGE`` env var
(``postgres`` | ``memory``), defaulting to ``memory`` — the safe default for a
scratch run that should leave nothing behind.
"""
from __future__ import annotations

import os
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from shared.pipeline import CHAIN


@runtime_checkable
class Storage(Protocol):
    """What the runner (and the workers it builds) require of a backend."""

    def save(self, engagement_id: UUID, agent: str, payload: dict[str, Any]) -> None:
        """Persist one stage's artifact (upsert on ``(engagement_id, agent)``)."""

    def load(self, engagement_id: UUID, agent: str) -> dict[str, Any] | None:
        """Read a stage's stored artifact, or ``None`` if it has not run.

        This is the exact method the exploit/script/adviser workers call on the
        ``results`` repo they are given, so the backend stands in for it."""

    def record_status(self, engagement_id: UUID, agent: str, status: str) -> None:
        """Note a stage's lifecycle status (started | done | failed | ...)."""

    def completed_stages(self, engagement_id: UUID) -> list[str]:
        """Stages that already have a stored artifact, in ``CHAIN`` order.

        This is the resume signal: a stage may be skipped only when its output
        exists for the next stage to read."""

    def stage_statuses(self, engagement_id: UUID) -> dict[str, str]:
        """The recorded lifecycle status of each stage that has one.

        Lets a controller show which stage is running now (``started``) vs done
        or failed. Stages with no recorded status are simply absent."""

    def ensure_engagement(self, engagement_id: UUID, spec: Any) -> None:
        """Make sure the engagement exists before any artifact is written.

        No-op where there is nothing to create (memory); in Postgres it inserts
        the ``engagements`` row the ``agent_results`` foreign key requires."""


# --------------------------------------------------------------------------- #
# In-memory backend
# --------------------------------------------------------------------------- #

class MemoryStorage:
    """Ephemeral dict-backed store. A restart discards everything.

    Keyed by ``(engagement_id, agent)`` exactly like the ``agent_results`` unique
    constraint, so a re-save of the same stage overwrites rather than accumulates
    — matching the Postgres upsert the workers' retries rely on.
    """

    def __init__(self) -> None:
        self._artifacts: dict[tuple[str, str], dict[str, Any]] = {}
        self._status: dict[tuple[str, str], str] = {}
        self._engagements: dict[str, Any] = {}

    def ensure_engagement(self, engagement_id: UUID, spec: Any = None) -> None:
        self._engagements.setdefault(str(engagement_id), spec)

    def save(self, engagement_id: UUID, agent: str, payload: dict[str, Any]) -> None:
        self._artifacts[(str(engagement_id), agent)] = payload
        self._status[(str(engagement_id), agent)] = "done"

    def load(self, engagement_id: UUID, agent: str) -> dict[str, Any] | None:
        return self._artifacts.get((str(engagement_id), agent))

    def record_status(self, engagement_id: UUID, agent: str, status: str) -> None:
        self._status[(str(engagement_id), agent)] = status

    def completed_stages(self, engagement_id: UUID) -> list[str]:
        eid = str(engagement_id)
        return [a for a in CHAIN if (eid, a) in self._artifacts]

    def stage_statuses(self, engagement_id: UUID) -> dict[str, str]:
        eid = str(engagement_id)
        return {a: self._status[(eid, a)] for a in CHAIN if (eid, a) in self._status}


# --------------------------------------------------------------------------- #
# Postgres backend
# --------------------------------------------------------------------------- #

class PostgresStorage:
    """Durable, resumable store wrapping the existing repositories.

    ``save``/``load`` delegate to :class:`AgentResultRepository` so the on-disk
    format is byte-for-byte what the networked pipeline writes — a run started
    here can be inspected, or resumed, by the existing tooling and vice versa.
    Status is mirrored into ``engagement_state`` (best-effort) to match the
    orchestrator's view.
    """

    def __init__(self, results: Any = None) -> None:
        if results is None:
            # Imported lazily so merely importing this module (or using the
            # memory backend) never requires psycopg / a reachable database.
            from agent.repositories.agent_result_repository import AgentResultRepository
            results = AgentResultRepository()
        self._results = results

    def save(self, engagement_id: UUID, agent: str, payload: dict[str, Any]) -> None:
        self._results.save(engagement_id, agent, payload)
        self.record_status(engagement_id, agent, "done")

    def load(self, engagement_id: UUID, agent: str) -> dict[str, Any] | None:
        return self._results.load(engagement_id, agent)

    def completed_stages(self, engagement_id: UUID) -> list[str]:
        # Authoritative: a stage counts as complete only if its artifact is on
        # disk, because resume's whole purpose is to feed that artifact forward.
        return [a for a in CHAIN if self.load(engagement_id, a) is not None]

    def stage_statuses(self, engagement_id: UUID) -> dict[str, str]:
        from shared.db import get_conn
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT agent, status FROM engagement_state WHERE engagement_id = %s",
                    (str(engagement_id),))
                return {a: s for a, s in cur.fetchall() if a in CHAIN}
        except Exception:  # noqa: BLE001 — a status read must never raise at the caller
            return {}

    def ensure_engagement(self, engagement_id: UUID, spec: Any) -> None:
        """Insert the engagement + seed per-stage state, idempotently.

        Mirrors ``orchestrator.main._create_engagement_row`` but with
        ``ON CONFLICT DO NOTHING`` so a resume (row already present) is a no-op.
        The ``agent_results`` table has a foreign key to ``engagements``; without
        this row the very first ``save`` would fail.
        """
        import psycopg

        from shared.db import get_conn

        scope_json = spec.scope.model_dump() if spec is not None and hasattr(spec, "scope") else {}
        objective = getattr(spec, "objective", "") or ""
        credentials = getattr(spec, "credentials", {}) or {}
        target_url = getattr(spec, "target_url", "") or ""
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO engagements
                       (id, target_url, scope, time_window, objective, credentials, status)
                   VALUES (%s, %s, %s::jsonb, %s::jsonb, %s, %s::jsonb, 'running')
                   ON CONFLICT (id) DO NOTHING""",
                (str(engagement_id), target_url,
                 psycopg.types.json.Json(scope_json),
                 psycopg.types.json.Json({}),
                 objective,
                 psycopg.types.json.Json(credentials)),
            )
            for agent in CHAIN:
                cur.execute(
                    """INSERT INTO engagement_state (engagement_id, agent, status)
                       VALUES (%s, %s, 'pending')
                       ON CONFLICT (engagement_id, agent) DO NOTHING""",
                    (str(engagement_id), agent),
                )

    def record_status(self, engagement_id: UUID, agent: str, status: str) -> None:
        # Best-effort: a status write must never fail an otherwise-good stage.
        from shared.db import get_conn
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    """UPDATE engagement_state SET status = %s, updated_at = NOW()
                       WHERE engagement_id = %s AND agent = %s""",
                    (status, str(engagement_id), agent),
                )
        except Exception:  # noqa: BLE001 — bookkeeping only
            pass


# --------------------------------------------------------------------------- #
# Selector
# --------------------------------------------------------------------------- #

def get_storage(kind: str | None = None) -> Storage:
    """Pick a backend. ``kind`` overrides ``APTS_STORAGE``; default ``memory``.

    ``memory`` is the default on purpose: it needs no database and leaves nothing
    behind, which is the right behaviour for an unqualified scratch run. Choose
    ``postgres`` for a persistent, resumable engagement.
    """
    resolved = (kind or os.environ.get("APTS_STORAGE") or "memory").strip().lower()
    if resolved == "postgres":
        return PostgresStorage()
    if resolved == "memory":
        return MemoryStorage()
    raise ValueError(
        f"unknown storage {resolved!r}; expected 'postgres' or 'memory'")


__all__ = [
    "Storage",
    "MemoryStorage",
    "PostgresStorage",
    "get_storage",
]

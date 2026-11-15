"""APTS single-process engine.

An *additive* collapse of the six networked agent microservices into one
in-process pipeline runner. The FastAPI agents, the orchestrator, and the
compose stack are untouched — this package reuses their pure pieces
(``shared.pipeline`` for ordering, the stage ``Worker`` implementations, the
orchestrator's directive authoring) and drives them directly instead of over
mTLS HTTP.

Public surface::

    from apts import Runner, RunSpec
    from apts.storage import get_storage

Only :class:`Runner` and its data shapes are re-exported here; importing this
module stays light (no LangGraph / MCP / DB imports) so the runner can be driven
with injected fakes in a test. The concrete workers and the Postgres backend are
imported lazily, at the point they are actually constructed.
"""
from __future__ import annotations

from apts.runner import RunResult, Runner, RunSpec

__all__ = ["Runner", "RunSpec", "RunResult"]

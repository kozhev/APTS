"""Proof for the harness MCP control server (``apts/serve.py``) — Docker-free.

Drives :class:`apts.serve.HarnessControl` DIRECTLY (bypassing the MCP transport)
with FAKE workers + ``MemoryStorage`` injected into the Runner, so the whole
thing runs in milliseconds with only pydantic + pytest — no langchain, no mcp, no
database.

It asserts:
  * ``create_engagement`` launches a background run; once it finishes,
    ``engagement_status`` reports ``completed`` with every stage done;
  * ``list_artifacts`` / ``get_artifact`` return the fake stage artifacts from the
    shared storage (so the control server and the Runner agree in-process);
  * ``get_artifact(query=...)`` searches a stored artifact;
  * ``stop_engagement`` cancels a long-running engagement and status flips to
    ``cancelled``;
  * ``resume_engagement`` returns a clear postgres-only message in memory mode;
  * the module-level tool wrappers delegate to the shared control instance;
  * ``apts.serve`` imports with no mcp/DB and registers the expected tool names.

Run it:
    pytest -q tests/test_harness_control.py
or:
    python tests/test_harness_control.py
"""
from __future__ import annotations

import asyncio

from shared.pipeline import CHAIN

from agent.services.workers.base import WorkContext
from apts.runner import Runner
from apts.storage import MemoryStorage
import apts.serve as serve
from apts.serve import HarnessControl


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

class FakeWorker:
    """Returns a tiny artifact tagged with its stage name."""

    def __init__(self, name: str) -> None:
        self.name = name

    async def __call__(self, ctx: WorkContext) -> dict:
        return {"stage": self.name, "items": [self.name],
                "note": f"{self.name} produced this"}


class BlockingWorker:
    """Completes fast, except ``block_on`` which waits forever (until cancelled)."""

    def __init__(self, name: str, block_on: str, gate: asyncio.Event) -> None:
        self.name = name
        self.block_on = block_on
        self.gate = gate

    async def __call__(self, ctx: WorkContext) -> dict:
        if self.name == self.block_on:
            self.gate.set()            # signal we've reached the blocking stage
            await asyncio.sleep(3600)  # block until stop_engagement cancels us
        return {"stage": self.name, "items": [self.name]}


def _fixed_directive(agent, prev_agent, upstream, objective) -> str:
    return f"directive[{agent}]"


def _runner_factory(worker_for):
    """Build a runner_factory that wires the given per-stage worker + fixed directives."""
    def factory(storage):
        return Runner(storage,
                      worker_factory=lambda name, st: worker_for(name),
                      directive_author=_fixed_directive)
    return factory


# --------------------------------------------------------------------------- #
# (1) create -> run to completion -> status / artifacts
# --------------------------------------------------------------------------- #

async def _create_and_complete():
    storage = MemoryStorage()
    hc = HarnessControl(storage, runner_factory=_runner_factory(FakeWorker))

    res = await hc.create_engagement("http://t.test", ["t.test"], objective="find bugs")
    assert res["status"] == "running"
    eid = res["engagement_id"]

    # engagement_status is answerable immediately (from meta), before/while running.
    early = await hc.engagement_status(eid)
    assert early["status"] in ("running", "completed")
    assert early["target_url"] == "http://t.test"

    await asyncio.wait_for(hc.task_for(eid), timeout=5)

    st = await hc.engagement_status(eid)
    assert st["status"] == "completed", st
    assert set(st["completed"]) == set(CHAIN)
    assert all(st["per_agent"][a] == "done" for a in CHAIN)
    assert st["current_agent"] is None

    arts = await hc.list_artifacts(eid)
    assert {a["agent"] for a in arts["artifacts"]} == set(CHAIN)
    assert all(a["size_chars"] > 0 for a in arts["artifacts"])

    ga = await hc.get_artifact(eid, "recon")
    assert ga["artifact"]["stage"] == "recon"
    assert ga["truncated"] is False

    # Search a stored artifact.
    gq = await hc.get_artifact(eid, "exploit", query="exploit")
    assert gq["match_count"] >= 1
    assert gq["matches"]

    # Unknown stage / missing artifact are clean errors, not exceptions.
    assert "error" in await hc.get_artifact(eid, "bogus")


def test_create_run_status_and_artifacts():
    asyncio.run(_create_and_complete())


# --------------------------------------------------------------------------- #
# (2) stop_engagement cancels a long run
# --------------------------------------------------------------------------- #

async def _stop_long_run():
    storage = MemoryStorage()
    gate = asyncio.Event()
    worker_for = lambda name: BlockingWorker(name, "mitre", gate)
    hc = HarnessControl(storage, runner_factory=_runner_factory(worker_for))

    res = await hc.create_engagement("http://t.test", ["t.test"])
    eid = res["engagement_id"]

    # Wait until recon+vuln are done and mitre is blocking.
    await asyncio.wait_for(gate.wait(), timeout=5)
    mid = await hc.engagement_status(eid)
    assert mid["status"] == "running"
    assert set(mid["completed"]) == {"recon", "vuln"}
    assert mid["current_agent"] == "mitre"  # the blocking stage was marked 'started'

    stop = await hc.stop_engagement(eid)
    assert stop["status"] == "cancelled"

    await asyncio.sleep(0.05)  # let the cancellation propagate into the task
    st = await hc.engagement_status(eid)
    assert st["status"] == "cancelled"
    task = hc.task_for(eid)
    assert task.done()
    # mitre/exploit/adviser never completed.
    assert "mitre" not in st["completed"]

    # A second stop is a no-op with a clear message.
    again = await hc.stop_engagement(eid)
    assert again["status"] == "cancelled"
    assert "nothing to stop" in again["message"]


def test_stop_engagement_cancels_long_run():
    asyncio.run(_stop_long_run())


# --------------------------------------------------------------------------- #
# (3) resume in memory mode returns a clear message
# --------------------------------------------------------------------------- #

async def _resume_memory():
    storage = MemoryStorage()
    hc = HarnessControl(storage, runner_factory=_runner_factory(FakeWorker))
    res = await hc.create_engagement("http://t.test", ["t.test"])
    eid = res["engagement_id"]
    await asyncio.wait_for(hc.task_for(eid), timeout=5)
    r = await hc.resume_engagement(eid)
    assert r["status"] == "unsupported"
    assert "postgres" in r["message"].lower()


def test_resume_memory_is_clear():
    asyncio.run(_resume_memory())


# --------------------------------------------------------------------------- #
# (4) module-level wrappers delegate to the shared control instance
# --------------------------------------------------------------------------- #

async def _wrappers_delegate():
    storage = MemoryStorage()
    serve.control = HarnessControl(storage, runner_factory=_runner_factory(FakeWorker))
    res = await serve.create_engagement("http://t.test", ["t.test"])
    eid = res["engagement_id"]
    await asyncio.wait_for(serve.control.task_for(eid), timeout=5)
    st = await serve.engagement_status(eid)
    assert st["status"] == "completed"
    arts = await serve.list_artifacts(eid)
    assert {a["agent"] for a in arts["artifacts"]} == set(CHAIN)
    serve.control = None  # reset the module singleton for other tests


def test_module_wrappers_delegate():
    asyncio.run(_wrappers_delegate())


# --------------------------------------------------------------------------- #
# (5) the server module imports (no mcp/DB) and registers the expected tools
# --------------------------------------------------------------------------- #

def test_serve_module_registry():
    # Importing apts.serve needed only pydantic (already imported at module top).
    assert hasattr(serve, "serve")
    assert hasattr(serve, "build_server")
    assert hasattr(serve, "HarnessControl")

    core = set(serve.CORE_TOOLS)
    assert core == {"apts_health", "create_engagement", "engagement_status",
                    "list_artifacts", "get_artifact", "get_report",
                    "stop_engagement", "resume_engagement"}

    db = set(serve.DB_TOOLS)
    expected_db = {"apts_capabilities", "list_engagements", "get_directives",
                   "get_loot", "get_recon_findings", "get_recon_summary",
                   "get_recon_peek", "get_probe_summary", "search_run"}
    assert expected_db <= db

    all_names = set(serve.ALL_TOOL_NAMES)
    assert core <= all_names and db <= all_names
    assert len(serve.ALL_TOOL_NAMES) == len(set(serve.ALL_TOOL_NAMES))  # no dups
    # Every core tool name has a wrapper callable behind it.
    assert set(serve._CORE_FNS) == core


# --------------------------------------------------------------------------- #
# Runnable without pytest.
# --------------------------------------------------------------------------- #

def _run_all() -> int:
    import traceback

    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except Exception:  # noqa: BLE001 — test harness
            failed += 1
            traceback.print_exc()
            print(f"FAIL  {t.__name__}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

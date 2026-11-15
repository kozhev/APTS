"""Proof that the in-process :class:`apts.runner.Runner` drives the pipeline
correctly — without Docker, a database, a real LLM, or the MCP tools server.

Everything the runner needs from the outside is injected:

* ``MemoryStorage`` stands in for Postgres (a plain in-process dict);
* a fake worker factory returns a ``FakeWorker`` per stage, each of which just
  records the ``WorkContext`` it was handed and returns a small artifact that
  references the previous stage's output;
* a fixed directive author replaces the orchestrator's model call.

So the test imports none of the heavy worker / LLM / DB code and runs in
milliseconds, yet it exercises the real ``Runner`` control flow.

It asserts:
  (a) all five stages run, in ``shared.pipeline.CHAIN`` order
      (recon, vuln, mitre, exploit, adviser);
  (b) each stage's ``WorkContext.upstream`` is the previous stage's stored
      output — artifacts flow down the chain;
  (c) a ``WorkFailed`` on a *critical* stage stops the run, while the same on a
      *non-critical* stage does not;
  (d) resume skips stages already present in the store and continues from the
      first unfinished one.

Run it:
    pytest -q tests/test_runner_smoke.py
or, with no pytest installed:
    python tests/test_runner_smoke.py
"""
from __future__ import annotations

import asyncio
from uuid import uuid4

from shared.models import Scope
from shared.pipeline import CHAIN, is_critical, previous_agent

from agent.services.workers.base import WorkContext, WorkFailed

from apts.runner import Runner, RunSpec
from apts.storage import MemoryStorage


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

class FakeWorker:
    """Records the context it is called with and returns a tiny artifact.

    The artifact carries ``stage`` (its own name) and ``from_upstream`` (the
    ``stage`` value of whatever it was handed), so the chain of references is
    visible in the stored results. ``fail=True`` makes it raise ``WorkFailed``
    on every call, to drive the retry/criticality paths.
    """

    def __init__(self, name: str, recorder: list, *, fail: bool = False) -> None:
        self.name = name
        self.recorder = recorder
        self.fail = fail

    async def __call__(self, ctx: WorkContext) -> dict:
        self.recorder.append((self.name, ctx))
        if self.fail:
            raise WorkFailed(f"{self.name} deliberately failed")
        upstream_stage = ctx.upstream.get("stage") if ctx.upstream else None
        return {
            "stage": self.name,
            "from_upstream": upstream_stage,
            "items": [self.name],  # a list, so progress summaries have something
        }


def _factory(recorder: list, fail_on: str | None = None):
    def make(name: str, storage) -> FakeWorker:
        return FakeWorker(name, recorder, fail=(name == fail_on))
    return make


def _fixed_directive(agent, prev_agent, upstream, objective) -> str:
    """A hermetic stand-in for the model-authored directive."""
    return f"directive[{agent}|prev={prev_agent}|obj={objective}]"


def _spec(engagement_id=None) -> RunSpec:
    return RunSpec(
        target_url="http://example.test",
        scope=Scope(domains=["example.test"]),
        objective="find auth bugs",
        engagement_id=engagement_id,
    )


def _run(runner: Runner, spec: RunSpec):
    return asyncio.run(runner.run(spec))


# --------------------------------------------------------------------------- #
# (a) all six stages run, in CHAIN order
# --------------------------------------------------------------------------- #

def test_all_stages_run_in_chain_order():
    recorder: list = []
    runner = Runner(MemoryStorage(),
                    worker_factory=_factory(recorder),
                    directive_author=_fixed_directive)
    result = _run(runner, _spec())

    ran = [name for name, _ in recorder]
    assert ran == list(CHAIN), f"expected {CHAIN}, ran {ran}"
    assert result.status == "complete"
    assert result.completed == list(CHAIN)
    # The directive really was placed on the context for each stage.
    assert all(ctx.directive.startswith("directive[") for _, ctx in recorder)


# --------------------------------------------------------------------------- #
# (b) artifacts flow: each stage's upstream is the previous stage's output
# --------------------------------------------------------------------------- #

def test_artifacts_flow_down_the_chain():
    recorder: list = []
    storage = MemoryStorage()
    runner = Runner(storage,
                    worker_factory=_factory(recorder),
                    directive_author=_fixed_directive)
    result = _run(runner, _spec())
    eid = result.engagement_id

    by_name = {name: ctx for name, ctx in recorder}

    # Recon is first: it gets an empty upstream.
    assert by_name["recon"].upstream == {}

    # Every later stage is handed exactly what its predecessor stored.
    for agent in CHAIN[1:]:
        prev = previous_agent(agent)
        stored_prev = storage.load(eid, prev)
        assert by_name[agent].upstream == stored_prev
        assert by_name[agent].upstream["stage"] == prev
        # And the artifact each stage produced recorded that linkage.
        assert storage.load(eid, agent)["from_upstream"] == prev


# --------------------------------------------------------------------------- #
# (c) WorkFailed: critical stage stops the run, non-critical does not
# --------------------------------------------------------------------------- #

def test_critical_failure_stops_the_run():
    assert is_critical("vuln")  # guard: vuln is a critical stage
    recorder: list = []
    runner = Runner(MemoryStorage(),
                    worker_factory=_factory(recorder, fail_on="vuln"),
                    directive_author=_fixed_directive)
    result = _run(runner, _spec())

    ran = {name for name, _ in recorder}
    assert result.status == "failed"
    assert result.stopped_stage == "vuln"
    assert "recon" in ran           # ran up to the failing stage
    assert "mitre" not in ran       # ... and no further
    assert "adviser" not in ran


def test_noncritical_failure_continues_the_run():
    assert not is_critical("exploit")  # guard: exploit is minor-but-special
    recorder: list = []
    storage = MemoryStorage()
    runner = Runner(storage,
                    worker_factory=_factory(recorder, fail_on="exploit"),
                    directive_author=_fixed_directive)
    result = _run(runner, _spec())
    eid = result.engagement_id

    ran = [name for name, _ in recorder]
    assert result.status == "complete"      # the run finished despite the failure
    assert "exploit" in result.failed_stages
    assert "adviser" in ran                 # the stage after it still ran
    assert storage.load(eid, "exploit") is None   # the failed stage stored nothing
    # adviser's predecessor (exploit) produced nothing, so it got an empty upstream.
    adviser_ctx = next(ctx for name, ctx in recorder if name == "adviser")
    assert adviser_ctx.upstream == {}


# --------------------------------------------------------------------------- #
# (d) resume skips already-completed stages
# --------------------------------------------------------------------------- #

def test_resume_skips_completed_stages():
    storage = MemoryStorage()
    eid = uuid4()
    # Pre-seed the store as if recon + vuln already ran in an earlier run.
    storage.ensure_engagement(eid, _spec())
    storage.save(eid, "recon", {"stage": "recon", "items": ["recon"]})
    storage.save(eid, "vuln", {"stage": "vuln", "items": ["vuln"]})

    recorder: list = []
    runner = Runner(storage,
                    worker_factory=_factory(recorder),
                    directive_author=_fixed_directive)
    result = _run(runner, _spec(engagement_id=eid))

    ran = [name for name, _ in recorder]
    assert ran == ["mitre", "exploit", "adviser"]  # recon/vuln skipped
    assert result.skipped == ["recon", "vuln"]
    assert result.status == "complete"
    # The resumed chain still reads the pre-seeded upstream: mitre sees vuln.
    mitre_ctx = next(ctx for name, ctx in recorder if name == "mitre")
    assert mitre_ctx.upstream == {"stage": "vuln", "items": ["vuln"]}


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
        except Exception:  # noqa: BLE001 — this is a test harness
            failed += 1
            traceback.print_exc()
            print(f"FAIL  {t.__name__}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

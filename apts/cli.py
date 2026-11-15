"""Operator CLI for the single-process runner.

    python -m apts.cli run --target <URL> [--scope <DOMAIN> ...] \\
        [--storage postgres|memory] [--objective <TEXT>] [--resume <id>]

Builds a :class:`~apts.runner.RunSpec`, picks a storage backend (the ``--storage``
flag overrides ``APTS_STORAGE``), and drives the whole pipeline in this process,
printing clear per-stage progress to stdout.

Environment it relies on (same vars the existing system reads — nothing new):

* ``APTS_MCP_URL``    — the native MCP tools server the workers call. The runner
                        does NOT start it; it must already be reachable.
* ``APTS_STORAGE``    — default backend (``postgres`` | ``memory``) when
                        ``--storage`` is not given. Defaults to ``memory``.
* ``APTS_DB_*`` / ``APTS_DB_PASSWORD_FILE`` — Postgres connection (postgres
                        backend only).
* ``APTS_LOOP_LLM_*`` / the model's API key — the workers' model backend, and
                        the orchestrator-style directive authoring.

Exit code: 0 when the run completes or pauses as requested, 1 when a critical
stage failed (or on a usage error).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from uuid import UUID

from shared.models import Scope

from apts.runner import Runner, RunSpec
from apts.storage import get_storage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apts",
        description="Run the APTS pentest pipeline as a single in-process run.")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run (or resume) an engagement end to end")
    run.add_argument("--target", required=True,
                     help="target URL to test, e.g. http://host/#/login")
    run.add_argument("--scope", action="append", default=[], metavar="DOMAIN",
                     help="in-scope domain (repeatable), e.g. --scope '*.example.com'")
    run.add_argument("--storage", choices=["postgres", "memory"], default=None,
                     help="storage backend; overrides APTS_STORAGE (default: memory)")
    run.add_argument("--objective", default="",
                     help="free-text engagement brief; steers every stage's directive")
    run.add_argument("--resume", default=None, metavar="ENGAGEMENT_ID",
                     help="resume an existing engagement id (postgres backend)")
    # Additive, optional extras — the four flags above are the fixed contract.
    run.add_argument("--scan-mode", default="default",
                     choices=["default", "thorough", "page"],
                     help="recon breadth (recon only)")
    run.add_argument("--stop-after", default="", choices=["", "probe", "recon"],
                     help="pause the pipeline after recon for inspection")
    run.add_argument("--no-model-directives", action="store_true",
                     help="skip the model directive pass; use deterministic templates")
    return parser


def _make_printer():
    """A progress callback that prints a readable line per runner event."""
    def printer(event: str, **fields) -> None:
        if event == "run_start":
            mode = "resuming" if fields.get("resuming") else "starting"
            print(f"[run] {mode} engagement {fields['engagement_id']} "
                  f"against {fields['target']}")
            done = fields.get("already_done") or []
            if done:
                print(f"[run] already completed, will skip: {', '.join(done)}")
        elif event == "stage_skipped":
            print(f"  - {fields['agent']:<8} SKIP   (already completed)")
        elif event == "stage_start":
            tag = "critical" if fields.get("critical") else "minor"
            print(f"  - {fields['agent']:<8} START  ({tag})")
        elif event == "stage_retry":
            print(f"  - {fields['agent']:<8} RETRY  attempt "
                  f"{fields['attempt']}/{fields['max_retries']}: {fields.get('error','')}")
        elif event == "stage_done":
            print(f"  - {fields['agent']:<8} DONE   -> {fields.get('summary','')}")
        elif event == "stage_failed":
            how = "FATAL" if fields.get("fatal") else "continuing with partial results"
            print(f"  - {fields['agent']:<8} FAILED ({how})")
        elif event == "run_paused":
            print(f"[run] paused after {fields['after']} ({fields.get('stop_after')})")
        elif event == "run_failed":
            print(f"[run] FAILED: {fields.get('reason','')}")
        elif event == "run_complete":
            print(f"[run] complete: {', '.join(fields.get('completed', []))}")
    return printer


def _cmd_run(args: argparse.Namespace) -> int:
    storage_kind = args.storage  # None -> get_storage falls back to APTS_STORAGE
    storage = get_storage(storage_kind)

    if type(storage).__name__ == "MemoryStorage":
        print("note: memory backend — ephemeral: nothing is persisted, the run "
              "cannot be resumed, and DB-backed tool lookups (e.g. recon-request) "
              "are unavailable. Use --storage postgres for the full, resumable path.")

    engagement_id = None
    if args.resume:
        try:
            engagement_id = UUID(args.resume)
        except ValueError:
            print(f"error: --resume must be a UUID, got {args.resume!r}",
                  file=sys.stderr)
            return 1
        if type(storage).__name__ == "MemoryStorage":
            print("warning: --resume with the memory backend cannot restore a "
                  "previous process's state; nothing will be skipped.",
                  file=sys.stderr)

    spec = RunSpec(
        target_url=args.target,
        scope=Scope(domains=list(args.scope)),
        objective=args.objective,
        scan_mode=args.scan_mode,
        stop_after=args.stop_after,
        engagement_id=engagement_id,
    )

    runner = Runner(storage,
                    use_model_directives=not args.no_model_directives,
                    progress=_make_printer())
    try:
        result = asyncio.run(runner.run(spec))
    finally:
        # Flush any buffered Langfuse spans before this short-lived process exits
        # — the exporter batches in a background thread, so without this the final
        # stage's traces can be lost on exit (no-op when Langfuse is off).
        try:
            from shared.llm import flush
            flush()
        except Exception:  # noqa: BLE001 — never let observability break a run
            pass

    print()
    print(f"engagement : {result.engagement_id}")
    print(f"status     : {result.status}")
    print(f"completed  : {', '.join(result.completed) or '(none)'}")
    if result.skipped:
        print(f"skipped    : {', '.join(result.skipped)}")
    if result.failed_stages:
        print(f"failed     : {', '.join(result.failed_stages)}")
    if result.reason:
        print(f"reason     : {result.reason}")

    return 0 if result.status in ("complete", "paused") else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

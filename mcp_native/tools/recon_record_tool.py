"""recon_finalize — the structured-output boundary for Claude-driven recon.

In the Model-B design a coding-agent subagent (Claude Code / Codex) DRIVES recon:
it calls probe/crawl/peek/http_request freely. The risk of a free-form agent is a
free-form result. This tool is how recon stays STRUCTURED: the agent's final call
hands its graded findings here, the tool VALIDATES them against a schema (rejecting
malformed input), assembles an ``AssetMap``-shaped artifact, and returns it. The
structure lives in this schema — not in the model's prose — so the next stage
(vuln) consumes the same typed surface it always did.

No database write: in Model B the coding agent carries the artifact in its own
context and feeds it to the next stage. (A persist option can be added when
long-running/resumable orchestration is wanted.)
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError


class ReconFinding(BaseModel):
    """One graded recon finding. The agent produces these; the schema enforces shape."""
    finding: str = Field(min_length=1, description="What was found, in one line.")
    where: str = Field(default="", description="URL/path/param it applies to.")
    category: str = Field(default="", description="e.g. exposure, auth, injection-surface, idor.")
    grade: Literal["high", "medium", "low"]
    reason: str = Field(default="", description="One line: why it matters / why this grade.")
    request: dict[str, Any] | None = Field(
        default=None, description="The captured request this finding sits on, if any.")


class ReconArtifact(BaseModel):
    """The structured recon result — an AssetMap-compatible surface + graded findings."""
    target_url: str
    summary: str = Field(default="", description="The recon agent's surface summary.")
    findings: list[ReconFinding] = Field(default_factory=list)
    observed_requests: list[dict[str, Any]] = Field(
        default_factory=list, description="Pass probe/crawl observed_requests straight through.")
    api_paths: list[str] = Field(default_factory=list)


async def recon_finalize(target_url: str, summary: str = "",
                         findings: list[dict[str, Any]] | None = None,
                         observed_requests: list[dict[str, Any]] | None = None,
                         api_paths: list[str] | None = None) -> dict[str, Any]:
    """Validate and structure the recon result. Call this LAST in a recon run.

    Hand it your graded findings (plus the surface you discovered). It validates
    every finding against the schema and returns a structured, machine-readable
    recon artifact the next stage can consume. Malformed findings are rejected with
    an error naming the problem — fix and call again.

    Args:
        target_url: the app you assessed.
        summary: one short paragraph describing the attack surface.
        findings: list of {finding, where, category, grade(high|medium|low), reason, request?}.
        observed_requests: the in-scope requests from probe/crawl, passed through.
        api_paths: candidate API paths discovered.
    """
    try:
        artifact = ReconArtifact(
            target_url=target_url,
            summary=summary or "",
            findings=[ReconFinding(**f) for f in (findings or [])],
            observed_requests=observed_requests or [],
            api_paths=api_paths or [],
        )
    except ValidationError as exc:
        return {"ok": False,
                "error": "findings did not validate — fix and call recon_finalize again",
                "details": exc.errors(include_url=False, include_input=False)[:10]}

    by_grade: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in artifact.findings:
        by_grade[f.grade] += 1

    return {
        "ok": True,
        "recon": artifact.model_dump(),
        "counts": {"findings": len(artifact.findings), "by_grade": by_grade,
                   "observed_requests": len(artifact.observed_requests)},
        "next": ("Structured recon is ready. Feed high/medium findings to the next "
                 "stage (vuln) one by one, each with its `request`."),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Finalize recon: validate your graded findings against the schema and "
        "return a structured, machine-readable recon artifact (target, summary, "
        "findings[{finding, where, category, grade, reason, request}], "
        "observed_requests, api_paths). Call this LAST, after probe + crawl. "
        "Malformed findings are rejected with the reason — fix and call again. This "
        "is what keeps Claude-driven recon structured for the next stage."
    ))(recon_finalize)
    return ["recon_finalize"]

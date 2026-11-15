"""Per-stage directive authoring for the in-process runner.

The orchestrator authors a short natural-language directive for each next stage,
grounded in what the previous stage produced, and puts it in
``WorkContext.directive``. This module reproduces that logic for the single-
process runner. It is a faithful, minimal re-implementation of the pure parts of
``orchestrator/main.py`` (``_recon_directive``, ``_STAGE_JOB``,
``_summarise_payload``, ``_directive_for``, ``_artifact_excerpt``,
``_compose_directive``) rather than an import of that module, because importing
``orchestrator.main`` would pull in its FastAPI app, guardrails and DB schema
bootstrap — none of which the runner wants.

The model pass is identical in spirit to the orchestrator's: try the shared chat
model, fall back to the deterministic template if it is unreachable, so a run
never stalls waiting for a directive. ``use_model=False`` skips the model
entirely (template only) — handy for offline / hermetic runs.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("apts.directives")

# One-line brief per stage — the same text the orchestrator uses to compose each
# directive. Recon is handled separately (it has no predecessor artifact).
STAGE_JOB: dict[str, str] = {
    "vuln": "Assess each recon request and hypothesise concrete, testable web "
            "weaknesses — pursue anything imaginable.",
    "mitre": "Map each weakness to the MITRE ATT&CK technique(s) it corresponds to.",
    "exploit": "Prove or disprove each weakness against the live target using "
               "your tools; confirm only on a real tool signal.",
    "adviser": "Produce the client report: group duplicates, keep only proven "
               "findings, and rank by impact.",
}

DIRECTIVE_SYSTEM = """\
You are the APTS orchestrator directing a pipeline of autonomous security agents
(recon -> vuln -> mitre -> exploit -> script -> adviser). Write a SHORT directive
(1-3 sentences, plain text, no preamble, no lists) telling the NEXT stage what to
focus on, grounded in what the PREVIOUS stage actually produced. The structured
artifact the agent receives is authoritative; your directive only steers
emphasis and priorities. If an OPERATOR OBJECTIVE is given, it governs: carry it
into this stage — translate it into what THIS stage should prioritise (and rank
down what falls outside it) — while still doing the stage's core job. Be specific
to this run. Output ONLY the directive text."""


def recon_directive(objective: str = "") -> str:
    """The first-stage directive, optionally shaped by the operator's brief.

    Mirrors ``orchestrator.main._recon_directive``: generic by construction — the
    objective is injected verbatim, never interpreted, and only biases triage.
    """
    directive = ("Map the attack surface of the target: crawl it, record every "
                 "in-scope request, and triage which are worth testing.")
    objective = (objective or "").strip()
    if objective:
        directive += (f" Operator objective for this engagement: {objective} "
                      "Let it steer what you prioritise; rank surface outside it lower.")
    return directive


def summarise_payload(payload: dict[str, Any]) -> str:
    """A short line about what a stage produced — counts its list/dict members."""
    if not isinstance(payload, dict):
        return "a result"
    parts = [f"{len(v)} {k}" for k, v in payload.items()
             if isinstance(v, (list, dict)) and v]
    return ", ".join(parts[:5]) or "a result"


def artifact_excerpt(payload: dict[str, Any], limit: int = 1200) -> str:
    """A compact highlights view of an artifact for the directive prompt."""
    if not isinstance(payload, dict):
        return ""
    lines: list[str] = []
    for k, v in payload.items():
        if isinstance(v, list) and v:
            parts = []
            for it in v[:6]:
                if isinstance(it, dict):
                    label = (it.get("title") or it.get("id") or it.get("path")
                             or it.get("url") or it.get("weakness_id")
                             or next((str(x) for x in it.values()), ""))
                    parts.append(str(label)[:70])
                else:
                    parts.append(str(it)[:70])
            lines.append(f"- {k}: " + "; ".join(parts))
    return "\n".join(lines)[:limit]


def directive_for(successor: str, prev_agent: str, prev_payload: dict[str, Any]) -> str:
    """Deterministic template directive — the fallback when the model is
    unreachable, and the base the failure-feedback path builds on."""
    return (f"The {prev_agent} stage produced: {summarise_payload(prev_payload)}. "
            f"{STAGE_JOB.get(successor, 'Continue the pipeline.')}")


async def compose_directive(successor: str, prev_agent: str,
                            prev_payload: dict[str, Any], *, note: str = "",
                            objective: str = "", use_model: bool = True) -> str:
    """Author ``successor``'s directive from the previous stage's output.

    Faithful to ``orchestrator.main._compose_directive``: try the model, fall
    back to the deterministic template so an advance never stalls, always surface
    ``note`` and ``objective`` to the agent. ``use_model=False`` goes straight to
    the template.
    """
    objective = (objective or "").strip()
    directive = ""
    if use_model:
        job = STAGE_JOB.get(successor, "Continue the pipeline.")
        objective_line = (f"OPERATOR OBJECTIVE (governs this whole engagement — carry it "
                          f"into this stage): {objective}\n" if objective else "")
        loot = prev_payload.get("loot") if isinstance(prev_payload, dict) else None
        loot_line = ""
        if loot:
            items = "; ".join(f"{l.get('type')}={str(l.get('value'))[:40]}"
                              for l in loot[:6] if isinstance(l, dict))
            loot_line = f"Interesting data already collected: {items}\n"
        user = (objective_line +
                f"Previous stage: {prev_agent} -> produced {summarise_payload(prev_payload)}.\n"
                f"Highlights:\n{artifact_excerpt(prev_payload) or '(none)'}\n"
                + loot_line +
                f"\nNext stage: {successor}. Its job: {job}\n"
                + (f"Also address this: {note}\n" if note else "")
                + "Write the directive for the next stage.")
        try:
            # Imported lazily: the model stack (LangChain etc.) is only needed on
            # this path, never for the template fallback or an offline run.
            from agent.services.workers.common import common_agentic as agentic
            from shared.llm import build_chat_model, run_config

            model = build_chat_model("orchestrator", max_tokens=200)
            msg = await model.ainvoke(
                agentic.to_lc_messages(DIRECTIVE_SYSTEM, user),
                config=run_config(agent="orchestrator"))
            directive = agentic.message_text(msg)
        except Exception as exc:  # noqa: BLE001 — never let a directive call stall the run
            log.warning("directive model call failed (%s); using template", exc)

    if not directive:
        directive = directive_for(successor, prev_agent, prev_payload)
        if objective:  # the template can't fold the objective in, so append it
            directive = f"{directive} Operator objective: {objective}"
    if note and note.lower()[:20] not in directive.lower():
        directive = f"{directive} (Note: {note})"
    return directive


async def author_directive(agent: str, prev_agent: str | None,
                           upstream: dict[str, Any], objective: str = "", *,
                           use_model: bool = True) -> str:
    """The directive for ``agent`` — recon's standalone brief, or a composed one."""
    if agent == "recon" or prev_agent is None:
        return recon_directive(objective)
    return await compose_directive(agent, prev_agent, upstream or {},
                                   objective=objective, use_model=use_model)


__all__ = [
    "STAGE_JOB",
    "recon_directive",
    "summarise_payload",
    "directive_for",
    "compose_directive",
    "author_directive",
]

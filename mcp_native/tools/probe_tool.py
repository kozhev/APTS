"""probe — the step-0 / step-0.5 initial view of a web app, as one MCP tool.

Composes the generic seed crawl (``crawl_v2``, shallow) with the per-page peek
behaviour map: a cheap first look that returns the app's routes, the requests it
fires, and what each page IS and DOES (inputs, buttons, on-load XHR) — WITHOUT the
deep recon crawl. A recon agent starts from this map instead of rediscovering the
surface, so there is no overlap with the deeper crawl it does next.
"""
from __future__ import annotations

from typing import Any


async def probe(target_url: str, max_pages: int = 12, max_depth: int = 2) -> dict[str, Any]:
    """Initial surface map of a web app: a shallow crawl plus a per-page behaviour peek.

    Returns the seed routes, every in-scope request the browser fired (with bodies),
    candidate api paths, and a per-route behaviour map (title, inputs, buttons,
    xhr_on_load). This is step 0 + 0.5 — a recon agent takes it as its STARTING
    point and does the deeper, security-relevant crawl itself. Do not re-probe.

    Args:
        target_url: the app's base URL (scheme + host, optionally a path/#route).
        max_pages: seed-crawl page budget — keep small; this is the shallow pass.
        max_depth: seed-crawl depth.
    """
    from mcp_native.tools.crawl_v2_tool import crawl_v2
    from mcp_native.tools.playwright_live import peek

    seed = await crawl_v2(url=target_url, max_pages=max_pages, max_depth=max_depth)
    if isinstance(seed, dict) and seed.get("error"):
        return {"target_url": target_url, "stage": "seed-crawl", "error": seed["error"]}

    pages = seed.get("pages", []) if isinstance(seed, dict) else []
    routes: list[str] = []
    for p in pages:
        url = p.get("url") if isinstance(p, dict) else None
        if url and url not in routes:
            routes.append(url)
    if target_url not in routes:
        routes.insert(0, target_url)

    behaviour = await peek(routes[:40]) if routes else {"pages": []}

    return {
        "target_url": target_url,
        "pages_crawled": len(pages),
        "routes": routes,
        "observed_requests": seed.get("observed_requests", []) if isinstance(seed, dict) else [],
        "api_paths": seed.get("api_paths", []) if isinstance(seed, dict) else [],
        "peek": behaviour.get("pages", []),
        "next": ("Decide which routes/requests are security-relevant and crawl or "
                 "test those next (crawl_v2 deeper, katana, http_request). Do not "
                 "re-run probe. When done, call recon_finalize with your graded findings."),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Initial surface view of a web app (step 0 + 0.5): a shallow generic crawl "
        "plus a per-page behaviour peek. Returns routes, observed_requests (with "
        "bodies), candidate api_paths, and per-route {title, inputs, buttons, "
        "xhr_on_load}. Call this FIRST on a target; start your recon from this map "
        "and crawl the security-relevant surface next — do not re-probe."
    ))(probe)
    return ["probe"]

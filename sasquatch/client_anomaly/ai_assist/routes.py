"""
ai_assist/routes.py — FastAPI routes for the AI Assist feature.

Routes
------
GET  /api/v1/ai/status
    Health-check: verify Ollama is reachable and the configured model is available.

GET  /api/v1/ai/families?scope=org|site&site_id=<id>
    Return the list of device families visible in the requested scope.
    Used by the frontend to populate the family checkbox list.

POST /api/v1/ai/assist
    Run an LLM analysis or comparison for one or two device families.
    Body: { "families": [...], "scope": "org"|"site", "site_id": "<id>" }
    Returns the LLM-generated text in {"result": "...", "mode": "analyze"|"compare"}.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from . import data_collector, ollama_client
from .prompts import (
    ANALYZE_USER_PROMPT,
    COMPARE_USER_PROMPT,
    SYSTEM_PROMPT,
    format_family_block,
)

log = logging.getLogger(__name__)

ai_router = APIRouter(prefix="/api/v1/ai", tags=["ai_assist"])


# ---------------------------------------------------------------------------
# GET /api/v1/ai/status
# ---------------------------------------------------------------------------

@ai_router.get("/status")
async def get_ai_status():
    """Check whether Ollama is reachable and the configured model is available."""
    return await ollama_client.health_check()


# ---------------------------------------------------------------------------
# GET /api/v1/ai/families
# ---------------------------------------------------------------------------

@ai_router.get("/families")
async def get_ai_families(scope: str = "org", site_id: str = ""):
    """
    Return the family names visible in the requested scope.

    Query params:
      scope    : "org" or "site"  (default: "org")
      site_id  : required when scope == "site"
    """
    effective_site_id = site_id.strip() or None
    try:
        stats = await data_collector.gather_family_stats(scope, effective_site_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    families = [
        {
            "name": s["name"],
            "client_count": s["client_count"],
            "total_events": s["total_events"],
            "site_count": s["site_count"],
            "worst_severity": s["worst_severity"],
            "if_outlier_count": s["if_outlier_count"],
        }
        for s in stats
    ]

    return {
        "scope": scope,
        "site_id": effective_site_id,
        "families": families,
    }


# ---------------------------------------------------------------------------
# POST /api/v1/ai/assist
# ---------------------------------------------------------------------------

@ai_router.post("/assist")
async def run_ai_assist(body: dict):
    """
    Run LLM analysis (1 family) or comparison (2 families).

    Request body
    ------------
    {
      "families": ["iPhone"],              // 1 or 2 family names
      "scope":    "org" | "site",
      "site_id":  "<uuid>"                 // required when scope == "site"
    }

    Response
    --------
    {
      "mode":      "analyze" | "compare",
      "families":  [...],
      "scope":     "org" | "site",
      "result":    "<LLM response text>",
      "timestamp": "<ISO 8601>"
    }
    """
    families: list[str] = body.get("families") or []
    scope: str = (body.get("scope") or "org").strip()
    site_id: str = (body.get("site_id") or "").strip() or None

    # --- Validate input -------------------------------------------------------
    if not families:
        raise HTTPException(status_code=400, detail="'families' must contain 1 or 2 family names.")
    if len(families) > 2:
        raise HTTPException(status_code=400, detail="Maximum 2 families per request.")
    if scope not in ("org", "site"):
        raise HTTPException(status_code=400, detail="'scope' must be 'org' or 'site'.")
    if scope == "site" and not site_id:
        raise HTTPException(status_code=400, detail="'site_id' is required when scope is 'site'.")

    # --- Gather family data from Redis ----------------------------------------
    try:
        all_stats = await data_collector.gather_family_stats(scope, site_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    stats_by_name = {s["name"]: s for s in all_stats}

    # Verify requested families exist in the data
    missing = [f for f in families if f not in stats_by_name]
    if missing:
        raise HTTPException(
            status_code=404,
            detail=f"No data found for family/families: {missing}. "
                   "Ensure a detection cycle has been run for the selected scope.",
        )

    # --- Build scope label for prompts ----------------------------------------
    scope_label = "Organization-wide (all sites)" if scope == "org" else f"Site {site_id}"

    # --- Determine mode and build prompt --------------------------------------
    mode: str
    user_prompt: str

    if len(families) == 1:
        mode = "analyze"
        family_block = format_family_block(stats_by_name[families[0]])
        user_prompt = ANALYZE_USER_PROMPT.format(
            scope_label=scope_label,
            family_block=family_block,
        )
    else:
        mode = "compare"
        family_block_a = format_family_block(stats_by_name[families[0]])
        family_block_b = format_family_block(stats_by_name[families[1]])
        user_prompt = COMPARE_USER_PROMPT.format(
            scope_label=scope_label,
            family_block_a=family_block_a,
            family_block_b=family_block_b,
        )

    # --- Call Ollama ----------------------------------------------------------
    try:
        result = await ollama_client.generate(SYSTEM_PROMPT, user_prompt)
    except RuntimeError as exc:
        log.error(f"Ollama call failed: {exc}")
        raise HTTPException(status_code=502, detail=str(exc))

    return {
        "mode": mode,
        "families": families,
        "scope": scope,
        "site_id": site_id,
        "result": result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

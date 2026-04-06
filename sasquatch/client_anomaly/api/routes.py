"""
routes.py — FastAPI route definitions.

All reads come from Redis — no real-time Mist API calls in the request path.
The API is read-only except for the manual refresh POST.

WLAN scoping: endpoints that return findings, anomalies, or event summaries accept an
optional ?wlan= query parameter. Default is "__all__" (all WLANs combined). Pass a
specific SSID name to scope the result to that WLAN only.
"""

import asyncio
import json
import logging
import os
import time as _time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

import httpx
import numpy as np
import redis.asyncio as aioredis
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from ..anomaly_detector import (
    _anomalies_redis_key,
    _findings_redis_key,
    _org_findings_redis_key,
    get_anomalies,
    get_findings,
    get_org_findings as _get_org_findings_for_site,
    score,
    score_org_wide,
)
from ..client_cache import get_client_cache, refresh_client_cache
from ..event_collector import (
    EVENT_CATEGORIES,
    collect_full,
    get_events,
    get_wlans,
    sanitize_wlan_key,
)
from ..feature_engineer import _features_redis_key, build_features, get_features
from ..health_scorer import get_health, score_health, _health_redis_key
from ..scheduler import build_org_pools, run_collect_only, run_detect_only, run_detection_cycle
from ..webhook_dispatcher import evaluate_and_dispatch
from .auth import require_auth

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
SITE_ID = os.getenv("MIST_SITE_ID", "")
DETECTION_INTERVAL_MINUTES = int(os.getenv("DETECTION_INTERVAL_MINUTES", "15"))
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")


# Module-level connection pool — created on first use after load_dotenv() has run.
# All route handlers share this pool; aclose() on a client returns the connection
# to the pool rather than destroying it.
_redis_pool: aioredis.ConnectionPool | None = None


def _get_redis() -> aioredis.Redis:
    """Return a Redis client backed by the shared module-level connection pool."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.ConnectionPool.from_url(
            REDIS_URL, decode_responses=True, max_connections=20
        )
    return aioredis.Redis(connection_pool=_redis_pool)


_CPU_POOL = ThreadPoolExecutor(max_workers=2)


def _run_pca(X: np.ndarray) -> tuple[np.ndarray, list[float]]:
    """
    Run StandardScaler + PCA synchronously in a thread pool worker.
    Called via run_in_executor to avoid blocking the async event loop.
    Returns (coords 2D array, explained_variance_ratio list).
    """
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    n_components = min(2, X_scaled.shape[0], X_scaled.shape[1])
    pca = PCA(n_components=n_components, random_state=42)
    coords = pca.fit_transform(X_scaled)
    if coords.shape[1] == 1:
        coords = np.hstack([coords, np.zeros((coords.shape[0], 1))])
    return coords, pca.explained_variance_ratio_.tolist()


def _configured_sites() -> list[str]:
    """Return list of configured site IDs from env."""
    site = os.getenv("MIST_SITE_ID", "")
    return [site] if site else []


async def _redis_get(key: str):
    client = _get_redis()
    try:
        return await client.get(key)
    finally:
        await client.aclose()


async def _run_wlan_detection_bg(site_id: str, redis_client, progress_key: str, wp) -> dict:
    """
    Run build_features + score_health + score for __all__ + each unique WLAN.
    Used by background detection tasks. Returns summary dict.
    """
    wlans = await get_wlans(site_id=site_id)
    scopes = ["__all__"] + wlans
    total_macs = 0

    for wlan in scopes:
        try:
            mac_count = await build_features(site_id, wlan)
            if mac_count == 0:
                log.info(f"No MACs with enough events for site={site_id} wlan={wlan} — skipping scoring")
                continue
            await score_health(site_id, wlan)
            scored = await score(site_id, wlan)
            if wlan == "__all__":
                total_macs = scored
        except Exception:
            log.exception(f"WLAN detection failed for site={site_id} wlan={wlan}")

    return {"macs_scored": total_macs, "wlan_scopes": len(scopes)}


async def _detection_background_task(site_id: str) -> None:
    """
    Full 24hr detection pipeline run as a FastAPI background task.
    Writes phase-by-phase progress to Redis key sasquatch:progress:{site_id}.
    Runs feature engineering + scoring for __all__ + each unique WLAN.
    """
    lock_key = f"sasquatch:lock:detection:{site_id}"
    progress_key = f"sasquatch:progress:{site_id}"
    started = _time.time()

    redis_client = _get_redis()

    async def wp(data: dict) -> None:
        data["started_at"] = started
        await redis_client.set(progress_key, json.dumps(data), ex=300)

    acquired = await redis_client.set(lock_key, "1", nx=True, ex=45 * 60)
    if not acquired:
        await wp({"phase": "error", "message": "Another detection cycle is already running"})
        await redis_client.aclose()
        return

    try:
        await wp({"phase": "starting", "events_fetched": 0, "total_estimated": None, "pages": 0})

        client_cache = await get_client_cache(site_id)
        if not client_cache:
            log.info(f"Client cache missing for site {site_id} — refreshing before full run")
            await refresh_client_cache(site_id)
            client_cache = await get_client_cache(site_id)
            if not client_cache:
                log.warning(f"Client cache still empty after refresh for site {site_id} — skipping")
                await wp({"phase": "error", "message": f"No clients found for site {site_id} after refresh"})
                return

        async def on_page(page: int, fetched: int, total: Optional[int]) -> None:
            await wp({
                "phase": "collecting",
                "events_fetched": fetched,
                "total_estimated": total,
                "pages": page,
            })

        event_count = await collect_full(site_id, on_page=on_page)

        if event_count == 0:
            log.info(f"No events found for site {site_id} — skipping detection")
            await wp({"phase": "complete", "events_fetched": 0, "total_estimated": 0, "pages": -1, "macs_scored": 0})
            return

        await wp({"phase": "scoring", "events_fetched": event_count, "total_estimated": event_count, "pages": -1})

        wlan_summary = await _run_wlan_detection_bg(site_id, redis_client, progress_key, wp)

        try:
            await evaluate_and_dispatch(site_id)
        except Exception:
            log.exception(f"Webhook dispatch failed for site {site_id} (non-fatal)")

        await wp({
            "phase": "complete",
            "events_fetched": event_count,
            "total_estimated": event_count,
            "pages": -1,
            "macs_scored": wlan_summary["macs_scored"],
            "wlan_scopes": wlan_summary["wlan_scopes"],
        })

    except Exception as exc:
        log.exception(f"Background detection failed for site {site_id}")
        await wp({"phase": "error", "message": str(exc)})
    finally:
        await redis_client.delete(lock_key)
        await redis_client.aclose()


@router.get("/focus")
async def get_focus():
    """Return the site the scheduler is currently targeting (Redis override or env fallback)."""
    client = _get_redis()
    try:
        override = await client.get("sasquatch:focus_site")
    finally:
        await client.aclose()
    return {
        "site_id": override if override else SITE_ID,
        "source": "override" if override else "env",
    }


@router.post("/focus")
async def set_focus(body: dict):
    """Redirect the scheduler to poll a different site (stored in Redis)."""
    site_id = (body.get("site_id") or "").strip()
    if not site_id:
        raise HTTPException(status_code=400, detail="site_id is required")
    client = _get_redis()
    try:
        await client.set("sasquatch:focus_site", site_id)
    finally:
        await client.aclose()
    log.info(f"Scheduler focus updated to site {site_id}")
    return {"site_id": site_id, "source": "override"}


@router.get("/sites/{site_id}/progress")
async def get_site_progress(site_id: str):
    """Return the latest detection cycle progress for a site."""
    raw = await _redis_get(f"sasquatch:progress:{site_id}")
    if not raw:
        return {"phase": "idle"}
    return json.loads(raw)


@router.get("/sites")
async def list_sites():
    """List all configured site IDs."""
    return {"sites": _configured_sites()}


@router.get("/wlans")
async def list_wlans(site_id: Optional[str] = Query(None)):
    """
    Return unique WLAN (SSID) names derived from the global event store.
    Optionally scoped to a single site via ?site_id=. Returns sorted list.
    """
    wlans = await get_wlans(site_id=site_id)
    return {"wlans": wlans, "site_id": site_id}


@router.get("/org/summary")
async def get_org_summary(wlan: str = Query("__all__")):
    """
    Per-site findings and event counts for the org overview.
    Reads from Redis — no real-time Mist API calls for the data itself.
    """
    if not MIST_ORG_ID:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID not configured.")
    if not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        # Load all events once, counting per site. Per-site sorted sets are fetched
        # in a single pipeline inside get_events().
        all_events = await get_events()
        events_per_site: Counter = Counter(
            e["site_id"]
            for e in all_events
            if e.get("site_id") and (wlan == "__all__" or e.get("wlan") == wlan)
        )

        # Fetch per-site findings, per-site health, and org-wide findings in one pipeline round trip
        sites_sorted = sorted(site_map.items(), key=lambda x: x[1].lower())
        pipe = redis_client.pipeline()
        for sid, _ in sites_sorted:
            pipe.get(_findings_redis_key(sid, wlan))
            pipe.get(_health_redis_key(sid, wlan))
        pipe.get(_org_findings_redis_key(wlan))
        pipeline_results = await pipe.execute()

        n = len(sites_sorted)
        findings_by_site = {
            sid: (json.loads(pipeline_results[i * 2]) if pipeline_results[i * 2] else [])
            for i, (sid, _) in enumerate(sites_sorted)
        }
        health_by_site = {
            sid: (json.loads(pipeline_results[i * 2 + 1]) if pipeline_results[i * 2 + 1] else {})
            for i, (sid, _) in enumerate(sites_sorted)
        }
        raw_org = pipeline_results[n * 2]
        org_findings = json.loads(raw_org) if raw_org else []

        _SUMMARY_HEALTH_THRESHOLD = 0.75

        result = []
        for sid, site_name in sites_sorted:
            findings = findings_by_site[sid]
            health = health_by_site[sid]
            event_count = events_per_site.get(sid, 0)
            # alert_count: families that are both anomalous (in findings) AND unhealthy
            alert_count = sum(
                1 for f in findings
                if health.get(f.get("device_family"), {}).get("health_score", 1.0) < _SUMMARY_HEALTH_THRESHOLD
            )
            result.append({
                "site_id": sid,
                "site_name": site_name,
                "finding_count": len(findings),
                "critical_count": sum(1 for f in findings if f.get("severity") == "significant"),
                "warning_count": sum(1 for f in findings if f.get("severity") == "moderate"),
                "info_count": sum(1 for f in findings if f.get("severity") == "minimal"),
                "alert_count": alert_count,
                "event_count": event_count,
                "has_data": event_count > 0,
            })
    finally:
        await redis_client.aclose()

    return {
        "sites": result,
        "total_sites": len(result),
        "org_significant_count": sum(1 for f in org_findings if f.get("severity") == "significant"),
        "org_moderate_count": sum(1 for f in org_findings if f.get("severity") == "moderate"),
        "org_minimal_count": sum(1 for f in org_findings if f.get("severity") == "minimal"),
        "org_alert_count": sum(
            1 for f in org_findings if f.get("health_score", 1.0) < _SUMMARY_HEALTH_THRESHOLD
        ),
        "org_finding_count": len(org_findings),
    }


@router.post("/org/run")
async def trigger_org_detection_run(background_tasks: BackgroundTasks):
    """
    Trigger the full 24hr detection pipeline for every site in the org as background tasks.
    Returns immediately. Poll GET /org/progress for per-site status.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        site_ids = await _get_org_site_ids(redis_client)
    except Exception:
        raise HTTPException(status_code=502, detail="Could not reach Mist API")
    finally:
        await redis_client.aclose()

    for sid in site_ids:
        background_tasks.add_task(_detection_background_task, sid)

    return {
        "status": "started",
        "site_count": len(site_ids),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/org/detect")
async def trigger_org_detect_only():
    """
    Re-run feature engineering + org-wide anomaly scoring for every site in the org
    using events already in Redis. Does not pull new events from Mist.

    Runs in two phases:
      1. Build features for all sites.
      2. Pool all site features and run score_org_wide() per WLAN scope so every MAC
         is scored against the full org population (DBSCAN, Family Centroid IF, and
         Isolation Forest all operate across all sites combined).

    Results are written to sasquatch:org_findings:{site_id}:{wlan} — the same keys
    read by GET /org/findings.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        site_ids = await _get_org_site_ids(redis_client)
    except Exception:
        raise HTTPException(status_code=502, detail="Could not reach Mist API")
    finally:
        await redis_client.aclose()

    # Phase 1 — build features, health scores, and per-site findings for all sites.
    wlans_by_site: dict[str, list[str]] = {}
    for sid in site_ids:
        try:
            wlans = await get_wlans(site_id=sid)
            wlans_by_site[sid] = wlans
            for wlan in ["__all__"] + wlans:
                await build_features(sid, wlan)
                await score_health(sid, wlan)
                await score(sid, wlan)
        except Exception:
            log.exception(f"Org detect: feature build failed for site {sid}")
            wlans_by_site.setdefault(sid, [])

    # Phase 2 — pool all site features and run org-wide cross-site scoring.
    all_wlans: set[str] = {"__all__"}
    for wlans in wlans_by_site.values():
        all_wlans.update(wlans)

    total_macs_scored: dict[str, int] = {}
    for wlan in sorted(all_wlans):
        features_this_wlan: dict[str, dict] = {}
        for sid in site_ids:
            site_features = await get_features(sid, wlan)
            if site_features:
                features_this_wlan[sid] = site_features

        if not features_this_wlan:
            continue

        try:
            scored = await score_org_wide(features_this_wlan, wlan=wlan)
            for sid, n in scored.items():
                total_macs_scored[sid] = total_macs_scored.get(sid, 0) + n
        except Exception:
            log.exception(f"Org detect: score_org_wide failed for wlan={wlan}")

    org_findings = await _get_org_findings_for_site()
    results = [
        {
            "site_id": sid,
            "status": "ok",
            "macs_scored": total_macs_scored.get(sid, 0),
        }
        for sid in site_ids
    ]

    return {
        "status": "ok",
        "site_count": len(site_ids),
        "finding_count": len(org_findings),
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/org/flush")
async def flush_org_redis():
    """
    Delete all sasquatch Redis state for every site in the org.
    Calls the per-site flush logic for each site, then also removes the
    org-level sites cache so the next request re-fetches from Mist.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        site_ids = await _get_org_site_ids(redis_client)
    except Exception:
        raise HTTPException(status_code=502, detail="Could not reach Mist API")

    results = []
    total_deleted = 0
    try:
        for sid in site_ids:
            deleted = 0
            static_keys = [
                f"sasquatch:events:{sid}",
                f"sasquatch:wlans:{sid}",
                f"sasquatch:clients:{sid}",
                f"sasquatch:unknown_event_types:{sid}",
                f"sasquatch:progress:{sid}",
            ]
            deleted += await redis_client.delete(*static_keys)
            pattern_keys: list[str] = []
            for prefix in ["sasquatch:features:", "sasquatch:anomalies:", "sasquatch:findings:"]:
                scan_cursor = 0
                while True:
                    scan_cursor, found = await redis_client.scan(scan_cursor, match=f"{prefix}{sid}:*", count=100)
                    pattern_keys.extend(found)
                    if scan_cursor == 0:
                        break
            if pattern_keys:
                deleted += await redis_client.delete(*pattern_keys)
            total_deleted += deleted
            results.append({"site_id": sid, "entries_removed": deleted})

        # Also clear the org sites cache
        await redis_client.delete(_ORG_SITES_CACHE_KEY)
    finally:
        await redis_client.aclose()

    log.info(f"Org flush: removed {total_deleted} Redis keys across {len(site_ids)} sites")
    return {
        "status": "ok",
        "site_count": len(site_ids),
        "total_entries_removed": total_deleted,
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/org/refresh")
async def trigger_org_client_refresh():
    """
    Manually trigger a client cache refresh from the Mist API for every site in the org.
    Runs serially per site (same as the per-site /refresh endpoint).
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        site_ids = await _get_org_site_ids(redis_client)
    except Exception:
        raise HTTPException(status_code=502, detail="Could not reach Mist API")
    finally:
        await redis_client.aclose()

    results = []
    total_cached = 0
    for sid in site_ids:
        try:
            count = await refresh_client_cache(sid)
            total_cached += count
            results.append({"site_id": sid, "status": "ok", "clients_cached": count})
        except Exception as exc:
            log.exception(f"Org client refresh failed for site {sid}")
            results.append({"site_id": sid, "status": "error", "detail": str(exc)})

    return {
        "status": "ok",
        "site_count": len(site_ids),
        "total_clients_cached": total_cached,
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


_ORG_SITES_CACHE_KEY = "sasquatch:org_sites_map"
_ORG_SITES_CACHE_TTL = 300  # 5 minutes


async def _get_org_site_map(redis_client) -> dict[str, str]:
    """Return {site_id: site_name} mapping, cached in Redis for 5 minutes."""
    cached = await redis_client.get(_ORG_SITES_CACHE_KEY)
    if cached:
        return json.loads(cached)

    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/sites"
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
    site_map = {s["id"]: s.get("name", s["id"]) for s in resp.json() if "id" in s}
    await redis_client.set(_ORG_SITES_CACHE_KEY, json.dumps(site_map), ex=_ORG_SITES_CACHE_TTL)
    return site_map


async def _get_org_site_ids(redis_client) -> list[str]:
    """Return org site IDs from the cached site map."""
    return list((await _get_org_site_map(redis_client)).keys())


@router.get("/org/progress")
async def get_org_progress():
    """Aggregate detection progress across all org sites."""
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return {"phase": "idle"}

    redis_client = _get_redis()
    progresses: dict[str, dict] = {}
    try:
        site_ids = await _get_org_site_ids(redis_client)
        pipe = redis_client.pipeline()
        for sid in site_ids:
            pipe.get(f"sasquatch:progress:{sid}")
        results = await pipe.execute()
        for sid, raw in zip(site_ids, results):
            if raw:
                progresses[sid] = json.loads(raw)
    except Exception:
        return {"phase": "idle"}
    finally:
        await redis_client.aclose()

    if not progresses:
        return {"phase": "idle", "sites_total": len(site_ids), "sites_complete": 0, "sites_running": 0}

    phases = [p.get("phase", "idle") for p in progresses.values()]
    total_events = sum(p.get("events_fetched", 0) or 0 for p in progresses.values())
    sites_total = len(site_ids)
    sites_running = sum(1 for p in phases if p in ("collecting", "scoring", "starting"))
    sites_complete = sum(1 for p in phases if p == "complete")
    sites_error = sum(1 for p in phases if p == "error")

    if sites_running > 0:
        overall_phase = "collecting"
    elif sites_error > 0 and sites_running == 0:
        overall_phase = "error"
    elif sites_complete > 0 and sites_running == 0:
        overall_phase = "complete"
    else:
        overall_phase = "idle"

    return {
        "phase": overall_phase,
        "events_fetched": total_events,
        "sites_total": sites_total,
        "sites_complete": sites_complete,
        "sites_running": sites_running,
        "message": f"{sites_complete}/{sites_total} sites complete",
    }


@router.get("/org/findings")
async def get_org_findings_endpoint(wlan: str = Query("__all__")):
    """
    Return org-wide anomaly findings produced by the cross-site detection job.

    Reads from sasquatch:org_findings:{wlan} — a single key written by score_org_wide()
    where every MAC was scored against the full org population. Each finding covers one
    device family across ALL sites (e.g. "iPhone: 41/41 devices org-wide") rather than
    one per-site slice. The sites_affected list on each finding is annotated with
    site_name for display.

    Returns an empty list when the org-wide job has not yet run.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")
        raw = await redis_client.get(_org_findings_redis_key(wlan))
    finally:
        await redis_client.aclose()

    if not raw:
        return {"findings": [], "count": 0, "wlan": wlan}

    findings = json.loads(raw)
    for f in findings:
        for sa in f.get("sites_affected", []):
            sa["site_name"] = site_map.get(sa["site_id"], sa["site_id"])

    return {"findings": findings, "count": len(findings), "wlan": wlan}


@router.get("/org/alerts")
async def get_org_alerts(wlan: str = Query("__all__")):
    """
    Return org-wide alerts AND per-site alerts in a single response.

    Org-wide alerts: org findings (cross-site scoring) where health_score < 0.75.
    Site alerts: per-site findings where the family health_score < 0.75, grouped by site.
    Only sites with at least one alert are included in site_alerts.

    All data is read from Redis — no real-time Mist API calls.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    _ALERT_HEALTH_THRESHOLD = 0.75

    redis_client = _get_redis()
    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        sites_sorted = sorted(site_map.items(), key=lambda x: x[1].lower())
        pipe = redis_client.pipeline()
        for sid, _ in sites_sorted:
            pipe.get(_findings_redis_key(sid, wlan))
            pipe.get(_health_redis_key(sid, wlan))
        pipe.get(_org_findings_redis_key(wlan))
        pipeline_results = await pipe.execute()
    finally:
        await redis_client.aclose()

    n = len(sites_sorted)
    findings_by_site = {
        sid: (json.loads(pipeline_results[i * 2]) if pipeline_results[i * 2] else [])
        for i, (sid, _) in enumerate(sites_sorted)
    }
    health_by_site = {
        sid: (json.loads(pipeline_results[i * 2 + 1]) if pipeline_results[i * 2 + 1] else {})
        for i, (sid, _) in enumerate(sites_sorted)
    }
    raw_org = pipeline_results[n * 2]
    org_findings = json.loads(raw_org) if raw_org else []

    # Org-wide alerts: org findings that are also unhealthy
    org_alerts = [
        f for f in org_findings
        if f.get("health_score", 1.0) < _ALERT_HEALTH_THRESHOLD
    ]
    for f in org_alerts:
        for sa in f.get("sites_affected", []):
            sa["site_name"] = site_map.get(sa["site_id"], sa["site_id"])

    # Per-site alerts: per-site findings cross-referenced with per-site health
    site_alerts = []
    for sid, site_name in sites_sorted:
        findings = findings_by_site[sid]
        health = health_by_site[sid]
        alerts = [
            {**f, "health_score": health.get(f.get("device_family"), {}).get("health_score", 1.0),
             "health_components": health.get(f.get("device_family"), {}).get("components")}
            for f in findings
            if health.get(f.get("device_family"), {}).get("health_score", 1.0) < _ALERT_HEALTH_THRESHOLD
        ]
        if alerts:
            site_alerts.append({
                "site_id": sid,
                "site_name": site_name,
                "alerts": alerts,
            })

    return {
        "org_alerts": org_alerts,
        "site_alerts": site_alerts,
        "wlan": wlan,
    }


@router.get("/org/family-insights")
async def get_org_family_insights(wlan: str = Query("__all__")):
    """
    Aggregate event category counts and anomaly findings per device family across all org sites.
    Optionally scoped to a specific WLAN via ?wlan=.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        # Load all events once (per-site sorted sets fetched in one pipeline inside get_events()).
        all_events = await get_events()
        events_by_site: dict[str, list[dict]] = defaultdict(list)
        for evt in all_events:
            sid = evt.get("site_id")
            if sid and (wlan == "__all__" or evt.get("wlan") == wlan):
                events_by_site[sid].append(evt)

        # Fetch per-site findings, anomalies, and health scores in one pipeline round trip.
        # Anomalies carry family_centroid_if_score on every MAC, so the centroid
        # score is available even when a family's outlier_ratio is below the
        # finding threshold (i.e. no finding was generated for that family).
        site_ids_ordered = list(site_map.keys())
        pipe = redis_client.pipeline()
        for sid in site_ids_ordered:
            pipe.get(_findings_redis_key(sid, wlan))
            pipe.get(_anomalies_redis_key(sid, wlan))
            pipe.get(_health_redis_key(sid, wlan))
        pipeline_results = await pipe.execute()
        findings_by_site = {
            sid: (json.loads(pipeline_results[i * 3]) if pipeline_results[i * 3] else [])
            for i, sid in enumerate(site_ids_ordered)
        }
        anomalies_by_site_insights = {
            sid: (json.loads(pipeline_results[i * 3 + 1]) if pipeline_results[i * 3 + 1] else {})
            for i, sid in enumerate(site_ids_ordered)
        }
        health_by_site = {
            sid: (json.loads(pipeline_results[i * 3 + 2]) if pipeline_results[i * 3 + 2] else {})
            for i, sid in enumerate(site_ids_ordered)
        }

        SEVERITY_RANK = {"significant": 3, "moderate": 2, "minimal": 1}

        family_event_counts: dict[str, Counter] = defaultdict(Counter)
        family_total_events: Counter = Counter()
        family_worst_severity: dict[str, str] = {}
        family_outlier_sites: dict[str, list[str]] = defaultdict(list)
        family_is_family_outlier: dict[str, bool] = defaultdict(bool)
        family_site_count: Counter = Counter()
        family_macs: dict[str, set] = defaultdict(set)
        # Track worst (most anomalous = most negative) centroid IF score and its top_features
        family_worst_centroid_if_score: dict[str, float] = {}
        family_worst_centroid_top_features: dict[str, list] = {}
        # Health score aggregation: weighted sum and total weight per family for averaging
        family_health_weighted_sum: dict[str, float] = defaultdict(float)
        family_health_weight_total: dict[str, float] = defaultdict(float)
        family_health_components_sum: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        sites_with_data = 0

        for site_id, site_name in site_map.items():
            events = events_by_site.get(site_id, [])
            if not events:
                continue
            sites_with_data += 1
            findings: list[dict] = findings_by_site[site_id]

            seen_families: set[str] = set()
            for event in events:
                family = event.get("device_family", "Unknown")
                category = event.get("event_category", "OTHER")
                family_event_counts[family][category] += 1
                family_total_events[family] += 1
                seen_families.add(family)
                mac = (event.get("mac") or "").replace(":", "").lower()
                if mac:
                    family_macs[family].add(mac)
            for fam in seen_families:
                family_site_count[fam] += 1

            for finding in findings:
                fam = finding.get("device_family")
                if not fam:
                    continue
                sev = finding.get("severity")
                if sev and SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(family_worst_severity.get(fam, ""), 0):
                    family_worst_severity[fam] = sev
                if finding.get("is_family_outlier"):
                    family_is_family_outlier[fam] = True
                if sev in SEVERITY_RANK:
                    family_outlier_sites[fam].append(site_name)

            # Accumulate health scores — volume-weighted by total_events per family at this site
            site_health = health_by_site.get(site_id, {})
            for fam, hdata in site_health.items():
                weight = hdata.get("total_events", 0)
                if weight > 0:
                    family_health_weighted_sum[fam] += hdata.get("health_score", 1.0) * weight
                    family_health_weight_total[fam] += weight
                    for comp, rate in hdata.get("components", {}).items():
                        family_health_components_sum[fam][comp] += rate * weight

            # Collect worst centroid IF score from anomaly records (available even when
            # no finding exists for a family at this site).
            site_anomaly_map = anomalies_by_site_insights.get(site_id, {})
            seen_fam_centroid: set[str] = set()
            for mac_data in site_anomaly_map.values():
                fam = mac_data.get("device_family")
                if not fam or fam in seen_fam_centroid:
                    continue
                c_score = mac_data.get("family_centroid_if_score")
                if c_score is not None:
                    seen_fam_centroid.add(fam)
                    if fam not in family_worst_centroid_if_score or c_score < family_worst_centroid_if_score[fam]:
                        family_worst_centroid_if_score[fam] = c_score
                        # Use top_features from the finding if one exists for this family/site
                        fam_finding = next((f for f in findings if f.get("device_family") == fam), None)
                        family_worst_centroid_top_features[fam] = fam_finding.get("top_features", []) if fam_finding else []
    finally:
        await redis_client.aclose()

    all_categories = list(EVENT_CATEGORIES.keys()) + ["OTHER"]
    families_out: dict[str, dict] = {}
    for family, cat_counts in family_event_counts.items():
        total = family_total_events[family]
        health_weight = family_health_weight_total.get(family, 0.0)
        health_score = (
            round(family_health_weighted_sum[family] / health_weight, 4)
            if health_weight > 0 else None
        )
        health_components = (
            {
                comp: round(family_health_components_sum[family][comp] / health_weight, 4)
                for comp in family_health_components_sum.get(family, {})
            }
            if health_weight > 0 else None
        )
        families_out[family] = {
            "total_events": total,
            "client_count": len(family_macs.get(family, set())),
            "site_count": family_site_count[family],
            "worst_severity": family_worst_severity.get(family),
            "is_family_outlier_any_site": family_is_family_outlier.get(family, False),
            "outlier_sites": family_outlier_sites.get(family, []),
            "worst_centroid_if_score": family_worst_centroid_if_score.get(family),
            "worst_centroid_top_features": family_worst_centroid_top_features.get(family, []),
            "health_score": health_score,
            "health_components": health_components,
            "categories": {
                cat: {
                    "count": cat_counts.get(cat, 0),
                    "ratio": round(cat_counts.get(cat, 0) / total, 4) if total > 0 else 0.0,
                }
                for cat in all_categories
            },
        }

    return {
        "families": families_out,
        "categories": list(EVENT_CATEGORIES.keys()),
        "total_sites": len(site_map),
        "sites_with_data": sites_with_data,
    }


@router.get("/org/families/{family}/drilldown")
async def get_org_family_drilldown(family: str, wlan: str = Query("__all__")):
    """
    Org-wide per-MAC drilldown for a single device family.
    Optionally scoped to a specific WLAN via ?wlan=.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    rows: list[dict] = []
    total_if_outliers = 0

    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        # Load all events once (per-site sorted sets fetched in one pipeline inside get_events()).
        all_events = await get_events()
        events_by_site: dict[str, list[dict]] = defaultdict(list)
        for evt in all_events:
            sid = evt.get("site_id")
            if sid and (wlan == "__all__" or evt.get("wlan") == wlan):
                events_by_site[sid].append(evt)

        # Fetch anomalies, client caches, and findings for all sites in one pipeline round trip
        site_ids_ordered = list(site_map.keys())
        pipe = redis_client.pipeline()
        for sid in site_ids_ordered:
            pipe.get(_anomalies_redis_key(sid, wlan))
            pipe.get(f"sasquatch:clients:{sid}")
            pipe.get(_findings_redis_key(sid, wlan))
        pipeline_results = await pipe.execute()
        anomalies_by_site = {
            sid: (json.loads(pipeline_results[i * 3]) if pipeline_results[i * 3] else None)
            for i, sid in enumerate(site_ids_ordered)
        }
        clients_by_site = {
            sid: (json.loads(pipeline_results[i * 3 + 1]) if pipeline_results[i * 3 + 1] else {})
            for i, sid in enumerate(site_ids_ordered)
        }
        findings_by_site = {
            sid: (json.loads(pipeline_results[i * 3 + 2]) if pipeline_results[i * 3 + 2] else [])
            for i, sid in enumerate(site_ids_ordered)
        }

        # Collect worst centroid IF score from anomaly records across sites.
        # Reading from per-MAC anomaly records (not findings) means the score is available
        # even when a family's outlier_ratio is below the finding threshold.
        worst_centroid_if_score: float | None = None
        worst_centroid_top_features: list = []
        for sid in site_ids_ordered:
            site_anomalies = anomalies_by_site.get(sid)
            if not site_anomalies:
                continue
            seen_score_this_site = False
            for mac_data in site_anomalies.values():
                if mac_data.get("device_family") != family:
                    continue
                c_score = mac_data.get("family_centroid_if_score")
                if c_score is not None and not seen_score_this_site:
                    seen_score_this_site = True
                    if worst_centroid_if_score is None or c_score < worst_centroid_if_score:
                        worst_centroid_if_score = c_score
                        # Pull top_features from the finding for this site/family if available
                        site_findings = findings_by_site.get(sid, [])
                        fam_finding = next((f for f in site_findings if f.get("device_family") == family), None)
                        worst_centroid_top_features = fam_finding.get("top_features", []) if fam_finding else []

        for site_id, site_name in site_map.items():
            anomalies_raw_data = anomalies_by_site.get(site_id)
            if not anomalies_raw_data:
                continue

            anomalies: dict = anomalies_raw_data
            client_cache: dict = clients_by_site.get(site_id, {})

            mac_categories: dict[str, Counter] = defaultdict(Counter)
            mac_total: dict[str, int] = defaultdict(int)
            family_macs: set[str] = set()
            for event in events_by_site.get(site_id, []):
                if event.get("device_family") != family:
                    continue
                mac = (event.get("mac") or "").replace(":", "").lower()
                if not mac:
                    continue
                mac_categories[mac][event.get("event_category", "OTHER")] += 1
                mac_total[mac] += 1
                family_macs.add(mac)

            for mac, data in anomalies.items():
                if mac not in family_macs:
                    continue
                is_if_outlier = data.get("is_if_outlier", False)
                if is_if_outlier:
                    total_if_outliers += 1
                rows.append({
                    "mac": mac,
                    "site_id": site_id,
                    "site_name": site_name,
                    "if_score": data.get("if_score"),
                    "is_if_outlier": is_if_outlier,
                    "is_dbscan_outlier": data.get("is_dbscan_outlier", False),
                    "event_count": data.get("event_count", 0),
                    "random_mac": data.get("random_mac", False),
                    "client_metadata": client_cache.get(mac, {}),
                    "categories": {cat: mac_categories[mac].get(cat, 0) for cat in EVENT_CATEGORIES},
                    "total_events": mac_total.get(mac, data.get("event_count", 0)),
                })
    finally:
        await redis_client.aclose()

    if not rows:
        raise HTTPException(status_code=404, detail=f"No data found for family '{family}' across any site.")

    rows.sort(key=lambda x: (x["if_score"] is None, x["if_score"] or 0))

    return {
        "family": family,
        "total_count": len(rows),
        "if_outlier_count": total_if_outliers,
        "rows": rows,
        "category_keys": list(EVENT_CATEGORIES.keys()),
        "worst_centroid_if_score": worst_centroid_if_score,
        "worst_centroid_top_features": worst_centroid_top_features,
    }


@router.get("/org/sites")
async def list_org_sites():
    """Fetch all sites in the configured org from the Mist API (cached 5 min)."""
    if not MIST_ORG_ID:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID not configured.")
    if not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        site_map = await _get_org_site_map(redis_client)
    except Exception:
        raise HTTPException(status_code=502, detail="Could not reach Mist API")
    finally:
        await redis_client.aclose()

    sites = sorted(
        [{"id": sid, "name": name} for sid, name in site_map.items()],
        key=lambda s: s["name"].lower(),
    )
    return {"sites": sites}


@router.get("/org/cluster-viz")
async def get_org_cluster_viz(wlan: str = Query("__all__")):
    """
    PCA 2D projection of all MAC feature vectors across every org site.
    Optionally scoped to a specific WLAN via ?wlan=.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    keyed_features: dict[str, dict] = {}
    keyed_anomalies: dict[str, dict] = {}
    key_site: dict[str, str] = {}

    try:
        site_map = await _get_org_site_map(redis_client)
        # Fetch features and anomalies for all sites in one pipeline round trip
        site_ids_ordered = list(site_map.keys())
        pipe = redis_client.pipeline()
        for sid in site_ids_ordered:
            pipe.get(_features_redis_key(sid, wlan))
            pipe.get(_anomalies_redis_key(sid, wlan))
        pipeline_results = await pipe.execute()

        for i, site_id in enumerate(site_ids_ordered):
            raw_feat = pipeline_results[i * 2]
            raw_anom = pipeline_results[i * 2 + 1]
            if not raw_feat:
                continue
            features = json.loads(raw_feat)
            anomalies = json.loads(raw_anom) if raw_anom else {}
            for mac, fdata in features.items():
                nk = f"{site_id}::{mac}"
                keyed_features[nk] = fdata
                keyed_anomalies[nk] = anomalies.get(mac, {})
                key_site[nk] = site_id
    finally:
        await redis_client.aclose()

    if len(keyed_features) < 3:
        return {"points": [], "explained_variance": [], "total_points": 0}

    keys = list(keyed_features.keys())
    vec_keys = list(keyed_features[keys[0]]["vector"].keys())
    X = np.array([[keyed_features[k]["vector"].get(vk, 0.0) for vk in vec_keys] for k in keys])

    loop = asyncio.get_event_loop()
    coords, explained_variance = await loop.run_in_executor(_CPU_POOL, _run_pca, X)

    points = []
    for i, nk in enumerate(keys):
        anom = keyed_anomalies.get(nk, {})
        site_id = key_site[nk]
        mac = nk.split("::", 1)[1]
        points.append({
            "mac": mac,
            "site_id": site_id,
            "site_name": site_map.get(site_id, site_id),
            "x": float(coords[i, 0]),
            "y": float(coords[i, 1]),
            "device_family": keyed_features[nk].get("device_family", "Unknown"),
            "is_outlier": anom.get("is_outlier", False),
            "is_dbscan_outlier": anom.get("is_dbscan_outlier", False),
            "dbscan_label": anom.get("dbscan_label"),
        })

    return {
        "points": points,
        "explained_variance": [round(v, 4) for v in explained_variance],
        "total_points": len(points),
        "site_count": len(site_map),
    }


@router.get("/sites/{site_id}/findings")
async def get_site_findings(site_id: str, wlan: str = Query("__all__")):
    """Current anomaly findings from Redis for a site, optionally scoped to a WLAN."""
    findings = await get_findings(site_id, wlan)
    return {"site_id": site_id, "wlan": wlan, "findings": findings, "count": len(findings)}


@router.get("/sites/{site_id}/health")
async def get_site_health(site_id: str, wlan: str = Query("__all__")):
    """
    Per-family health scores for a site, optionally scoped to a WLAN.
    Returns {family: {health_score, components, total_events, mac_count}}.
    health_score ranges 0.0 (all failures) to 1.0 (no failures).
    """
    health = await get_health(site_id, wlan)
    return {"site_id": site_id, "wlan": wlan, "health": health}


@router.get("/sites/{site_id}/clients")
async def get_site_clients(site_id: str):
    """
    Client list with device type breakdown.
    Returns family summary counts and full MAC → metadata mapping.
    """
    client_cache = await get_client_cache(site_id)
    if not client_cache:
        raise HTTPException(status_code=404, detail="Client cache not found. Run /refresh first.")

    family_counts: Counter = Counter(v.get("family", "Unknown") for v in client_cache.values())
    return {
        "site_id": site_id,
        "total_clients": len(client_cache),
        "by_family": dict(family_counts),
        "clients": client_cache,
    }


@router.get("/sites/{site_id}/events/summary")
async def get_events_summary(site_id: str, wlan: str = Query("__all__")):
    """
    Event category counts per device family — used for heatmap in SiteOverview.
    Optionally scoped to a specific WLAN via ?wlan=.
    """
    events = await get_events(
        site_id=site_id,
        wlan=wlan if wlan != "__all__" else None,
    )
    if not events:
        raise HTTPException(status_code=404, detail="No events found for site.")

    summary: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    family_totals: Counter = Counter()
    family_macs: dict[str, set] = defaultdict(set)

    for event in events:
        family = event.get("device_family", "Unknown")
        category = event.get("event_category", "OTHER")
        summary[family][category] += 1
        family_totals[family] += 1
        mac = (event.get("mac") or "").replace(":", "").lower()
        if mac:
            family_macs[family].add(mac)

    result = {}
    for family, cat_counts in summary.items():
        total = family_totals[family]
        result[family] = {
            cat: {
                "count": count,
                "ratio": round(count / total, 4) if total > 0 else 0.0,
            }
            for cat, count in cat_counts.items()
        }

    return {
        "site_id": site_id,
        "wlan": wlan,
        "total_events": len(events),
        "families": result,
        "family_client_counts": {fam: len(macs) for fam, macs in family_macs.items()},
        "categories": list(EVENT_CATEGORIES.keys()),
    }


@router.get("/sites/{site_id}/families/{family}/if-outliers")
async def get_family_if_outliers(site_id: str, family: str, wlan: str = Query("__all__")):
    """
    MACs within a device family that triggered an Isolation Forest deviation.
    Used by the Family Drilldown view. Optionally scoped to a WLAN.
    """
    anomalies = await get_anomalies(site_id, wlan)
    if not anomalies:
        raise HTTPException(status_code=404, detail="No anomaly data found. Run detection first.")

    client_cache = await get_client_cache(site_id)

    family_macs = [
        mac for mac, data in anomalies.items()
        if data.get("device_family") == family
    ]
    if not family_macs:
        raise HTTPException(status_code=404, detail=f"No clients found for family '{family}'.")

    all_clients = [
        {
            "mac": mac,
            "if_score": anomalies[mac].get("if_score"),
            "is_if_outlier": anomalies[mac].get("is_if_outlier", False),
            "is_dbscan_outlier": anomalies[mac].get("is_dbscan_outlier", False),
            "event_count": anomalies[mac].get("event_count", 0),
            "random_mac": anomalies[mac].get("random_mac", False),
            "client_metadata": client_cache.get(mac, {}),
        }
        for mac in family_macs
    ]

    all_clients.sort(key=lambda x: (x["if_score"] is None, x["if_score"] or 0))
    if_outlier_count = sum(1 for c in all_clients if c["is_if_outlier"])

    # Pull centroid_if_score from anomaly records (available for all families where
    # centroid IF ran, regardless of whether a finding was generated).
    # Fall back to the stored finding for top_features.
    centroid_if_score = next(
        (anomalies[m].get("family_centroid_if_score")
         for m in family_macs
         if anomalies[m].get("family_centroid_if_score") is not None),
        None,
    )
    findings = await get_findings(site_id, wlan)
    family_finding = next((f for f in findings if f.get("device_family") == family), None)
    family_top_features = family_finding.get("top_features", []) if family_finding else []

    return {
        "site_id": site_id,
        "family": family,
        "wlan": wlan,
        "total_family_count": len(family_macs),
        "if_outlier_count": if_outlier_count,
        "outliers": all_clients,
        "centroid_if_score": centroid_if_score,
        "top_features": family_top_features,
    }


@router.get("/sites/{site_id}/families/{family}/event-counts")
async def get_family_event_counts(site_id: str, family: str, wlan: str = Query("__all__")):
    """
    Per-MAC event category counts for all clients in a device family.
    Used by the Family Drilldown Event Counts view. Optionally scoped to a WLAN.
    """
    events = await get_events(
        site_id=site_id,
        wlan=wlan if wlan != "__all__" else None,
    )
    if not events:
        raise HTTPException(status_code=404, detail="No events found for site.")

    client_cache = await get_client_cache(site_id)

    mac_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    mac_total: dict[str, int] = defaultdict(int)
    family_macs: set[str] = set()

    for event in events:
        if event.get("device_family") != family:
            continue
        mac = (event.get("mac") or "").replace(":", "").lower()
        if not mac:
            continue
        category = event.get("event_category", "OTHER")
        mac_counts[mac][category] += 1
        mac_total[mac] += 1
        family_macs.add(mac)

    if not family_macs:
        raise HTTPException(status_code=404, detail=f"No clients found for family '{family}'.")

    clients = []
    for mac in sorted(family_macs):
        meta = client_cache.get(mac, {})
        clients.append({
            "mac": mac,
            "random_mac": meta.get("random_mac", False),
            "client_metadata": meta,
            "categories": {cat: mac_counts[mac].get(cat, 0) for cat in EVENT_CATEGORIES},
            "total_events": mac_total[mac],
        })

    return {
        "site_id": site_id,
        "family": family,
        "wlan": wlan,
        "clients": clients,
        "category_keys": list(EVENT_CATEGORIES.keys()),
    }


@router.get("/sites/{site_id}/anomalies/{mac}")
async def get_mac_anomaly(site_id: str, mac: str, wlan: str = Query("__all__")):
    """
    Full event timeline + anomaly scores for one MAC.
    Used by MAC Drill-down view. Optionally scoped to a WLAN.
    """
    mac_normalized = mac.replace(":", "").lower()

    anomalies = await get_anomalies(site_id, wlan)
    mac_scores = anomalies.get(mac_normalized)
    if mac_scores is None:
        raise HTTPException(status_code=404, detail=f"No anomaly data for MAC {mac}")

    raw_features = await _redis_get(_features_redis_key(site_id, wlan))
    features = json.loads(raw_features) if raw_features else {}
    mac_features = features.get(mac_normalized, {})

    # Event timeline — always show ALL events for this MAC regardless of WLAN scope
    # so the admin can see the full picture of this device's behavior
    all_events = await get_events(site_id=site_id)
    mac_events = [
        e for e in all_events
        if (e.get("mac") or "").replace(":", "").lower() == mac_normalized
    ]
    mac_events.sort(key=lambda e: e.get("timestamp", 0))

    client_cache = await get_client_cache(site_id)
    client_meta = client_cache.get(mac_normalized, {})

    # Compute per-MAC Shapley features: top feature deviations vs family mean
    shapley_features: list[dict] = []
    mac_vec = mac_features.get("vector", {})
    device_family = mac_scores.get("device_family", "Unknown")
    if mac_vec and features:
        family_vectors = [
            features[m]["vector"]
            for m in features
            if features[m].get("device_family") == device_family and m != mac_normalized
        ]
        if family_vectors:
            keys = list(mac_vec.keys())
            family_arr = np.array([[v.get(k, 0.0) for k in keys] for v in family_vectors])
            family_means = family_arr.mean(axis=0)
            mac_arr = np.array([mac_vec.get(k, 0.0) for k in keys])
            diffs = np.abs(mac_arr - family_means)
            top_indices = np.argsort(diffs)[::-1][:5]
            shapley_features = [
                {
                    "feature": keys[i],
                    "outlier_mean": float(mac_arr[i]),
                    "baseline_mean": float(family_means[i]),
                }
                for i in top_indices
            ]

    return {
        "mac": mac_normalized,
        "site_id": site_id,
        "wlan": wlan,
        "client_metadata": client_meta,
        "anomaly_scores": mac_scores,
        "feature_vector": mac_features.get("vector", {}),
        "shapley_features": shapley_features,
        "event_count": len(mac_events),
        "events": mac_events,
    }


@router.post("/sites/{site_id}/refresh")
async def trigger_client_refresh(site_id: str):
    """Manually trigger a client cache refresh from the Mist API."""
    try:
        count = await refresh_client_cache(site_id)
        return {
            "site_id": site_id,
            "status": "ok",
            "clients_cached": count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        log.exception(f"Manual client refresh failed for site {site_id}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sites/{site_id}/flush")
async def flush_site_redis(site_id: str):
    """
    Delete all sasquatch Redis state for a site.
    Removes the per-site event sorted set and WLAN set, and deletes all
    per-site per-WLAN feature/anomaly/finding keys via pattern scan.
    """
    client = _get_redis()
    deleted = 0
    try:
        # Delete the per-site event sorted set and WLAN set directly
        static_keys = [
            f"sasquatch:events:{site_id}",
            f"sasquatch:wlans:{site_id}",
            f"sasquatch:clients:{site_id}",
            f"sasquatch:unknown_event_types:{site_id}",
            f"sasquatch:progress:{site_id}",
        ]
        deleted += await client.delete(*static_keys)

        # Scan for per-WLAN feature/anomaly/finding keys
        pattern_keys: list[str] = []
        for prefix in ["sasquatch:features:", "sasquatch:anomalies:", "sasquatch:findings:"]:
            scan_cursor = 0
            while True:
                scan_cursor, found = await client.scan(scan_cursor, match=f"{prefix}{site_id}:*", count=100)
                pattern_keys.extend(found)
                if scan_cursor == 0:
                    break
        if pattern_keys:
            deleted += await client.delete(*pattern_keys)

    finally:
        await client.aclose()

    log.info(f"Flushed {deleted} Redis keys for site {site_id}")
    return {
        "site_id": site_id,
        "status": "ok",
        "entries_removed": deleted,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sites/{site_id}/run")
async def trigger_full_detection_run(site_id: str, background_tasks: BackgroundTasks):
    """
    Start the full 24hr detection pipeline as a background task.
    Returns immediately with status "started". Poll GET /progress for live updates.
    Returns 409 if a cycle is already in progress.
    """
    client = _get_redis()
    try:
        locked = await client.exists(f"sasquatch:lock:detection:{site_id}")
    finally:
        await client.aclose()

    if locked:
        raise HTTPException(status_code=409, detail="Detection cycle already running for this site")

    background_tasks.add_task(_detection_background_task, site_id)
    return {"status": "started", "site_id": site_id, "timestamp": datetime.now(timezone.utc).isoformat()}


@router.post("/sites/{site_id}/unlock")
async def unlock_detection(site_id: str):
    """Force-release the detection lock for a site."""
    client = _get_redis()
    try:
        deleted = await client.delete(f"sasquatch:lock:detection:{site_id}")
    finally:
        await client.aclose()
    return {
        "site_id": site_id,
        "status": "ok" if deleted else "no_lock",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sites/{site_id}/collect")
async def trigger_event_collection(site_id: str):
    """
    Pull 24hr events from Mist and store in the global Redis sorted set.
    Does not run anomaly detection. Returns 409 if a cycle is already in progress.
    """
    try:
        summary = await run_collect_only(site_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:
        log.exception(f"Event collection failed for site {site_id}")
        raise HTTPException(status_code=500, detail=str(exc))

    return {
        "site_id": site_id,
        "status": "ok",
        "events_collected": summary["events"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sites/{site_id}/detect")
async def trigger_anomaly_detection(site_id: str):
    """
    Run feature engineering + anomaly scoring on events already in Redis.
    Runs for __all__ WLANs + each unique WLAN in the event data.
    Does not pull new events from Mist — use /collect first.
    Returns 409 if a cycle is already in progress, 404 if no events in Redis.
    """
    try:
        summary = await run_detect_only(site_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        log.exception(f"Anomaly detection failed for site {site_id}")
        raise HTTPException(status_code=500, detail=str(exc))

    findings = await get_findings(site_id)
    return {
        "site_id": site_id,
        "status": "ok",
        "macs_with_features": summary["macs_with_features"],
        "macs_scored": summary["macs_scored"],
        "wlan_scopes": summary.get("wlan_scopes", 1),
        "findings_generated": len(findings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/sites/{site_id}/cluster-viz")
async def get_cluster_viz(site_id: str, wlan: str = Query("__all__")):
    """
    PCA 2D projection of all MAC feature vectors for the cluster scatter plot.
    Optionally scoped to a specific WLAN via ?wlan=.
    """
    raw_features = await _redis_get(_features_redis_key(site_id, wlan))
    if not raw_features:
        raise HTTPException(status_code=404, detail="No features found. Run detection first.")

    features: dict = json.loads(raw_features)
    if len(features) < 3:
        return {"site_id": site_id, "points": [], "explained_variance": []}

    raw_anomalies = await _redis_get(_anomalies_redis_key(site_id, wlan))
    anomalies: dict = json.loads(raw_anomalies) if raw_anomalies else {}

    macs = list(features.keys())
    vec_keys = list(features[macs[0]]["vector"].keys())
    X = np.array([[features[m]["vector"].get(k, 0.0) for k in vec_keys] for m in macs])

    loop = asyncio.get_event_loop()
    coords, explained_variance = await loop.run_in_executor(_CPU_POOL, _run_pca, X)

    points = []
    for i, mac in enumerate(macs):
        anom = anomalies.get(mac, {})
        points.append({
            "mac": mac,
            "x": float(coords[i, 0]),
            "y": float(coords[i, 1]),
            "device_family": features[mac].get("device_family", "Unknown"),
            "is_outlier": anom.get("is_outlier", False),
            "is_dbscan_outlier": anom.get("is_dbscan_outlier", False),
            "dbscan_label": anom.get("dbscan_label"),
        })

    return {
        "site_id": site_id,
        "wlan": wlan,
        "points": points,
        "explained_variance": [round(v, 4) for v in explained_variance],
        "total_points": len(points),
    }


@router.get("/sites/{site_id}/status")
async def get_site_status(site_id: str, wlan: str = Query("__all__")):
    """Last run metadata: event count, finding count, Redis key TTLs."""
    client = _get_redis()
    try:
        clients_ttl = await client.ttl(f"sasquatch:clients:{site_id}")
        features_ttl = await client.ttl(_features_redis_key(site_id, wlan))
        anomalies_ttl = await client.ttl(_anomalies_redis_key(site_id, wlan))
        findings_ttl = await client.ttl(_findings_redis_key(site_id, wlan))

        raw_findings = await client.get(_findings_redis_key(site_id, wlan))
        finding_count = len(json.loads(raw_findings)) if raw_findings else 0

        unknown_types = await client.smembers(f"sasquatch:unknown_event_types:{site_id}")
    finally:
        await client.aclose()

    # Event count from global sorted set
    site_events = await get_events(site_id=site_id, wlan=wlan if wlan != "__all__" else None)

    return {
        "site_id": site_id,
        "wlan": wlan,
        "event_count": len(site_events),
        "finding_count": finding_count,
        "detection_interval_minutes": DETECTION_INTERVAL_MINUTES,
        "redis_ttls": {
            "clients": clients_ttl,
            "features": features_ttl,
            "anomalies": anomalies_ttl,
            "findings": findings_ttl,
        },
        "unknown_event_types": list(unknown_types),
    }

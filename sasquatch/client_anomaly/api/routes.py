"""
routes.py — FastAPI route definitions.

All reads come from Redis — no real-time Mist API calls in the request path.
The API is read-only except for the manual refresh POST.
"""

import json
import logging
import os
import time as _time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

import httpx
import numpy as np
import redis.asyncio as aioredis
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from ..anomaly_detector import get_anomalies, get_findings, score
from ..client_cache import get_client_cache, refresh_client_cache
from ..event_collector import EVENT_CATEGORIES, collect_full
from ..feature_engineer import build_features
from ..scheduler import run_collect_only, run_detect_only, run_detection_cycle
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


def _configured_sites() -> list[str]:
    """Return list of configured site IDs from env."""
    site = os.getenv("MIST_SITE_ID", "")
    return [site] if site else []


async def _redis_get(key: str):
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        return await client.get(key)
    finally:
        await client.aclose()


async def _detection_background_task(site_id: str) -> None:
    """
    Full 24hr detection pipeline run as a FastAPI background task.
    Writes phase-by-phase progress to Redis key sasquatch:progress:{site_id}.
    Manages its own lock so it cannot overlap with the scheduler.
    """
    lock_key = f"sasquatch:lock:detection:{site_id}"
    progress_key = f"sasquatch:progress:{site_id}"
    started = _time.time()

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

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

        # Ensure client cache exists before pulling events; refresh if missing.
        client_cache = await get_client_cache(site_id)
        if not client_cache:
            log.info(f"Client cache missing for site {site_id} — refreshing before full run")
            await refresh_client_cache(site_id)

        async def on_page(page: int, fetched: int, total: Optional[int]) -> None:
            await wp({
                "phase": "collecting",
                "events_fetched": fetched,
                "total_estimated": total,
                "pages": page,
            })

        event_count = await collect_full(site_id, on_page=on_page)

        await wp({"phase": "scoring", "events_fetched": event_count, "total_estimated": event_count, "pages": -1})

        mac_count = await build_features(site_id)
        scored = await score(site_id)

        try:
            await evaluate_and_dispatch(site_id)
        except Exception:
            log.exception(f"Webhook dispatch failed for site {site_id} (non-fatal)")

        await wp({
            "phase": "complete",
            "events_fetched": event_count,
            "total_estimated": event_count,
            "pages": -1,
            "macs_scored": scored,
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
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
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
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await client.set("sasquatch:focus_site", site_id)
    finally:
        await client.aclose()
    log.info(f"Scheduler focus updated to site {site_id}")
    return {"site_id": site_id, "source": "override"}


@router.get("/sites/{site_id}/progress")
async def get_site_progress(site_id: str):
    """Return the latest detection cycle progress for a site (written by the background task)."""
    raw = await _redis_get(f"sasquatch:progress:{site_id}")
    if not raw:
        return {"phase": "idle"}
    return json.loads(raw)


@router.get("/sites")
async def list_sites():
    """List all configured site IDs."""
    return {"sites": _configured_sites()}


@router.get("/org/sites")
async def list_org_sites():
    """Fetch all sites in the configured org from the Mist API."""
    if not MIST_ORG_ID:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID not configured.")
    if not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_API_TOKEN not configured.")

    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/sites"
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.error(f"Mist API error fetching org sites: {exc.response.status_code}")
            raise HTTPException(status_code=502, detail=f"Mist API returned {exc.response.status_code}")
        except httpx.RequestError as exc:
            log.error(f"Network error fetching org sites: {exc}")
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

    raw = resp.json()
    # Mist returns a list of site objects directly
    sites = [{"id": s["id"], "name": s.get("name", s["id"])} for s in raw if "id" in s]
    sites.sort(key=lambda s: s["name"].lower())
    return {"sites": sites}


@router.get("/sites/{site_id}/findings")
async def get_site_findings(site_id: str):
    """Current anomaly findings from Redis, ranked by severity."""
    findings = await get_findings(site_id)
    return {"site_id": site_id, "findings": findings, "count": len(findings)}


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
async def get_events_summary(site_id: str):
    """
    Event category counts per device family — used for heatmap in SiteOverview.
    Returns {family: {category: {success_count, failure_count, total}}}
    """
    raw = await _redis_get(f"sasquatch:events:{site_id}")
    if not raw:
        raise HTTPException(status_code=404, detail="No events found for site.")

    events: list[dict] = json.loads(raw)

    # Build nested counts: family → category → count; track unique MACs per family
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

    # Compute failure ratios per family × category
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
        "total_events": len(events),
        "families": result,
        "family_client_counts": {fam: len(macs) for fam, macs in family_macs.items()},
        "categories": list(EVENT_CATEGORIES.keys()),
    }


@router.get("/sites/{site_id}/families/{family}/if-outliers")
async def get_family_if_outliers(site_id: str, family: str):
    """
    MACs within a device family that triggered an Isolation Forest deviation.
    Used by the Family Drilldown view. Sorted by IF score ascending (most anomalous first).
    """
    anomalies = await get_anomalies(site_id)
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

    # Sort by IF score ascending — most anomalous (most negative) first, None last
    all_clients.sort(key=lambda x: (x["if_score"] is None, x["if_score"] or 0))

    if_outlier_count = sum(1 for c in all_clients if c["is_if_outlier"])

    return {
        "site_id": site_id,
        "family": family,
        "total_family_count": len(family_macs),
        "if_outlier_count": if_outlier_count,
        "outliers": all_clients,
    }


@router.get("/sites/{site_id}/anomalies/{mac}")
async def get_mac_anomaly(site_id: str, mac: str):
    """
    Full event timeline + anomaly scores for one MAC.
    Used by MAC Drill-down view.
    """
    mac_normalized = mac.replace(":", "").lower()

    # Get anomaly scores
    anomalies = await get_anomalies(site_id)
    mac_scores = anomalies.get(mac_normalized)
    if mac_scores is None:
        raise HTTPException(status_code=404, detail=f"No anomaly data for MAC {mac}")

    # Get features
    raw_features = await _redis_get(f"sasquatch:features:{site_id}")
    features = json.loads(raw_features) if raw_features else {}
    mac_features = features.get(mac_normalized, {})

    # Get event timeline
    raw_events = await _redis_get(f"sasquatch:events:{site_id}")
    all_events: list[dict] = json.loads(raw_events) if raw_events else []
    mac_events = [
        e for e in all_events
        if (e.get("mac") or "").replace(":", "").lower() == mac_normalized
    ]
    mac_events.sort(key=lambda e: e.get("timestamp", 0))

    # Get client metadata
    client_cache = await get_client_cache(site_id)
    client_meta = client_cache.get(mac_normalized, {})

    return {
        "mac": mac_normalized,
        "site_id": site_id,
        "client_metadata": client_meta,
        "anomaly_scores": mac_scores,
        "feature_vector": mac_features.get("vector", {}),
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
    """Delete all sasquatch Redis keys for a site (events, features, anomalies, findings)."""
    keys = [
        f"sasquatch:events:{site_id}",
        f"sasquatch:features:{site_id}",
        f"sasquatch:anomalies:{site_id}",
        f"sasquatch:findings:{site_id}",
        f"sasquatch:unknown_event_types:{site_id}",
    ]
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        deleted = await client.delete(*keys)
    finally:
        await client.aclose()
    log.info(f"Flushed {deleted} Redis keys for site {site_id}")
    return {
        "site_id": site_id,
        "status": "ok",
        "keys_deleted": deleted,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/sites/{site_id}/run")
async def trigger_full_detection_run(site_id: str, background_tasks: BackgroundTasks):
    """
    Start the full 24hr detection pipeline as a background task.
    Returns immediately with status "started". Poll GET /progress for live updates.
    Returns 409 if a cycle is already in progress.
    """
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
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
    """Force-release the detection lock for a site. Use when a run was interrupted and left the lock stuck."""
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
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
    Pull 24hr events from Mist and store in Redis. Does not run anomaly detection.
    Returns 409 if a cycle is already in progress.
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
        "findings_generated": len(findings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/sites/{site_id}/cluster-viz")
async def get_cluster_viz(site_id: str):
    """
    PCA 2D projection of all MAC feature vectors for the cluster scatter plot.
    Returns one point per MAC with x/y coordinates, device family, and outlier status.
    """
    raw_features = await _redis_get(f"sasquatch:features:{site_id}")
    if not raw_features:
        raise HTTPException(status_code=404, detail="No features found. Run detection first.")

    features: dict = json.loads(raw_features)
    if len(features) < 3:
        return {"site_id": site_id, "points": [], "explained_variance": []}

    raw_anomalies = await _redis_get(f"sasquatch:anomalies:{site_id}")
    anomalies: dict = json.loads(raw_anomalies) if raw_anomalies else {}

    macs = list(features.keys())
    vec_keys = list(features[macs[0]]["vector"].keys())
    X = np.array([[features[m]["vector"].get(k, 0.0) for k in vec_keys] for m in macs])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    n_components = min(2, X_scaled.shape[0], X_scaled.shape[1])
    pca = PCA(n_components=n_components, random_state=42)
    coords = pca.fit_transform(X_scaled)

    # Pad to 2 columns if PCA could only produce 1 component
    if coords.shape[1] == 1:
        coords = np.hstack([coords, np.zeros((coords.shape[0], 1))])

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
        "points": points,
        "explained_variance": [round(v, 4) for v in pca.explained_variance_ratio_.tolist()],
        "total_points": len(points),
    }


@router.get("/sites/{site_id}/status")
async def get_site_status(site_id: str):
    """Last run metadata: event count, finding count, Redis key TTLs."""
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        events_ttl = await client.ttl(f"sasquatch:events:{site_id}")
        clients_ttl = await client.ttl(f"sasquatch:clients:{site_id}")
        features_ttl = await client.ttl(f"sasquatch:features:{site_id}")
        anomalies_ttl = await client.ttl(f"sasquatch:anomalies:{site_id}")
        findings_ttl = await client.ttl(f"sasquatch:findings:{site_id}")

        raw_events = await client.get(f"sasquatch:events:{site_id}")
        raw_findings = await client.get(f"sasquatch:findings:{site_id}")

        event_count = len(json.loads(raw_events)) if raw_events else 0
        finding_count = len(json.loads(raw_findings)) if raw_findings else 0

        unknown_types = await client.smembers(f"sasquatch:unknown_event_types:{site_id}")
    finally:
        await client.aclose()

    return {
        "site_id": site_id,
        "event_count": event_count,
        "finding_count": finding_count,
        "detection_interval_minutes": DETECTION_INTERVAL_MINUTES,
        "redis_ttls": {
            "clients": clients_ttl,
            "events": events_ttl,
            "features": features_ttl,
            "anomalies": anomalies_ttl,
            "findings": findings_ttl,
        },
        "unknown_event_types": list(unknown_types),
    }

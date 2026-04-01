"""
routes.py — FastAPI route definitions.

All reads come from Redis — no real-time Mist API calls in the request path.
The API is read-only except for the manual refresh POST.
"""

import json
import logging
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException

from ..anomaly_detector import get_anomalies, get_findings, score
from ..client_cache import get_client_cache, refresh_client_cache
from ..event_collector import EVENT_CATEGORIES, collect
from ..feature_engineer import build_features

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
SITE_ID = os.getenv("MIST_SITE_ID", "")
DETECTION_INTERVAL_MINUTES = int(os.getenv("DETECTION_INTERVAL_MINUTES", "15"))


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


@router.get("/sites")
async def list_sites():
    """List all configured site IDs."""
    return {"sites": _configured_sites()}


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

    # Build nested counts: family → category → count
    summary: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    family_totals: Counter = Counter()

    for event in events:
        family = event.get("device_family", "Unknown")
        category = event.get("event_category", "OTHER")
        summary[family][category] += 1
        family_totals[family] += 1

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
        "categories": list(EVENT_CATEGORIES.keys()),
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
async def trigger_full_detection_run(site_id: str):
    """
    Pull 24hr events, build features, score anomalies, and populate findings.
    Runs the full detection pipeline synchronously — same steps as the scheduler job.
    Returns a summary of what was produced.
    """
    try:
        event_count = await collect(site_id)
    except Exception as exc:
        log.exception(f"Event collection failed for site {site_id}")
        raise HTTPException(status_code=500, detail=f"Event collection failed: {exc}")

    try:
        mac_count = await build_features(site_id)
    except Exception as exc:
        log.exception(f"Feature engineering failed for site {site_id}")
        raise HTTPException(status_code=500, detail=f"Feature engineering failed: {exc}")

    try:
        scored = await score(site_id)
    except Exception as exc:
        log.exception(f"Anomaly scoring failed for site {site_id}")
        raise HTTPException(status_code=500, detail=f"Anomaly scoring failed: {exc}")

    findings = await get_findings(site_id)
    return {
        "site_id": site_id,
        "status": "ok",
        "events_collected": event_count,
        "macs_with_features": mac_count,
        "macs_scored": scored,
        "findings_generated": len(findings),
        "timestamp": datetime.now(timezone.utc).isoformat(),
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

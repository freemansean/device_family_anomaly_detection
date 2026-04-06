"""
scheduler.py — APScheduler job definitions.

Jobs:
- client_refresh_job: Daily at 00:00 — refresh client device cache.
- event_and_detect_job: Every DETECTION_INTERVAL_MINUTES — collect events and run detection.

Detection now runs for each unique WLAN present in the site's event data, plus a
combined "__all__" pass that uses events across all WLANs. This allows the frontend
to display WLAN-scoped anomaly findings.
"""

import logging
import os

import httpx
import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .anomaly_detector import score, score_org_wide
from .client_cache import get_client_cache, refresh_client_cache
from .event_collector import collect, collect_full, get_wlans, reenrich_stale_events
from .feature_engineer import build_features, get_features
from .health_scorer import score_health
from .webhook_dispatcher import evaluate_and_dispatch

log = logging.getLogger(__name__)

SITE_ID = os.getenv("MIST_SITE_ID", "")
DETECTION_INTERVAL_MINUTES = int(os.getenv("DETECTION_INTERVAL_MINUTES", "15"))
ORG_DETECTION_INTERVAL_HOURS = int(os.getenv("ORG_DETECTION_INTERVAL_HOURS", "6"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

ORG_FOCUS_VALUE = "__org__"

# Lock TTL: generous upper bound for a full collection + scoring cycle.
_LOCK_TTL_SECONDS = 45 * 60  # 45 minutes
# Org-wide lock covers event collection + feature build + scoring across all sites.
_ORG_LOCK_TTL_SECONDS = 2 * 60 * 60  # 2 hours


async def _acquire_lock(site_id: str) -> tuple[aioredis.Redis, bool]:
    """
    Try to acquire the per-site detection lock via Redis SETNX.
    Returns (redis_client, acquired). Caller must release the client regardless.
    """
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    key = f"sasquatch:lock:detection:{site_id}"
    acquired = await client.set(key, "1", nx=True, ex=_LOCK_TTL_SECONDS)
    return client, bool(acquired)


async def _release_lock(redis_client: aioredis.Redis, site_id: str) -> None:
    try:
        await redis_client.delete(f"sasquatch:lock:detection:{site_id}")
    finally:
        await redis_client.aclose()


async def _get_focus_site() -> str:
    """Return the active focus site: Redis override first, then MIST_SITE_ID env var."""
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        override = await client.get("sasquatch:focus_site")
        return override if override else SITE_ID
    finally:
        await client.aclose()


async def _get_org_sites() -> list[str]:
    """Fetch all site IDs for the configured org from the Mist API."""
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        log.error("MIST_ORG_ID or MIST_API_TOKEN not configured — cannot fetch org sites")
        return []
    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/sites"
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return [s["id"] for s in resp.json() if "id" in s]
    except Exception:
        log.exception("Failed to fetch org sites from Mist API")
        return []


async def _run_wlan_detection(
    site_id: str,
    org_pools: "dict[str, dict[str, list[dict]]] | None" = None,
) -> dict:
    """
    Build features and run anomaly scoring for __all__ WLANs plus each unique WLAN
    found in the site's event data.

    org_pools: optional {wlan: {family: [feature_records from OTHER sites]}} used to
      supplement small device families that would otherwise be skipped by IF.

    Returns summary dict with total MACs scored and WLAN count.
    """
    wlans = await get_wlans(site_id=site_id)
    scopes = ["__all__"] + wlans
    log.info(f"[wlan detection] Site {site_id}: running {len(scopes)} scope(s): {scopes}")

    total_macs = 0
    for wlan in scopes:
        try:
            mac_count = await build_features(site_id, wlan)
            await score_health(site_id, wlan)
            org_ctx = org_pools.get(wlan) if org_pools else None
            scored = await score(site_id, wlan, org_family_contexts=org_ctx)
            log.info(f"[wlan detection] site={site_id} wlan={wlan}: {scored} MACs scored")
            if wlan == "__all__":
                total_macs = scored
        except Exception:
            log.exception(f"[wlan detection] Failed for site={site_id} wlan={wlan}")

    return {"macs_scored": total_macs, "wlan_scopes": len(scopes)}


async def build_org_pools(
    site_ids: list[str],
    exclude_site: str,
    wlans_by_site: "dict[str, list[str]]",
) -> "dict[str, dict[str, list[dict]]]":
    """
    Load feature records from all sites EXCEPT exclude_site and pool them by WLAN
    and device family. Used to build the org-level IF context for a single site.

    Returns {wlan: {family: [feature_records]}}.
    """
    from collections import defaultdict

    pools: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for sid in site_ids:
        if sid == exclude_site:
            continue
        for wlan in ["__all__"] + wlans_by_site.get(sid, []):
            features = await get_features(sid, wlan)
            if not features:
                continue
            for record in features.values():
                family = record.get("device_family", "Unknown")
                pools[wlan][family].append(record)

    return {wlan: dict(fam_map) for wlan, fam_map in pools.items()}


async def client_refresh_job():
    """Daily job: refresh the MAC → device metadata cache from Mist API."""
    site_id = await _get_focus_site()
    if not site_id:
        log.error("No focus site configured — skipping client refresh")
        return
    if site_id == ORG_FOCUS_VALUE:
        site_ids = await _get_org_sites()
        if not site_ids:
            log.error("Org focus set but no sites returned — skipping client refresh")
            return
        for sid in site_ids:
            try:
                count = await refresh_client_cache(sid)
                log.info(f"Client cache refreshed for site {sid}: {count} devices")
                cache = await get_client_cache(sid)
                reenriched = await reenrich_stale_events(sid, cache)
                if reenriched:
                    log.info(f"Re-enriched {reenriched} stale events for site {sid}")
            except Exception:
                log.exception(f"client_refresh_job failed for site {sid}")
        return
    try:
        count = await refresh_client_cache(site_id)
        log.info(f"Client cache refreshed for site {site_id}: {count} devices")
        cache = await get_client_cache(site_id)
        reenriched = await reenrich_stale_events(site_id, cache)
        if reenriched:
            log.info(f"Re-enriched {reenriched} stale events for site {site_id}")
    except Exception:
        log.exception("client_refresh_job failed")


async def run_detection_cycle(site_id: str, full_refresh: bool = False) -> dict:
    """
    Core detection pipeline: collect → features (per WLAN) → score (per WLAN) → dispatch.
    Acquires a Redis lock so only one run proceeds at a time.

    full_refresh=False (default, scheduler): incremental 1hr append.
    full_refresh=True (API trigger): full 24hr backfill.

    Returns a summary dict; raises RuntimeError if the lock is already held.
    """
    redis_client, acquired = await _acquire_lock(site_id)
    if not acquired:
        await redis_client.aclose()
        raise RuntimeError(f"Detection cycle already running for site {site_id} — skipping")

    try:
        if full_refresh:
            event_count = await collect_full(site_id)
        else:
            event_count = await collect(site_id)
        log.info(f"[cycle] Events collected: {event_count}")

        wlan_summary = await _run_wlan_detection(site_id)
        log.info(f"[cycle] WLAN detection complete: {wlan_summary}")

        try:
            await evaluate_and_dispatch(site_id)
        except Exception:
            log.exception("[cycle] webhook_dispatcher failed (non-fatal)")

        return {
            "events": event_count,
            "macs_scored": wlan_summary["macs_scored"],
            "wlan_scopes": wlan_summary["wlan_scopes"],
        }

    finally:
        await _release_lock(redis_client, site_id)


async def run_collect_only(site_id: str) -> dict:
    """
    Collect events from Mist and store in Redis — no scoring.
    Acquires the same per-site lock as run_detection_cycle to prevent overlap.
    Raises RuntimeError if a cycle is already in progress.
    """
    redis_client, acquired = await _acquire_lock(site_id)
    if not acquired:
        await redis_client.aclose()
        raise RuntimeError(f"Detection cycle already running for site {site_id} — skipping")

    try:
        event_count = await collect_full(site_id)
        log.info(f"[collect] Events collected: {event_count}")
        return {"events": event_count}
    finally:
        await _release_lock(redis_client, site_id)


async def run_detect_only(
    site_id: str,
    org_pools: "dict[str, dict[str, list[dict]]] | None" = None,
) -> dict:
    """
    Run feature engineering + anomaly scoring on events already in Redis.
    Does NOT pull new events from Mist. Runs for __all__ + each unique WLAN.
    Acquires the same per-site lock as run_detection_cycle to prevent overlap.
    Raises RuntimeError if the lock is already held.
    Raises ValueError if no events are found in Redis for this site.

    org_pools: optional pre-built org-level feature context (from build_org_pools).
      When provided, families below MIN_PEERS at this site are supplemented with
      records from other sites before running Isolation Forest.
    """
    from .event_collector import get_events
    redis_client, acquired = await _acquire_lock(site_id)
    if not acquired:
        await redis_client.aclose()
        raise RuntimeError(f"Detection cycle already running for site {site_id} — skipping")

    try:
        events = await get_events(site_id=site_id)
        if not events:
            raise ValueError(f"No events in Redis for site {site_id} — run /collect first")

        wlan_summary = await _run_wlan_detection(site_id, org_pools=org_pools)
        log.info(f"[detect] WLAN detection complete: {wlan_summary}")

        try:
            await evaluate_and_dispatch(site_id)
        except Exception:
            log.exception("[detect] webhook_dispatcher failed (non-fatal)")

        return {
            "macs_with_features": wlan_summary["macs_scored"],
            "macs_scored": wlan_summary["macs_scored"],
            "wlan_scopes": wlan_summary["wlan_scopes"],
        }
    finally:
        await _release_lock(redis_client, site_id)


async def event_and_detect_job():
    """Scheduled wrapper — delegates to run_detection_cycle with lock protection."""
    site_id = await _get_focus_site()
    if not site_id:
        log.error("No focus site configured — skipping detection cycle")
        return
    if site_id == ORG_FOCUS_VALUE:
        site_ids = await _get_org_sites()
        if not site_ids:
            log.error("Org focus set but no sites returned — skipping detection cycle")
            return
        log.info(f"[org] Running detection cycle for {len(site_ids)} sites")
        for sid in site_ids:
            try:
                cache = await get_client_cache(sid)
                if not cache:
                    log.info(f"[org] Client cache missing for site {sid} — refreshing")
                    await refresh_client_cache(sid)
                await run_detection_cycle(sid)
            except RuntimeError as exc:
                log.warning(str(exc))  # Lock contention — not an error
            except Exception:
                log.exception(f"[cycle] detection cycle failed for site {sid}")
        return
    try:
        await run_detection_cycle(site_id)
    except RuntimeError as exc:
        log.warning(str(exc))  # Lock contention — not an error
    except Exception:
        log.exception("[cycle] detection cycle failed")


async def org_cross_site_detect_job() -> None:
    """
    Scheduled job: full org-wide cross-site anomaly detection.

    Unlike the per-site event_and_detect_job, this job pools every MAC from every
    site in the org into a single population and runs DBSCAN, Family Centroid IF,
    and Isolation Forest against that combined dataset. Each MAC is scored relative
    to all org peers in its device family rather than just the MACs at its own site.

    Pipeline:
      1. Collect incremental events for every org site.
      2. Build per-WLAN feature vectors for every org site.
      3. For each WLAN scope, run score_org_wide across the pooled population.
      4. Dispatch webhooks per site using the org-wide findings.

    Results are stored separately from per-site results:
      sasquatch:org_anomalies:{site_id}:{wlan_key}
      sasquatch:org_findings:{site_id}:{wlan_key}

    Only runs when MIST_ORG_ID and MIST_API_TOKEN are configured.
    Runs every ORG_DETECTION_INTERVAL_HOURS (default: 6).
    Holds a Redis lock (sasquatch:lock:org_detection) for the duration of the cycle
    so concurrent scheduled triggers are skipped rather than stacked.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        log.debug("[org-detect] MIST_ORG_ID or MIST_API_TOKEN not configured — skipping")
        return

    # Acquire org-wide lock
    lock_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    lock_key = "sasquatch:lock:org_detection"
    acquired = await lock_client.set(lock_key, "1", nx=True, ex=_ORG_LOCK_TTL_SECONDS)
    await lock_client.aclose()
    if not acquired:
        log.warning("[org-detect] Lock already held — skipping cycle")
        return

    lock_release_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        site_ids = await _get_org_sites()
        if not site_ids:
            log.error("[org-detect] No org sites returned — skipping")
            return

        log.info(f"[org-detect] Starting cross-site detection for {len(site_ids)} sites")

        # Step 1: Ensure client caches are warm, then collect events for all sites.
        for sid in site_ids:
            try:
                cache = await get_client_cache(sid)
                if not cache:
                    log.info(f"[org-detect] Client cache missing for site {sid} — refreshing")
                    await refresh_client_cache(sid)
                await collect(sid)
            except Exception:
                log.exception(f"[org-detect] Event collection failed for site {sid}")

        # Step 2: Build features and health scores for every site and record each site's WLAN set.
        wlans_by_site: dict[str, list[str]] = {}
        for sid in site_ids:
            try:
                wlans = await get_wlans(site_id=sid)
                wlans_by_site[sid] = wlans
                for wlan in ["__all__"] + wlans:
                    await build_features(sid, wlan)
                    await score_health(sid, wlan)
                log.info(
                    f"[org-detect] Features built for site {sid}: "
                    f"{len(wlans) + 1} WLAN scope(s)"
                )
            except Exception:
                log.exception(f"[org-detect] Feature build failed for site {sid}")
                wlans_by_site.setdefault(sid, [])

        # Step 3: Determine the union of all WLAN scopes across the org.
        all_wlans: set[str] = {"__all__"}
        for wlans in wlans_by_site.values():
            all_wlans.update(wlans)

        # Step 4: For each WLAN scope, pool all site features and run org-wide scoring.
        for wlan in sorted(all_wlans):
            try:
                features_this_wlan: dict[str, dict] = {}
                for sid in site_ids:
                    site_features = await get_features(sid, wlan)
                    if site_features:
                        features_this_wlan[sid] = site_features

                if not features_this_wlan:
                    log.info(f"[org-detect] No features for wlan={wlan} — skipping")
                    continue

                total_macs = sum(len(f) for f in features_this_wlan.values())
                log.info(
                    f"[org-detect] Org-wide scoring wlan={wlan}: {total_macs} MACs "
                    f"across {len(features_this_wlan)} sites"
                )
                site_macs_scored = await score_org_wide(features_this_wlan, wlan=wlan)
                log.info(f"[org-detect] Scoring complete wlan={wlan}: {site_macs_scored}")

            except Exception:
                log.exception(f"[org-detect] Org-wide scoring failed for wlan={wlan}")

        # Step 5: Dispatch a single org-wide webhook from the combined findings list.
        try:
            await evaluate_and_dispatch("__org__", org_scope=True)
        except Exception:
            log.exception("[org-detect] Webhook dispatch failed (non-fatal)")

        log.info(
            f"[org-detect] Cross-site detection cycle complete for {len(site_ids)} sites"
        )

    finally:
        await lock_release_client.delete(lock_key)
        await lock_release_client.aclose()


def create_scheduler() -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()

    # Daily at midnight — client cache refresh
    scheduler.add_job(
        client_refresh_job,
        "cron",
        hour=0,
        minute=0,
        id="client_refresh",
        name="Client Cache Refresh",
    )

    # Periodic per-site detection cycle
    scheduler.add_job(
        event_and_detect_job,
        "interval",
        minutes=DETECTION_INTERVAL_MINUTES,
        id="event_and_detect",
        name="Event Collection + Anomaly Detection",
    )

    # Org-wide cross-site detection — only active when MIST_ORG_ID is configured.
    # Pools all org MACs together so each MAC is scored against the full org population.
    if MIST_ORG_ID:
        scheduler.add_job(
            org_cross_site_detect_job,
            "interval",
            hours=ORG_DETECTION_INTERVAL_HOURS,
            id="org_cross_site_detect",
            name="Org Cross-Site Anomaly Detection",
        )
        log.info(
            f"Org cross-site detection scheduled every {ORG_DETECTION_INTERVAL_HOURS}h "
            f"(org={MIST_ORG_ID})"
        )

    return scheduler

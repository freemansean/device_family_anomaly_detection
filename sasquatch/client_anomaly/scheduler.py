"""
scheduler.py — APScheduler job definitions and global mutex.

Scheduled jobs:
- client_refresh_job: Daily at 00:00 — refresh client device cache.
- markov_baseline_job: Daily at 00:30 — rebuild Markov baselines.
- org_event_poll_job: Hourly (optional) — collection only, no detection.
- sqlite_retention_job: Daily at 03:00 — purge expired events.

Anomaly detection is triggered only (not scheduled) — via POST /api/v1/org/detect
or the UI. A global mutex (sasquatch:lock:global_operation) ensures only one
operation (collecting or detecting) runs at a time.
"""

import json
import logging
import os
import time as _time
from datetime import datetime, timezone

import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .anomaly_detector import score, score_org_wide
from .client_cache import get_client_cache, refresh_client_cache_org
from .event_collector import collect_org, ensure_event_type_index, get_wlans, reenrich_stale_events
from .feature_engineer import build_features, get_features
from .health_scorer import score_health
from .markov_analyzer import baseline_exists as markov_baseline_exists
from .markov_analyzer import build_and_store_baseline as build_markov_baseline
from .webhook_dispatcher import evaluate_and_dispatch

from . import db

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

# Global mutex: only one operation (collecting or detecting) at a time.
_GLOBAL_LOCK_KEY = "sasquatch:lock:global_operation"
_GLOBAL_LOCK_TTL_SECONDS = 2 * 60 * 60  # 2 hours

# Redis keys for tracking last operation timestamps
_LAST_COLLECTION_KEY = "sasquatch:last_collection"
_LAST_DETECTION_KEY = "sasquatch:last_detection"


async def _acquire_global_lock(operation: str) -> tuple[aioredis.Redis, bool]:
    """
    Try to acquire the global operation lock via Redis SETNX.
    operation: "collecting" or "detecting" — stored as the lock value.
    Returns (redis_client, acquired). Caller must release the client regardless.
    """
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    acquired = await client.set(
        _GLOBAL_LOCK_KEY,
        json.dumps({"operation": operation, "started_at": _time.time()}),
        nx=True,
        ex=_GLOBAL_LOCK_TTL_SECONDS,
    )
    return client, bool(acquired)


async def _release_global_lock(redis_client: aioredis.Redis) -> None:
    try:
        await redis_client.delete(_GLOBAL_LOCK_KEY)
    finally:
        await redis_client.aclose()


async def get_global_lock_status() -> dict | None:
    """Return the current global lock value, or None if no lock is held."""
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await client.get(_GLOBAL_LOCK_KEY)
        if raw:
            return json.loads(raw)
        return None
    finally:
        await client.aclose()


async def get_job_status() -> dict:
    """
    Return current job state: active operation, polling status, and last
    collection/detection timestamps.
    """
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw_lock = await client.get(_GLOBAL_LOCK_KEY)
        polling_enabled = await client.get("sasquatch:event_polling_enabled")
        last_collection = await client.get(_LAST_COLLECTION_KEY)
        last_detection = await client.get(_LAST_DETECTION_KEY)
    finally:
        await client.aclose()

    active_operation = None
    started_at = None
    if raw_lock:
        lock_data = json.loads(raw_lock)
        active_operation = lock_data.get("operation")
        started_at = lock_data.get("started_at")

    return {
        "active_operation": active_operation,
        "started_at": started_at,
        "polling_enabled": polling_enabled == "1",
        "last_collection": last_collection,
        "last_detection": last_detection,
    }


async def _record_last_timestamp(key: str) -> None:
    """Write the current UTC ISO timestamp to a Redis key (no TTL)."""
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await client.set(key, datetime.now(timezone.utc).isoformat())
    finally:
        await client.aclose()


_ORG_DETECT_PROGRESS_KEY = "sasquatch:progress:org_detect"
_ORG_DETECT_PROGRESS_TTL = 300  # 5 minutes


async def run_org_pipeline(
    site_ids: list[str],
    site_map: dict[str, str],
    progress_callback=None,
) -> dict:
    """
    ARCH-5 org detection pipeline — org-first, then per-site, with progress.

    Sequence:
      1. Acquire global mutex
      2. Build features + score health for all sites/WLANs
      3. Run org-wide anomaly detection → write org findings → dispatch org webhook
      4. Run per-site anomaly detection (iterate each site) → dispatch per-site webhooks
      5. Release global mutex

    Org findings appear in Redis as soon as phase 3 completes (frontend auto-refreshes).
    Per-site findings appear incrementally as each site completes in phase 4.
    If the pipeline fails mid-site, previously completed sites retain their results.

    progress_callback: optional async callable(dict) to write progress updates.
    site_map: {site_id: site_name} for progress messages.

    Returns summary dict; raises RuntimeError if the lock is already held.
    """
    redis_client, acquired = await _acquire_global_lock("detecting")
    if not acquired:
        await redis_client.aclose()
        raise RuntimeError("Another operation is already running — skipping")

    started = _time.time()

    async def _progress(data: dict) -> None:
        data["started_at"] = started
        if progress_callback:
            await progress_callback(data)

    try:
        total_sites = len(site_ids)
        await _progress({
            "phase": "building_features",
            "current_site": None,
            "sites_complete": 0,
            "total_sites": total_sites,
            "org_complete": False,
        })

        # ── Phase 2: Build features + score health for all sites ──────────
        wlans_by_site: dict[str, list[str]] = {}
        _redis_for_baseline = aioredis.from_url(REDIS_URL, decode_responses=True)
        try:
            event_type_index = await ensure_event_type_index(_redis_for_baseline)
        finally:
            await _redis_for_baseline.aclose()

        for i, sid in enumerate(site_ids):
            site_name = site_map.get(sid, sid[:8])
            await _progress({
                "phase": "building_features",
                "current_site": site_name,
                "sites_complete": i,
                "total_sites": total_sites,
                "org_complete": False,
            })
            try:
                wlans = await get_wlans(site_id=sid)
                wlans_by_site[sid] = wlans

                # Build Markov baselines if missing (same fallback as _run_wlan_detection)
                _redis_bl = aioredis.from_url(REDIS_URL, decode_responses=True)
                try:
                    for wlan in wlans:
                        if not await markov_baseline_exists(sid, wlan, _redis_bl):
                            log.info("[org pipeline] No Markov baseline for site=%s wlan=%s — building", sid, wlan)
                            try:
                                await build_markov_baseline(sid, wlan, event_type_index)
                            except Exception:
                                log.exception("[org pipeline] Markov baseline build failed site=%s wlan=%s", sid, wlan)
                finally:
                    await _redis_bl.aclose()

                for wlan in wlans:
                    await build_features(sid, wlan)
                    await score_health(sid, wlan)
            except Exception:
                log.exception(f"[org pipeline] Feature build failed for site {sid}")
                wlans_by_site.setdefault(sid, [])

        # ── Phase 3: Org-wide anomaly detection ──────────────────────────
        await _progress({
            "phase": "org_scoring",
            "current_site": None,
            "sites_complete": 0,
            "total_sites": total_sites,
            "org_complete": False,
        })

        all_wlans: set[str] = set()
        for wlans in wlans_by_site.values():
            all_wlans.update(wlans)

        org_total_macs: dict[str, int] = {}
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
                    org_total_macs[sid] = org_total_macs.get(sid, 0) + n
            except Exception:
                log.exception(f"[org pipeline] score_org_wide failed for wlan={wlan}")

        # Dispatch org-wide webhooks
        for wlan in sorted(all_wlans):
            try:
                await evaluate_and_dispatch("__org__", wlan=wlan, org_scope=True)
            except Exception:
                log.exception(f"[org pipeline] Org webhook dispatch failed for wlan={wlan}")

        await _progress({
            "phase": "site_scoring",
            "current_site": None,
            "sites_complete": 0,
            "total_sites": total_sites,
            "org_complete": True,
        })

        # ── Phase 4: Per-site anomaly detection (sequential) ─────────────
        for i, sid in enumerate(site_ids):
            site_name = site_map.get(sid, sid[:8])
            await _progress({
                "phase": "site_scoring",
                "current_site": site_name,
                "sites_complete": i,
                "total_sites": total_sites,
                "org_complete": True,
            })

            wlans = wlans_by_site.get(sid, [])
            for wlan in wlans:
                try:
                    await score(sid, wlan)
                    await evaluate_and_dispatch(sid, wlan=wlan)
                except Exception:
                    log.exception(f"[org pipeline] Per-site scoring failed for site={sid} wlan={wlan}")

        # ── Done ─────────────────────────────────────────────────────────
        await _record_last_timestamp(_LAST_DETECTION_KEY)

        await _progress({
            "phase": "complete",
            "current_site": None,
            "sites_complete": total_sites,
            "total_sites": total_sites,
            "org_complete": True,
        })

        return {
            "status": "ok",
            "site_count": total_sites,
            "org_macs_scored": org_total_macs,
        }

    except Exception:
        log.exception("[org pipeline] Pipeline failed")
        await _progress({
            "phase": "error",
            "current_site": None,
            "sites_complete": 0,
            "total_sites": len(site_ids),
            "org_complete": False,
            "message": "Pipeline failed — check server logs",
        })
        raise
    finally:
        await _release_global_lock(redis_client)


async def client_refresh_job():
    """Daily job: refresh the org-wide MAC → device metadata cache from Mist API.

    The cache is now org-scoped (MACs are unique across the org), so a single
    refresh call serves every site. After the refresh we re-enrich stored
    events for every site that has data in the retention window, using the
    same shared cache.
    """
    if not MIST_ORG_ID:
        log.error("MIST_ORG_ID not configured — skipping client refresh")
        return
    try:
        total = await refresh_client_cache_org(MIST_ORG_ID)
    except Exception:
        log.exception("client_refresh_job: org-level client fetch failed")
        return
    log.info(f"Org client cache refreshed: {total} devices")

    try:
        cache = await get_client_cache()
    except Exception:
        log.exception("client_refresh_job: failed to load freshly written cache")
        return
    if cache is None:
        log.error("client_refresh_job: cache missing immediately after refresh")
        return

    site_ids = await db.get_site_ids_with_events()
    for sid in site_ids:
        try:
            reenriched = await reenrich_stale_events(sid, cache)
            if reenriched:
                log.info(f"Re-enriched {reenriched} stale events for site {sid}")
        except Exception:
            log.exception(f"client_refresh_job: re-enrichment failed for site {sid}")


async def markov_baseline_job() -> None:
    """
    Daily job: build Markov Chain transition matrix baselines for every site/WLAN
    pair that has events in SQLite.

    Runs at 00:30 (30 minutes after the client cache refresh at 00:00) so that any
    newly-refreshed client enrichment is reflected in the baseline events before the
    matrix is built.

    For each site and each WLAN scope, loads the last 24hr of events and computes:
      - Event-level NxN transition count matrix (Laplace-smoothed, row-normalized)
      - Episode-type 2x2 transition count matrix (short/normal episode states)

    Stored at sasquatch:markov_baseline:{site_id}:{wlan_key} with 48hr TTL.
    On first deploy (no events yet) the iteration is empty — the next daily run
    after events accumulate populates the baselines.
    """
    site_ids = await db.get_site_ids_with_events()
    if not site_ids:
        log.info("[markov baseline] No sites with events in SQLite — skipping")
        return

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        event_type_index = await ensure_event_type_index(redis_client)
    finally:
        await redis_client.aclose()

    for sid in site_ids:
        try:
            wlans = await get_wlans(site_id=sid)
            for wlan in wlans:
                result = await build_markov_baseline(sid, wlan, event_type_index)
                log.info(
                    "[markov baseline] site=%s wlan=%s: %d MACs, %d events, "
                    "%d normal episodes",
                    sid, wlan,
                    result.get("macs", 0),
                    result.get("events", 0),
                    result.get("normal_episodes", 0),
                )
        except Exception:
            log.exception("[markov baseline] Failed for site=%s", sid)


async def org_event_poll_job() -> None:
    """
    Optional hourly org-level event collection (collection only, no detection).

    Controlled by the `sasquatch:event_polling_enabled` Redis key, toggled via
    POST /api/v1/org/polling. When disabled (default), this job exits immediately.

    Acquires the global mutex to prevent overlap with detection operations.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        log.debug("[org-poll] MIST_ORG_ID or MIST_API_TOKEN not configured — skipping")
        return

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        enabled = await redis_client.get("sasquatch:event_polling_enabled")
    finally:
        await redis_client.aclose()

    if enabled != "1":
        log.debug("[org-poll] Event polling disabled — skipping")
        return

    lock_client, acquired = await _acquire_global_lock("collecting")
    if not acquired:
        await lock_client.aclose()
        log.warning("[org-poll] Global lock held — skipping this poll cycle")
        return

    try:
        log.info("[org-poll] Starting hourly org-level event collection")
        site_counts = await collect_org(MIST_ORG_ID, duration="1h")
        total = sum(site_counts.values())
        log.info(
            f"[org-poll] Collection complete: {total} events "
            f"across {len(site_counts)} sites"
        )
        await _record_last_timestamp(_LAST_COLLECTION_KEY)
    except Exception:
        log.exception("[org-poll] Event collection failed")
    finally:
        await _release_global_lock(lock_client)


async def sqlite_retention_job():
    """Purge SQLite events older than the 7-day retention window."""
    try:
        deleted = await db.purge_old_events()
        if deleted:
            log.info(f"[retention] Purged {deleted} expired events from SQLite")
    except Exception:
        log.exception("[retention] SQLite retention purge failed")


def create_scheduler() -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()

    # Daily at 03:00 — purge expired events from SQLite
    scheduler.add_job(
        sqlite_retention_job,
        "cron",
        hour=3,
        minute=0,
        id="sqlite_retention",
        name="SQLite Event Retention Cleanup",
    )

    # Daily at midnight — client cache refresh
    scheduler.add_job(
        client_refresh_job,
        "cron",
        hour=0,
        minute=0,
        id="client_refresh",
        name="Client Cache Refresh",
    )

    # Daily at 00:30 — Markov baseline rebuild (after client cache refresh).
    # Also runs immediately at startup so the baseline is available without
    # waiting up to 24 hours after a fresh deployment or service restart.
    # If no events are in Redis yet, the job exits early without writing anything
    # and the nightly run will populate the baseline once events accumulate.
    scheduler.add_job(
        markov_baseline_job,
        "cron",
        hour=0,
        minute=30,
        id="markov_baseline",
        name="Markov Chain Baseline Rebuild",
        next_run_time=datetime.now(timezone.utc),
    )

    # ARCH-4: Scheduled detection jobs removed. Anomaly detection is now triggered
    # only via POST /api/v1/org/detect or the UI "Re-detect" button.

    # Optional hourly org-level event polling (collection only, no detection).
    # Disabled by default — toggled via POST /api/v1/org/polling.
    if MIST_ORG_ID:
        scheduler.add_job(
            org_event_poll_job,
            "interval",
            hours=1,
            id="org_event_poll",
            name="Org-Level Event Poll",
        )

    return scheduler

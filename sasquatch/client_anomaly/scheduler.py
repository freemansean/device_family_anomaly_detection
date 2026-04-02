"""
scheduler.py — APScheduler job definitions.

Jobs:
- client_refresh_job: Daily at 00:00 — refresh client device cache.
- event_and_detect_job: Every DETECTION_INTERVAL_MINUTES — collect events and run detection.
"""

import logging
import os

import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .anomaly_detector import score
from .client_cache import refresh_client_cache
from .event_collector import collect, collect_full
from .feature_engineer import build_features
from .webhook_dispatcher import evaluate_and_dispatch

log = logging.getLogger(__name__)

SITE_ID = os.getenv("MIST_SITE_ID", "")
DETECTION_INTERVAL_MINUTES = int(os.getenv("DETECTION_INTERVAL_MINUTES", "15"))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Lock TTL: generous upper bound for a full collection + scoring cycle.
# If a run dies without releasing the lock, it will auto-expire.
_LOCK_TTL_SECONDS = 45 * 60  # 45 minutes


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


async def client_refresh_job():
    """Daily job: refresh the MAC → device metadata cache from Mist API."""
    if not SITE_ID:
        log.error("MIST_SITE_ID not configured — skipping client refresh")
        return
    try:
        count = await refresh_client_cache(SITE_ID)
        log.info(f"Client cache refreshed: {count} devices")
    except Exception:
        log.exception("client_refresh_job failed")


async def run_detection_cycle(site_id: str, full_refresh: bool = False) -> dict:
    """
    Core detection pipeline: collect → features → score → dispatch.
    Acquires a Redis lock so only one run proceeds at a time regardless of
    whether the trigger came from the scheduler or a manual /run API call.

    full_refresh=False (default, scheduler): incremental 1hr append + 24hr age-out.
    full_refresh=True (API trigger): full 24hr backfill, replaces dataset entirely.

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

        mac_count = await build_features(site_id)
        log.info(f"[cycle] Features built for {mac_count} MACs")

        scored = await score(site_id)
        log.info(f"[cycle] Anomaly scoring complete: {scored} MACs")

        try:
            await evaluate_and_dispatch(site_id)
        except Exception:
            log.exception("[cycle] webhook_dispatcher failed (non-fatal)")

        return {"events": event_count, "macs_with_features": mac_count, "macs_scored": scored}

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


async def run_detect_only(site_id: str) -> dict:
    """
    Run feature engineering + anomaly scoring on events already in Redis.
    Does NOT pull new events from Mist.
    Acquires the same per-site lock as run_detection_cycle to prevent overlap.
    Raises RuntimeError if a cycle is already in progress.
    Raises ValueError if no events are found in Redis.
    """
    redis_client, acquired = await _acquire_lock(site_id)
    if not acquired:
        await redis_client.aclose()
        raise RuntimeError(f"Detection cycle already running for site {site_id} — skipping")

    try:
        exists = await redis_client.exists(f"sasquatch:events:{site_id}")
        if not exists:
            raise ValueError(f"No events in Redis for site {site_id} — run /collect first")

        mac_count = await build_features(site_id)
        log.info(f"[detect] Features built for {mac_count} MACs")

        scored = await score(site_id)
        log.info(f"[detect] Anomaly scoring complete: {scored} MACs")

        try:
            await evaluate_and_dispatch(site_id)
        except Exception:
            log.exception("[detect] webhook_dispatcher failed (non-fatal)")

        return {"macs_with_features": mac_count, "macs_scored": scored}
    finally:
        await _release_lock(redis_client, site_id)


async def event_and_detect_job():
    """Scheduled wrapper — delegates to run_detection_cycle with lock protection."""
    if not SITE_ID:
        log.error("MIST_SITE_ID not configured — skipping detection cycle")
        return
    try:
        await run_detection_cycle(SITE_ID)
    except RuntimeError as exc:
        log.warning(str(exc))  # Lock contention — not an error
    except Exception:
        log.exception("[cycle] detection cycle failed")


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

    # Periodic detection cycle
    scheduler.add_job(
        event_and_detect_job,
        "interval",
        minutes=DETECTION_INTERVAL_MINUTES,
        id="event_and_detect",
        name="Event Collection + Anomaly Detection",
    )

    return scheduler

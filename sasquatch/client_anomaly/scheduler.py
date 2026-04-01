"""
scheduler.py — APScheduler job definitions.

Jobs:
- client_refresh_job: Daily at 00:00 — refresh client device cache.
- event_and_detect_job: Every DETECTION_INTERVAL_MINUTES — collect events and run detection.
"""

import logging
import os

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from .anomaly_detector import score
from .client_cache import refresh_client_cache
from .event_collector import collect
from .feature_engineer import build_features
from .webhook_dispatcher import evaluate_and_dispatch

log = logging.getLogger(__name__)

SITE_ID = os.getenv("MIST_SITE_ID", "")
DETECTION_INTERVAL_MINUTES = int(os.getenv("DETECTION_INTERVAL_MINUTES", "15"))


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


async def event_and_detect_job():
    """
    Periodic job: collect events → build features → score anomalies → dispatch webhook.
    If any step raises, log and abort remaining steps.
    Does NOT corrupt Redis state from the previous good cycle on failure.
    """
    if not SITE_ID:
        log.error("MIST_SITE_ID not configured — skipping detection cycle")
        return

    try:
        event_count = await collect(SITE_ID)
        log.info(f"[cycle] Events collected: {event_count}")
    except Exception:
        log.exception("[cycle] event_collector.collect() failed — aborting cycle")
        return

    try:
        mac_count = await build_features(SITE_ID)
        log.info(f"[cycle] Features built for {mac_count} MACs")
    except Exception:
        log.exception("[cycle] feature_engineer.build_features() failed — aborting cycle")
        return

    try:
        scored = await score(SITE_ID)
        log.info(f"[cycle] Anomaly scoring complete: {scored} MACs")
    except Exception:
        log.exception("[cycle] anomaly_detector.score() failed — aborting cycle")
        return

    try:
        await evaluate_and_dispatch(SITE_ID)
    except Exception:
        log.exception("[cycle] webhook_dispatcher.evaluate_and_dispatch() failed")
        # Don't abort — detection already succeeded


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

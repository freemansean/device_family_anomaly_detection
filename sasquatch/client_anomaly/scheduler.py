"""
scheduler.py — APScheduler job definitions and global mutex.

Scheduled jobs:
- client_refresh_job: Daily at 00:00 — refresh client device cache.
- markov_baseline_job: Daily at 00:30 — rebuild Markov baselines.
- org_event_poll_job: Every `general.org_detection_interval_hours` hours (optional) — collection only, no detection.
- sqlite_retention_job: Daily at 03:00 — purge expired events.

Anomaly detection is triggered only (not scheduled) — via POST /api/v1/org/detect
or the UI. A global mutex (sasquatch:lock:global_operation) ensures only one
operation (collecting or detecting) runs at a time.
"""

import asyncio
import ctypes
import gc
import json
import logging
import os
import time as _time
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from . import config
from .anomaly_detector import score, score_org_wide
from .client_cache import get_client_cache, refresh_client_cache_org
from .event_collector import collect_org, ensure_event_type_index, get_wlans, reenrich_stale_events
from .feature_engineer import build_features, get_features
from .health_scorer import score_health
from .markov_analyzer import baseline_exists as markov_baseline_exists
from .markov_analyzer import build_and_store_baseline as build_markov_baseline
from .webhook_dispatcher import evaluate_and_dispatch

from . import config as _config_mod
from . import db

log = logging.getLogger(__name__)

try:
    _LIBC = ctypes.CDLL("libc.so.6")
    _LIBC.malloc_trim.argtypes = [ctypes.c_size_t]
    _LIBC.malloc_trim.restype = ctypes.c_int
except OSError:
    _LIBC = None

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

# Global mutex: only one operation (collecting or detecting) at a time.
_GLOBAL_LOCK_KEY = "sasquatch:lock:global_operation"
_GLOBAL_LOCK_TTL_SECONDS = 6 * 60 * 60  # 6 hours — covers a full 12hr multi-million-event collect with margin. `clear_stale_global_lock()` at startup handles the crash-before-release case; this TTL is only a backstop.

# Redis keys for tracking last operation timestamps
_LAST_COLLECTION_KEY = "sasquatch:last_collection"
_LAST_DETECTION_KEY = "sasquatch:last_detection"

# Auto-chain detection after collects (manual full-collect and hourly poll).
# Default: enabled (value missing → "1"). Toggled via /api/v1/org/auto-detect.
_AUTO_DETECT_ENABLED_KEY = "sasquatch:auto_detect_enabled"

# Shared cache key for the org site map (also read by api/routes.py).
_ORG_SITES_CACHE_KEY = "sasquatch:org_sites_map"
_ORG_SITES_CACHE_TTL = 300  # 5 minutes


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


async def clear_stale_global_lock() -> None:
    """
    Unconditionally delete the global operation lock at process startup.

    The lock carries a 2-hour TTL, so a crash/restart of the backend mid-job
    leaves a ghost lock behind that blocks every subsequent collect/detect
    trigger with 409 until the TTL expires. A freshly-started process cannot
    possibly be mid-flight on any background task, so clearing the key on
    startup is always safe.
    """
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await client.get(_GLOBAL_LOCK_KEY)
        if raw:
            log.warning(
                "Clearing stale global lock at startup: %s", raw
            )
            await client.delete(_GLOBAL_LOCK_KEY)
    finally:
        await client.aclose()


async def _transfer_global_lock(redis_client: aioredis.Redis, to_op: str) -> None:
    """
    Atomically rewrite the in-flight global lock value to a new operation name
    without releasing it. Used by the collect→detect auto-chain so no competing
    operation can grab the mutex during the handoff window.

    Caller must already hold the lock. TTL is refreshed to the standard duration.
    """
    await redis_client.set(
        _GLOBAL_LOCK_KEY,
        json.dumps({"operation": to_op, "started_at": _time.time()}),
        ex=_GLOBAL_LOCK_TTL_SECONDS,
    )


async def _release_phase_memory(phase_label: str) -> None:
    """
    Belt-and-suspenders memory release between pipeline phases.

    The collect→detect auto-chain runs both phases in the same task, so
    Python's refcount-based GC does not always free large collect-side
    buffers (event dicts, HTTP response bodies held by httpx, pandas
    scratch frames) before the detect phase starts allocating dense
    NumPy feature matrices and PCA intermediates. On a multi-million-event
    org this overlap has caused OOM kills. Force a full generational
    collect and yield briefly so the event loop can settle before the
    next phase begins.

    No-op when there is nothing to free; safe to call unconditionally.
    """
    collected = gc.collect()
    # Yield the event loop so any pending tasks (e.g. httpx connection
    # teardown) complete and their buffers are released before the next
    # phase's heavy allocations.
    await asyncio.sleep(0)
    # gc.collect() frees Python objects but glibc retains freed arenas in
    # userspace rather than returning pages to the kernel. After a detection
    # run that allocates multi-GB numpy/sklearn buffers, the process RSS can
    # sit at 10+ GB of private-anonymous pages with zero live Python objects,
    # leaving no headroom for the next phase and causing OOM kills. Ask glibc
    # to trim freed arenas back to the OS.
    trimmed = _LIBC.malloc_trim(0) if _LIBC is not None else -1
    log.info(
        "[gc] %s phase boundary: collected %d objects, malloc_trim=%d",
        phase_label,
        collected,
        trimmed,
    )


async def get_auto_detect_enabled() -> bool:
    """
    Return whether collect→detect auto-chain is enabled.

    Default is disabled: a missing key counts as off. Only the explicit string
    "1" enables it. Detection on a large org is memory-intensive; back-to-back
    collect+detect in a constrained container has caused OOM kills in the
    past, so the operator must explicitly opt in via /api/v1/org/auto-detect.
    """
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        val = await client.get(_AUTO_DETECT_ENABLED_KEY)
    finally:
        await client.aclose()
    return val == "1"


async def set_auto_detect_enabled(enabled: bool) -> None:
    """Persist the auto-detect toggle. Writes "1" or "0" (no TTL)."""
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await client.set(_AUTO_DETECT_ENABLED_KEY, "1" if enabled else "0")
    finally:
        await client.aclose()


async def _get_cached_site_map(redis_client: aioredis.Redis) -> dict[str, str]:
    """
    Return the {site_id: site_name} map, preferring the Redis cache (5-minute
    TTL shared with api/routes.py). Falls back to a direct Mist API call and
    re-populates the cache on miss.

    Used by the auto-chain path so the scheduler job does not depend on the
    routes module. Raises on API failure — the caller decides how to degrade.
    """
    cached = await redis_client.get(_ORG_SITES_CACHE_KEY)
    if cached:
        return json.loads(cached)

    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/sites"
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
    site_map = {s["id"]: s.get("name", s["id"]) for s in resp.json() if "id" in s}
    await redis_client.set(
        _ORG_SITES_CACHE_KEY, json.dumps(site_map), ex=_ORG_SITES_CACHE_TTL
    )
    return site_map


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

# Hourly poll progress — mirrors the full-collect progress schema in
# _org_collect_background_task (api/routes.py) so the frontend can reuse the
# same status-bar component. Key auto-expires so the bar clears itself after a
# run completes, and disabled / skipped cycles leave no residual state.
_ORG_HOURLY_POLL_PROGRESS_KEY = "sasquatch:progress:org_hourly_poll"
_ORG_HOURLY_POLL_PROGRESS_TTL = 300  # 5 minutes


async def run_org_pipeline(
    site_ids: list[str],
    site_map: dict[str, str],
    progress_callback=None,
) -> dict:
    """
    ARCH-5 org detection pipeline — org-first, then per-site, with progress.

    Acquires the global mutex as ``detecting``, runs the body, releases the
    mutex. Raises RuntimeError if the lock is already held.

    See ``_run_org_pipeline_body`` for the detailed phase sequence.
    """
    redis_client, acquired = await _acquire_global_lock("detecting")
    if not acquired:
        await redis_client.aclose()
        raise RuntimeError("Another operation is already running — skipping")

    try:
        return await _run_org_pipeline_body(
            site_ids=site_ids,
            site_map=site_map,
            progress_callback=progress_callback,
        )
    finally:
        await _release_global_lock(redis_client)


async def _run_org_pipeline_body(
    site_ids: list[str],
    site_map: dict[str, str],
    progress_callback=None,
) -> dict:
    """
    Pipeline body shared by the public ``run_org_pipeline`` wrapper and the
    collect→detect auto-chain paths. The caller is responsible for holding the
    global mutex — this function does NOT acquire or release it.

    Sequence:
      1. Build features + score health for all sites/WLANs
      2. Run per-site anomaly detection (Markov runs here, writes per-site anomaly records)
      3. Run org-wide anomaly detection (merges Markov from per-site records) → write org findings
      4. Dispatch org + per-site webhooks
      5. Pre-compute dashboard summary cache

    Per-site scoring runs BEFORE org-wide scoring so that score_org_wide() can
    merge fresh per-site Markov results from the current cycle (previously org
    scoring ran first, causing Markov data to lag by one pipeline cycle).

    progress_callback: optional async callable(dict) to write progress updates.
    site_map: {site_id: site_name} for progress messages.
    """
    started = _time.time()
    # Per-phase wall-clock timings, logged at each phase boundary and
    # re-summarized at pipeline exit. Helps tell where to invest next on
    # the speedup work — Phase 5's per-site loop is the obvious candidate
    # but worth confirming with numbers before parallelizing anything.
    phase_timings: dict[str, float] = {}
    _phase_clock = {"start": _time.monotonic(), "label": "phase1_setup"}

    def _phase_done(label: str) -> None:
        elapsed = _time.monotonic() - _phase_clock["start"]
        phase_timings[label] = elapsed
        log.info("[timing] %s: %.2fs", label, elapsed)
        _phase_clock["start"] = _time.monotonic()
        _phase_clock["label"] = label

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

        # Pre-compute (site, wlan) event counts in one SQL GROUP BY so we can
        # skip every scope with zero events before doing any per-scope work.
        # On a 197-site org with ~125 sites empty for the current retention
        # window this drops Phase 2 work by more than half. The per-site
        # `get_wlans()` call still runs because it's needed to populate
        # `wlans_by_site` for the downstream phases — but `build_features` and
        # `score_health` are only invoked for scopes with at least one event.
        try:
            scope_event_counts = await db.get_event_counts_by_site_wlan()
        except Exception:
            log.exception("[org pipeline] event count pre-scan failed; falling back to no-skip")
            scope_event_counts = {}

        # Pre-compute the per-WLAN org-wide qualifying manufacturer set.
        # `-MFG` virtual families should fire when a manufacturer has
        # mfg_rollup_min_macs MACs across the *entire org*, not per site —
        # otherwise an Amazon population of 3 per site × 30 sites never
        # crosses the threshold at any single site and the rollup stays
        # silent. The per-WLAN scope matches where Centroid actually runs.
        # Compute once, thread into every build_features() call.
        mfg_rollup_min = int(config.get("general", "mfg_rollup_min_macs"))
        qualifying_mfgs_by_wlan: dict[str, set[str]] = {}
        try:
            from .client_cache import resolve_manufacturer_from_family
            mfg_inputs = await db.get_mfg_inputs_by_wlan()
            for wlan_key, rows in mfg_inputs.items():
                mfg_to_macs: dict[str, set[str]] = {}
                for mac, fam, mfg_raw in rows:
                    resolved = resolve_manufacturer_from_family(fam, mfg_raw)
                    if resolved:
                        mfg_to_macs.setdefault(resolved, set()).add(mac)
                qualifying_mfgs_by_wlan[wlan_key] = {
                    m for m, macs in mfg_to_macs.items()
                    if len(macs) >= mfg_rollup_min
                }
            total_qualifying = sum(len(s) for s in qualifying_mfgs_by_wlan.values())
            log.info(
                "[org pipeline] mfg-rollup pre-pass: %d WLANs, %d total qualifying mfgs (>= %d MACs org-wide)",
                len(qualifying_mfgs_by_wlan), total_qualifying, mfg_rollup_min,
            )
        except Exception:
            log.exception("[org pipeline] mfg-rollup pre-pass failed; falling back to per-site threshold")
            qualifying_mfgs_by_wlan = {}

        # Markov baseline build remains a sequential per-site step. It only
        # fires when a baseline is missing (48hr TTL — usually a no-op on a
        # warm system) and we don't want N parallel rebuilds hammering a cold
        # Redis after a flush.
        for sid in site_ids:
            try:
                wlans = await get_wlans(site_id=sid)
                wlans_by_site[sid] = wlans
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
            except Exception:
                log.exception(f"[org pipeline] WLAN/Markov pre-pass failed for site {sid}")
                wlans_by_site.setdefault(sid, [])

        # Flatten (site, wlan) pairs that actually have events. Same concurrency
        # pattern as Phase 3: each build_features/score_health pair is independent
        # (separate Redis client, separate event list), bounded to 4 in-flight to
        # keep peak memory predictable. Empty scopes are dropped here.
        phase2_pairs: list[tuple[str, str]] = []
        phase2_skipped_empty = 0
        for sid in site_ids:
            for wlan in wlans_by_site.get(sid, []):
                if scope_event_counts.get((sid, wlan), 0) > 0:
                    phase2_pairs.append((sid, wlan))
                elif scope_event_counts:
                    # Only count skips when the pre-scan succeeded — falling
                    # back to no-skip would otherwise inflate this counter.
                    phase2_skipped_empty += 1

        _PHASE2_CONCURRENCY = 4
        phase2_sem = asyncio.Semaphore(_PHASE2_CONCURRENCY)
        phase2_done_count = {"n": 0}

        async def _build_one(sid: str, wlan: str) -> None:
            async with phase2_sem:
                try:
                    await build_features(
                        sid, wlan,
                        qualifying_mfgs=qualifying_mfgs_by_wlan.get(wlan),
                    )
                    await score_health(sid, wlan)
                except Exception:
                    log.exception(
                        f"[org pipeline] Feature/health build failed for site={sid} wlan={wlan}"
                    )
                finally:
                    phase2_done_count["n"] += 1

        phase2_progress_done = asyncio.Event()
        phase2_total_pairs = len(phase2_pairs)

        async def _phase2_progress_ticker() -> None:
            while not phase2_progress_done.is_set():
                await _progress({
                    "phase": "building_features",
                    "current_site": None,
                    "sites_complete": phase2_done_count["n"],
                    "total_sites": phase2_total_pairs or total_sites,
                    "org_complete": False,
                })
                try:
                    await asyncio.wait_for(phase2_progress_done.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

        phase2_ticker = asyncio.create_task(_phase2_progress_ticker())
        try:
            await asyncio.gather(*(_build_one(sid, wlan) for sid, wlan in phase2_pairs))
        finally:
            phase2_progress_done.set()
            await phase2_ticker

        log.info(
            "[org pipeline] Phase 2 complete: built=%d skipped_empty=%d concurrency=%d",
            phase2_total_pairs, phase2_skipped_empty, _PHASE2_CONCURRENCY,
        )

        all_wlans: set[str] = set()
        for wlans in wlans_by_site.values():
            all_wlans.update(wlans)

        # Release feature/health build fragmentation before per-site scoring.
        await _release_phase_memory("phase2 features+health")

        _phase_done("phase2_features_health")

        # ── Phase 3: Per-site anomaly detection (sequential) ────────────
        # Runs BEFORE org-wide scoring so that per-site Markov results are
        # available for score_org_wide() to merge. Previously this ran after
        # org scoring (as "Phase 4"), which meant org anomaly records lagged
        # per-site Markov data by one cycle — the MacDrilldown fallback to
        # org anomalies would show empty Markov fields.
        await _progress({
            "phase": "site_scoring",
            "current_site": None,
            "sites_complete": 0,
            "total_sites": total_sites,
            "org_complete": False,
        })

        # Counters for the end-of-phase summary. A (site, wlan) combo lands in
        # exactly one bucket: scored (score() returned > 0), skipped_empty_features
        # (score() returned 0 — features key exists but dict is empty, see
        # anomaly_detector.score() skip path), or failed (score() raised). Tracked
        # so the silent-skip gap between features keys and anomalies keys is
        # observable at a glance (see TODO Phase 4 investigation).
        phase3_wlans_scored = 0
        phase3_wlans_skipped_empty_features = 0
        phase3_wlans_failed = 0
        phase3_sites_with_any_scored: set[str] = set()

        # Flatten (site, wlan) pairs and run them concurrently with a bounded
        # semaphore. Each score() call is independent — separate Redis/SQLite
        # reads, separate sklearn matrices, separate output keys — so the only
        # shared state is the counter dict and a per-site "any-scored" set,
        # both updated under the asyncio single-threaded event loop. Concurrency
        # of 4 keeps peak memory predictable: each in-flight scope allocates a
        # category_vector matrix (~few hundred KB) plus an event_vector matrix
        # (a few MB at most), so 4× is small relative to the org-wide pool that
        # already lives in Phase 4.
        scope_pairs: list[tuple[str, str]] = []
        for sid in site_ids:
            for wlan in wlans_by_site.get(sid, []):
                scope_pairs.append((sid, wlan))

        _PHASE3_CONCURRENCY = 4
        sem = asyncio.Semaphore(_PHASE3_CONCURRENCY)

        async def _score_one(sid: str, wlan: str) -> None:
            nonlocal phase3_wlans_scored, phase3_wlans_skipped_empty_features, phase3_wlans_failed
            async with sem:
                try:
                    n_scored = await score(sid, wlan)
                    if n_scored > 0:
                        phase3_wlans_scored += 1
                        phase3_sites_with_any_scored.add(sid)
                    else:
                        phase3_wlans_skipped_empty_features += 1
                except Exception:
                    phase3_wlans_failed += 1
                    log.exception(
                        f"[org pipeline] Per-site scoring failed for site={sid} wlan={wlan}"
                    )

        # Periodic progress updates: a separate coroutine ticks every 2s with
        # the running sites-complete count so the UI's progress bar advances
        # smoothly even though work order is non-deterministic under gather.
        progress_done = asyncio.Event()

        async def _progress_ticker() -> None:
            while not progress_done.is_set():
                await _progress({
                    "phase": "site_scoring",
                    "current_site": None,
                    "sites_complete": len(phase3_sites_with_any_scored),
                    "total_sites": total_sites,
                    "org_complete": False,
                })
                try:
                    await asyncio.wait_for(progress_done.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

        ticker_task = asyncio.create_task(_progress_ticker())
        try:
            await asyncio.gather(*(_score_one(sid, wlan) for sid, wlan in scope_pairs))
        finally:
            progress_done.set()
            await ticker_task

        _phase_done("phase3_per_site_score")

        # ── Phase 4: Org-wide anomaly detection ──────────────────────────
        # Runs after per-site scoring so score_org_wide() can read fresh
        # per-site Markov results from the current cycle.
        await _progress({
            "phase": "org_scoring",
            "current_site": None,
            "sites_complete": 0,
            "total_sites": total_sites,
            "org_complete": False,
        })

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
            finally:
                # The org-wide feature pool for a busy WLAN (e.g. eduroam across
                # 197 sites) is the single largest in-memory structure in the
                # pipeline. Drop the Python references now so the next WLAN's
                # pool doesn't stack on top of this one, and ask glibc to trim
                # the freed sklearn/numpy arenas back to the OS. Without this
                # Phase 4 grows monotonically until OOM.
                del features_this_wlan
                await _release_phase_memory(f"phase4 wlan={wlan}")

        # Dispatch org-wide webhooks
        for wlan in sorted(all_wlans):
            try:
                await evaluate_and_dispatch("__org__", wlan=wlan, org_scope=True)
            except Exception:
                log.exception(f"[org pipeline] Org webhook dispatch failed for wlan={wlan}")

        # Dispatch per-site webhooks (after org scoring so all anomaly records
        # are complete before any webhook fires)
        for i, sid in enumerate(site_ids):
            wlans = wlans_by_site.get(sid, [])
            for wlan in wlans:
                try:
                    await evaluate_and_dispatch(sid, wlan=wlan)
                except Exception:
                    log.exception(f"[org pipeline] Per-site webhook dispatch failed for site={sid} wlan={wlan}")

        total_wlans = phase3_wlans_scored + phase3_wlans_skipped_empty_features + phase3_wlans_failed
        log.info(
            "[org pipeline] Per-site scoring summary: sites_scored=%d/%d wlans_scored=%d/%d "
            "wlans_skipped_empty_features=%d wlans_failed=%d",
            len(phase3_sites_with_any_scored), total_sites,
            phase3_wlans_scored, total_wlans,
            phase3_wlans_skipped_empty_features,
            phase3_wlans_failed,
        )

        # Release Phase 3/4 fragmentation before Phase 5's cache builders,
        # which allocate hundreds of aggregator frames back-to-back.
        await _release_phase_memory("phase4 scoring+webhooks")

        _phase_done("phase4_org_score_and_webhooks")

        # ── Phase 5: Pre-compute dashboard summary cache ─────────────────
        # Builds the aggregates that /org/summary, /org/alerts-full,
        # /org/findings, /org/family-insights, /sites/{id}/findings,
        # /sites/{id}/health, and /sites/{id}/events/summary serve out of
        # cache between detection cycles. Best-effort: cache failures must
        # never fail the pipeline, so each builder is wrapped in its own
        # try/except. Lazy import to break the circular import (api.routes
        # already imports scheduler).
        try:
            from .api import routes as _routes
            from . import summary_cache as _summary_cache

            cache_redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            try:
                summary_wlans = sorted(all_wlans)
                org_built = 0
                site_built = 0

                # Org-level entries are per-WLAN.
                for wlan in summary_wlans:
                    for build_fn, key_fn in (
                        (_routes.build_org_summary, _summary_cache._org_summary_key),
                        (_routes.build_org_findings, _summary_cache._org_findings_key),
                        (_routes.build_org_family_insights, _summary_cache._org_family_insights_key),
                    ):
                        try:
                            payload = await build_fn(cache_redis, site_map, wlan)
                            await _summary_cache.cache_set(cache_redis, key_fn(wlan), payload)
                            org_built += 1
                        except Exception:
                            log.exception(
                                "[org pipeline] summary cache build failed: %s wlan=%s",
                                build_fn.__name__, wlan,
                            )

                # Cross-WLAN aggregation has no wlan dimension.
                try:
                    payload = await _routes.build_org_alerts_full(cache_redis, site_map)
                    await _summary_cache.cache_set(
                        cache_redis, _summary_cache._org_alerts_full_key(), payload,
                    )
                    org_built += 1
                except Exception:
                    log.exception("[org pipeline] summary cache build failed: build_org_alerts_full")

                _phase_done("phase5a_org_builders")

                # WLAN-list dropdowns: rewrite from data already in scope.
                # Avoids a multi-second SELECT DISTINCT scan over the events
                # table on every page load between detection cycles.
                try:
                    await _summary_cache.write_wlan_lists(
                        cache_redis, all_wlans, wlans_by_site,
                    )
                except Exception:
                    log.exception("[org pipeline] wlan-list cache write failed")

                # Site-level entries are per (site, wlan). Trim glibc arenas
                # every N sites so fragmentation from the per-site builders
                # (each pulls anomaly/health blobs from Redis, JSON-decodes
                # them, builds aggregates) does not pile up across the full
                # ~200-site sweep. Without this, RSS grew monotonically into
                # OOM mid-Phase-5 even after the per-site builders returned.
                _PHASE5_TRIM_EVERY = 25
                for site_idx, sid in enumerate(site_ids):
                    for wlan in wlans_by_site.get(sid, []):
                        try:
                            payload = await _routes.build_site_findings(sid, wlan)
                            await _summary_cache.cache_set(
                                cache_redis, _summary_cache._site_findings_key(sid, wlan), payload,
                            )
                            site_built += 1
                        except Exception:
                            log.exception(
                                "[org pipeline] site_findings cache build failed: site=%s wlan=%s",
                                sid, wlan,
                            )
                        try:
                            payload = await _routes.build_site_health(sid, wlan)
                            await _summary_cache.cache_set(
                                cache_redis, _summary_cache._site_health_key(sid, wlan), payload,
                            )
                            site_built += 1
                        except Exception:
                            log.exception(
                                "[org pipeline] site_health cache build failed: site=%s wlan=%s",
                                sid, wlan,
                            )
                        try:
                            payload = await _routes.build_site_events_summary(sid, wlan)
                            if payload is not None:
                                await _summary_cache.cache_set(
                                    cache_redis,
                                    _summary_cache._site_events_summary_key(sid, wlan),
                                    payload,
                                )
                                site_built += 1
                        except Exception:
                            log.exception(
                                "[org pipeline] site_events_summary cache build failed: "
                                "site=%s wlan=%s", sid, wlan,
                            )
                    if (site_idx + 1) % _PHASE5_TRIM_EVERY == 0:
                        await _release_phase_memory(
                            f"phase5 sites {site_idx + 1}/{total_sites}"
                        )

                log.info(
                    "[org pipeline] Phase 5 summary cache: org_entries=%d site_entries=%d "
                    "wlans=%d sites=%d",
                    org_built, site_built, len(summary_wlans), total_sites,
                )
            finally:
                await cache_redis.aclose()
        except Exception:
            log.exception("[org pipeline] Phase 5 summary cache populate failed (non-fatal)")

        # Release Phase 5 aggregator fragmentation before Phase 5b walks
        # every (site, wlan) scope in SQLite to rebuild client_summary.
        await _release_phase_memory("phase5 summary cache")

        _phase_done("phase5_site_builders_loop")

        # ── Phase 5b: Rebuild client_summary table for drilldowns ────────
        # Per-(mac, site, wlan) rollup that backs the Device Family Drilldown
        # and Device Family Search endpoints. Truncate-and-rebuild per scope.
        # Best-effort: failures log and are swallowed.
        try:
            from . import client_summary_builder as _builder
            _cache_redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            try:
                scope_pairs: list[tuple[str, str]] = []
                for sid in site_ids:
                    for wlan in wlans_by_site.get(sid, []):
                        scope_pairs.append((sid, wlan))
                summary_stats = await _builder.rebuild_summary_table(
                    _cache_redis, scope_pairs, org_id=MIST_ORG_ID,
                )
                log.info(
                    "[org pipeline] Phase 5b client_summary: scopes_built=%d "
                    "scopes_failed=%d rows=%d stale_rows_swept=%d",
                    summary_stats["scopes_built"], summary_stats["scopes_failed"],
                    summary_stats["rows_total"], summary_stats["stale_rows_swept"],
                )
            finally:
                await _cache_redis.aclose()
        except Exception:
            log.exception("[org pipeline] Phase 5b client_summary rebuild failed (non-fatal)")

        _phase_done("phase5b_client_summary_table")

        # Final trim so the idle backend returns to baseline RSS rather than
        # sitting on unreclaimed arenas until the next pipeline run.
        await _release_phase_memory("pipeline exit")

        total_elapsed = _time.time() - started
        log.info(
            "[timing] === Pipeline summary === total=%.1fs (%.1f min) | %s",
            total_elapsed,
            total_elapsed / 60.0,
            " | ".join(f"{k}={v:.1f}s" for k, v in phase_timings.items()),
        )

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


async def markov_baseline_job(skip_existing: bool = False) -> None:
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

    When ``skip_existing=True``, each (site, wlan) pair is checked against Redis
    and skipped if a baseline key is already present. Used by the one-shot
    startup invocation so a restart within the 48hr TTL does not redundantly
    rebuild every site×wlan pair. The nightly cron invocation uses the default
    (rebuild everything).
    """
    site_ids = await db.get_site_ids_with_events()
    if not site_ids:
        log.info("[markov baseline] No sites with events in SQLite — skipping")
        return

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        event_type_index = await ensure_event_type_index(redis_client)

        built = 0
        skipped = 0
        for sid in site_ids:
            try:
                wlans = await get_wlans(site_id=sid)
                for wlan in wlans:
                    if skip_existing and await markov_baseline_exists(
                        sid, wlan, redis_client
                    ):
                        skipped += 1
                        continue
                    result = await build_markov_baseline(
                        sid, wlan, event_type_index
                    )
                    built += 1
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

        if skip_existing:
            log.info(
                "[markov baseline] Startup check complete: built %d, "
                "skipped %d (already present in Redis)",
                built, skipped,
            )
    finally:
        await redis_client.aclose()


async def org_event_poll_job() -> None:
    """
    Optional hourly org-level event collection (collection only, no detection).

    Controlled by the `sasquatch:event_polling_enabled` Redis key, toggled via
    POST /api/v1/org/polling. When disabled (default), this job exits immediately.

    Acquires the global mutex to prevent overlap with detection operations.

    Writes phase-by-phase progress to `sasquatch:progress:org_hourly_poll`
    mirroring the full-collect schema in `_org_collect_background_task`
    (api/routes.py) so the frontend progress bar can be reused. Only the
    `collecting_events` / `complete` / `error` phases are emitted — the
    hourly poll does not refresh the client cache, so there is no
    `collecting_clients` phase. Disabled / skipped cycles intentionally
    write nothing so the status bar stays idle.
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

    started = _time.time()

    async def wp(data: dict) -> None:
        data["started_at"] = started
        await lock_client.set(
            _ORG_HOURLY_POLL_PROGRESS_KEY,
            json.dumps(data),
            ex=_ORG_HOURLY_POLL_PROGRESS_TTL,
        )

    async def on_page(page: int, fetched: int, total) -> None:
        expected_pages = (total + 999) // 1000 if total else None
        if expected_pages:
            status = (
                f"Hourly poll — page {page}/{expected_pages} "
                f"({fetched:,}/{total:,})"
            )
        else:
            status = f"Hourly poll — page {page} ({fetched:,} so far)"
        await wp({
            "phase": "collecting_events",
            "pages_fetched": page,
            "events_fetched": fetched,
            "total_events_estimated": total,
            "expected_event_pages": expected_pages,
            "status": status,
        })

    try:
        log.info("[org-poll] Starting hourly org-level event collection")
        await wp({
            "phase": "collecting_events",
            "pages_fetched": 0,
            "events_fetched": 0,
            "total_events_estimated": None,
            "expected_event_pages": None,
            "status": "Hourly poll — gathering client events...",
        })

        site_counts = await collect_org(MIST_ORG_ID, duration="1h", on_page=on_page)
        total = sum(site_counts.values())
        log.info(
            f"[org-poll] Collection complete: {total} events "
            f"across {len(site_counts)} sites"
        )
        await _record_last_timestamp(_LAST_COLLECTION_KEY)

        await wp({
            "phase": "complete",
            "pages_fetched": -1,
            "events_fetched": total,
            "site_counts": site_counts,
            "sites_with_events": len(site_counts),
            "status": (
                f"Hourly poll complete — {total:,} events "
                f"across {len(site_counts)} sites"
            ),
        })

        # ── Auto-chain: detect after collect ─────────────────────────────
        # Keep the global mutex throughout the handoff — rewrite its value
        # from "collecting" → "detecting" in place so no manual trigger can
        # sneak in between collect and detect.
        if await get_auto_detect_enabled():
            log.info("[org-poll] Auto-detect enabled — chaining to detection pipeline")
            await _transfer_global_lock(lock_client, "detecting")
            await _release_phase_memory("org-poll collect→detect")
            try:
                site_map = await _get_cached_site_map(lock_client)
            except Exception:
                log.exception("[org-poll] Auto-detect: failed to fetch site map — skipping detect")
            else:
                site_ids = list(site_map.keys())

                async def _write_detect_progress(data: dict) -> None:
                    await lock_client.set(
                        _ORG_DETECT_PROGRESS_KEY,
                        json.dumps(data),
                        ex=_ORG_DETECT_PROGRESS_TTL,
                    )

                try:
                    await _run_org_pipeline_body(
                        site_ids=site_ids,
                        site_map=site_map,
                        progress_callback=_write_detect_progress,
                    )
                except Exception:
                    log.exception("[org-poll] Auto-detect chain failed")
        else:
            log.debug("[org-poll] Auto-detect disabled — skipping chained detection")
    except Exception as exc:
        log.exception("[org-poll] Event collection failed")
        try:
            await wp({"phase": "error", "message": str(exc)})
        except Exception:
            log.exception("[org-poll] Failed to write error progress")
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
    # Unconditional nightly rebuild using the trailing 24hr of events.
    scheduler.add_job(
        markov_baseline_job,
        "cron",
        hour=0,
        minute=30,
        id="markov_baseline",
        name="Markov Chain Baseline Rebuild",
    )

    # One-shot startup rebuild: only fills in baselines that are missing or
    # expired in Redis. Baselines carry a 48hr TTL, so a restart within that
    # window no longer triggers a redundant per-site-per-WLAN rebuild of
    # hundreds of baselines at boot. If no events are in SQLite yet the job
    # exits early and the nightly cron will populate them once events
    # accumulate.
    scheduler.add_job(
        markov_baseline_job,
        "date",
        run_date=datetime.now(timezone.utc),
        id="markov_baseline_startup",
        name="Markov Chain Baseline Startup Check",
        kwargs={"skip_existing": True},
    )

    # ARCH-4: Scheduled detection jobs removed. Anomaly detection is now triggered
    # only via POST /api/v1/org/detect or the UI "Re-detect" button.

    # Optional org-level event polling (collection only — detection auto-chains
    # when sasquatch:auto_detect_enabled is "1"). Disabled by default; toggled
    # via POST /api/v1/org/polling. Interval is driven by the
    # `org_detection_interval_hours` general-config control so operators can
    # slow or speed up the poll from the GUI. Value is read at startup — a
    # service restart is required for the new interval to take effect.
    if MIST_ORG_ID:
        poll_hours = int(_config_mod.get("general", "org_detection_interval_hours"))
        scheduler.add_job(
            org_event_poll_job,
            "interval",
            hours=poll_hours,
            id="org_event_poll",
            name="Org-Level Event Poll",
            max_instances=1,
            coalesce=True,
        )
        log.info("Org event poll scheduled every %d hour(s)", poll_hours)

    return scheduler

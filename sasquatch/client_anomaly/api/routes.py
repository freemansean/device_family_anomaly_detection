"""
routes.py — FastAPI route definitions.

Events and client cache are read from SQLite; anomaly results, features, health
scores, findings, and config remain in Redis. No real-time Mist API calls in the
request path. The API is read-only except for the manual refresh POST.

WLAN scoping: endpoints that return findings, anomalies, or event summaries require a
?wlan= query parameter specifying the SSID to scope results to. The parameter is
mandatory — omitting it returns a 422 error.
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
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

from ..anomaly_detector import (
    _anomalies_redis_key,
    _findings_redis_key,
    _org_anomalies_redis_key,
    _org_findings_redis_key,
    get_anomalies,
    get_findings,
    score,
)
from ..client_cache import get_client_cache, refresh_client_cache_org
from ..event_collector import (
    EVENT_CATEGORIES,
    collect_org_full,
    get_event_type_index,
    get_events,
    get_wlans,
)
from ..feature_engineer import _family_event_counts_redis_key, _features_redis_key, build_features, get_features
from ..health_scorer import get_health, score_health, _health_redis_key
from ..markov_analyzer import build_and_store_baseline as build_markov_baseline
from .. import summary_cache
from ..scheduler import (
    _GLOBAL_LOCK_KEY,
    _LAST_COLLECTION_KEY,
    _ORG_DETECT_PROGRESS_KEY,
    _ORG_DETECT_PROGRESS_TTL,
    _run_org_pipeline_body,
    _transfer_global_lock,
    get_auto_detect_enabled,
    get_global_lock_status,
    get_job_status,
    run_org_pipeline,
    set_auto_detect_enabled,
)
from .. import alert_tracker
from ..webhook_dispatcher import evaluate_and_dispatch, run_family_tshoot

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")


def _viz_random_state() -> int | None:
    """Resolve the visualization PCA random seed at call time.

    Reads `anomaly.anomaly_random_state` through the config module so GUI-set
    overrides in config_overrides.json take effect without a restart. A value
    of -1 means "non-deterministic" and returns None.
    """
    try:
        val = int(_config_mod.get("anomaly", "anomaly_random_state"))
    except (KeyError, ValueError, TypeError):
        val = 42
    return None if val == -1 else val


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
    pca = PCA(n_components=n_components, random_state=_viz_random_state())
    coords = pca.fit_transform(X_scaled)
    if coords.shape[1] == 1:
        coords = np.hstack([coords, np.zeros((coords.shape[0], 1))])
    return coords, pca.explained_variance_ratio_.tolist()


async def _redis_get(key: str):
    client = _get_redis()
    try:
        return await client.get(key)
    finally:
        await client.aclose()


@router.get("/org/detection-enabled")
async def get_org_detection_enabled():
    """Return whether the scheduled org-wide detection job is enabled."""
    client = _get_redis()
    try:
        val = await client.get("sasquatch:org_detection_enabled")
    finally:
        await client.aclose()
    # Absent key = enabled by default
    return {"enabled": val != "0"}


@router.post("/org/detection-enabled")
async def set_org_detection_enabled(body: dict):
    """Enable or disable the scheduled org-wide detection job."""
    enabled = bool(body.get("enabled", True))
    client = _get_redis()
    try:
        await client.set("sasquatch:org_detection_enabled", "1" if enabled else "0")
    finally:
        await client.aclose()
    log.info(f"Org detection {'enabled' if enabled else 'disabled'} by administrator")
    return {"enabled": enabled}


# ---------------------------------------------------------------------------
# Org-level event collection (ARCH-3)
# ---------------------------------------------------------------------------

async def _org_collect_background_task() -> None:
    """
    Full 24hr org-level event collection run as a FastAPI background task.
    Writes phase-by-phase progress to sasquatch:progress:org_collect.

    Phase sequence:
      1. ``collecting_clients`` — refresh the org-wide client cache so event
         enrichment sees up-to-date device metadata.
      2. ``collecting_events`` — stream org-wide client events into SQLite.
    """
    progress_key = "sasquatch:progress:org_collect"
    lock_key = _GLOBAL_LOCK_KEY
    started = _time.time()

    redis_client = _get_redis()

    async def wp(data: dict) -> None:
        data["started_at"] = started
        await redis_client.set(progress_key, json.dumps(data), ex=300)

    acquired = await redis_client.set(
        lock_key,
        json.dumps({"operation": "collecting", "started_at": started}),
        nx=True,
        ex=2 * 60 * 60,
    )
    if not acquired:
        await wp({"phase": "error", "message": "Another operation is already running"})
        await redis_client.aclose()
        return

    try:
        # ── Phase 1: refresh the org-wide client cache ───────────────────
        await wp({
            "phase": "collecting_clients",
            "pages_fetched": 0,
            "clients_fetched": 0,
            "total_clients_estimated": None,
            "expected_client_pages": None,
            "status": "Gathering clients...",
        })

        async def on_client_page(page: int, fetched: int, total: Optional[int]) -> None:
            # With a 1000-record page size, the total number of pages required
            # is ceil(total / 1000). Surface both so the frontend can drive the
            # bar off page/expected_pages rather than a page-count heuristic.
            expected_pages = (total + 999) // 1000 if total else None
            if expected_pages:
                status = (
                    f"Gathering clients — page {page}/{expected_pages} "
                    f"({fetched:,}/{total:,})"
                )
            else:
                status = f"Gathering clients — page {page} ({fetched:,} so far)"
            await wp({
                "phase": "collecting_clients",
                "pages_fetched": page,
                "clients_fetched": fetched,
                "total_clients_estimated": total,
                "expected_client_pages": expected_pages,
                "status": status,
            })

        try:
            total_clients = await refresh_client_cache_org(
                MIST_ORG_ID, on_page=on_client_page
            )
            log.info(f"Org client cache refreshed: {total_clients} clients")
        except Exception:
            log.exception("Org client cache refresh failed — proceeding with existing cache")
            total_clients = 0

        # ── Phase 2: stream org-wide client events ──────────────────────
        await wp({
            "phase": "collecting_events",
            "pages_fetched": 0,
            "events_fetched": 0,
            "clients_fetched": total_clients,
            "total_events_estimated": None,
            "expected_event_pages": None,
            "status": "Gathering client events...",
        })

        async def on_page(page: int, fetched: int, total: Optional[int]) -> None:
            # Mist returns a `total` on the events response (e.g. 171498). At
            # 1000 events per page that's ceil(171498/1000) = 172 calls; use
            # that to drive the progress bar off real work instead of a
            # fixed-step heuristic.
            expected_pages = (total + 999) // 1000 if total else None
            if expected_pages:
                status = (
                    f"Gathering client events — page {page}/{expected_pages} "
                    f"({fetched:,}/{total:,})"
                )
            else:
                status = f"Gathering client events — page {page}"
            await wp({
                "phase": "collecting_events",
                "pages_fetched": page,
                "events_fetched": fetched,
                "clients_fetched": total_clients,
                "total_events_estimated": total,
                "expected_event_pages": expected_pages,
                "status": status,
            })

        site_results = await collect_org_full(MIST_ORG_ID, on_page=on_page)

        total_events = sum(site_results.values())

        await redis_client.set(
            _LAST_COLLECTION_KEY,
            datetime.now(timezone.utc).isoformat(),
        )

        # Auto-enable hourly event polling once a successful full collect lands.
        # The hourly job (org_event_poll_job in scheduler.py) gates on this key,
        # so flipping it here means subsequent hourly increments will run without
        # requiring the operator to flip the toggle in the UI.
        await redis_client.set("sasquatch:event_polling_enabled", "1")
        log.info("Org event polling auto-enabled after successful full collect")

        await wp({
            "phase": "complete",
            "pages_fetched": -1,
            "events_fetched": total_events,
            "clients_fetched": total_clients,
            "site_counts": site_results,
            "sites_with_events": len(site_results),
            "status": (
                f"Complete — {total_clients:,} clients, "
                f"{total_events:,} events across {len(site_results)} sites"
            ),
        })

        # ── Auto-chain: detect after collect ─────────────────────────────
        # Rewrite the global lock in place from "collecting" → "detecting"
        # so a manual trigger cannot sneak in between the two phases. We
        # keep the same redis_client (and therefore hold the lock the whole
        # time) — the finally block below still deletes the lock key.
        if await get_auto_detect_enabled():
            log.info("[org-collect] Auto-detect enabled — chaining to detection pipeline")
            await _transfer_global_lock(redis_client, "detecting")
            try:
                site_map = await _get_org_site_map(redis_client)
            except Exception:
                log.exception("[org-collect] Auto-detect: failed to fetch site map — skipping detect")
            else:
                site_ids = list(site_map.keys())

                async def _write_detect_progress(data: dict) -> None:
                    await redis_client.set(
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
                    log.exception("[org-collect] Auto-detect chain failed")
        else:
            log.debug("[org-collect] Auto-detect disabled — skipping chained detection")

    except Exception as exc:
        log.exception("Org-level collection failed")
        await wp({"phase": "error", "message": str(exc)})
    finally:
        await redis_client.delete(lock_key)
        await redis_client.aclose()


@router.post("/org/collect-full")
async def trigger_org_collect_full(background_tasks: BackgroundTasks):
    """
    Trigger a full 24hr org-level event collection via a single Mist API call.
    Replaces per-site collection loops. Runs in the background.
    Returns 409 if an operation is already in progress (global mutex).
    """
    if not MIST_ORG_ID:
        raise HTTPException(status_code=400, detail="MIST_ORG_ID not configured")
    if not MIST_API_TOKEN:
        raise HTTPException(status_code=400, detail="MIST_API_TOKEN not configured")

    lock_status = await get_global_lock_status()
    if lock_status:
        raise HTTPException(
            status_code=409,
            detail=f"Another operation is already running: {lock_status.get('operation', 'unknown')}",
        )

    background_tasks.add_task(_org_collect_background_task)
    return {"status": "started", "operation": "org_collect_full"}


@router.get("/org/collect-progress")
async def get_org_collect_progress():
    """Return progress of an ongoing org-level event collection."""
    redis_client = _get_redis()
    try:
        raw = await redis_client.get("sasquatch:progress:org_collect")
        if raw:
            return json.loads(raw)
        return {"phase": "idle"}
    finally:
        await redis_client.aclose()


@router.get("/org/hourly-progress")
async def get_org_hourly_progress():
    """Return progress of the hourly org-level event poll (same schema as collect-progress)."""
    redis_client = _get_redis()
    try:
        raw = await redis_client.get("sasquatch:progress:org_hourly_poll")
        if raw:
            return json.loads(raw)
        return {"phase": "idle"}
    finally:
        await redis_client.aclose()


@router.get("/org/job-status")
async def get_org_job_status():
    """
    Return the current job state: active operation, polling status, and last
    collection/detection timestamps. Frontend uses this to disable trigger buttons
    when an operation is active.
    """
    return await get_job_status()


@router.get("/org/polling")
async def get_org_polling_status():
    """Return whether org-level hourly event polling is enabled."""
    redis_client = _get_redis()
    try:
        val = await redis_client.get("sasquatch:event_polling_enabled")
    finally:
        await redis_client.aclose()
    return {"enabled": val == "1"}


@router.post("/org/polling")
async def set_org_polling(body: dict):
    """Enable or disable org-level hourly event polling."""
    enabled = bool(body.get("enabled", True))
    redis_client = _get_redis()
    try:
        await redis_client.set(
            "sasquatch:event_polling_enabled", "1" if enabled else "0"
        )
    finally:
        await redis_client.aclose()
    log.info(f"Org event polling {'enabled' if enabled else 'disabled'}")
    return {"enabled": enabled}


@router.get("/org/auto-detect")
async def get_org_auto_detect():
    """
    Return whether auto-chain detection is enabled. When true, a successful
    manual full collect or hourly poll will automatically run the org
    detection pipeline immediately after the collect completes.

    Default: enabled (missing Redis key counts as on).
    """
    return {"enabled": await get_auto_detect_enabled()}


@router.post("/org/auto-detect")
async def set_org_auto_detect(body: dict):
    """Enable or disable auto-chain detection after collects."""
    enabled = bool(body.get("enabled", True))
    await set_auto_detect_enabled(enabled)
    log.info(f"Auto-detect {'enabled' if enabled else 'disabled'}")
    return {"enabled": enabled}


_WEBHOOK_CONFIG_KEY = "sasquatch:webhook_config"


@router.get("/webhook-config")
async def get_webhook_config():
    """Return current webhook configuration (Redis override values merged with .env defaults)."""
    client = _get_redis()
    try:
        raw = await client.get(_WEBHOOK_CONFIG_KEY)
    finally:
        await client.aclose()

    env_url = os.getenv("ANOMALY_WEBHOOK_URL", "")
    mist_org_id = os.getenv("MIST_ORG_ID", "")
    mist_api_token = os.getenv("MIST_API_TOKEN", "")

    # Start from .env defaults, then apply any Redis overrides
    config = {
        "enabled": bool(env_url),
        "url": env_url,
        "scope": "org_and_site",
        "marvis_tshoot_enabled": bool(mist_org_id and mist_api_token),
        "family_size_threshold": 1,
    }
    if raw:
        config.update(json.loads(raw))
    return config


@router.post("/webhook-config")
async def set_webhook_config(body: dict):
    """Save webhook configuration to Redis, overriding .env defaults at runtime."""
    config: dict = {}
    if "enabled" in body:
        config["enabled"] = bool(body["enabled"])
    if "url" in body:
        config["url"] = str(body["url"]).strip()
    if "scope" in body:
        scope = str(body["scope"])
        if scope not in ("org_only", "org_and_site"):
            raise HTTPException(status_code=400, detail="scope must be 'org_only' or 'org_and_site'")
        config["scope"] = scope
    if "marvis_tshoot_enabled" in body:
        config["marvis_tshoot_enabled"] = bool(body["marvis_tshoot_enabled"])
    if "family_size_threshold" in body:
        try:
            threshold = int(body["family_size_threshold"])
            if threshold < 1:
                raise ValueError
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="family_size_threshold must be an integer >= 1")
        config["family_size_threshold"] = threshold

    client = _get_redis()
    try:
        await client.set(_WEBHOOK_CONFIG_KEY, json.dumps(config))
    finally:
        await client.aclose()

    log.info("Webhook configuration updated by administrator: %s", config)
    return config


# ── General Config + Anomaly Config (file-persisted, survives reboots) ────────

from .. import config as _config_mod

import pathlib as _pathlib

_CONFIG_OVERRIDES_FILE = _pathlib.Path(__file__).parent.parent / "config_overrides.json"


def _load_config_overrides() -> dict:
    """Load persisted config overrides from disk. Returns empty dict on missing/corrupt file."""
    try:
        return json.loads(_CONFIG_OVERRIDES_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_config_section(section: str, values: dict) -> None:
    """Merge `values` into the named section of config_overrides.json and write to disk."""
    overrides = _load_config_overrides()
    overrides[section] = values
    _CONFIG_OVERRIDES_FILE.write_text(json.dumps(overrides, indent=2))


@router.get("/general-config")
async def get_general_config():
    """Return current general config — resolved values from config module."""
    return _config_mod.get_section("general")


@router.post("/general-config")
async def set_general_config(body: dict):
    """Persist general config overrides to disk so they survive service restarts."""
    config: dict = {}

    int_bounds = {
        "org_detection_interval_hours": (1, 168),
        "anomaly_min_mac_events": (1, 10000),
        "alarm_min_family_size": (1, 1000),
        # Negative dBm. -120 is effectively "off" (below noise floor).
        "anomaly_rssi_min_threshold": (-120, 0),
    }
    float_bounds = {
        # Health score threshold for dual-gate alarm generation. Lives under
        # general config because it gates alarm generation alongside
        # alarm_min_family_size at both org and site level.
        "anomaly_health_score_threshold": (0.0, 1.0),
        # Service-alarm device-percentage threshold. A family fires an alarm
        # via the service-alarm gate when at least this fraction of its MACs
        # have individually tripped a service alarm.
        "alarm_service_device_pct": (0.0, 1.0),
        # Fraction of family clients flagged by DBSCAN-or-Markov required to
        # fire an alarm via the rollup gate. Inter-family centroid detection
        # remains independently sufficient.
        "alarm_dbscan_markov_ratio": (0.0, 1.0),
    }
    for key, (lo, hi) in int_bounds.items():
        if key in body:
            try:
                v = int(body[key])
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail=f"{key} must be an integer")
            if not (lo <= v <= hi):
                raise HTTPException(status_code=400, detail=f"{key} must be between {lo} and {hi}")
            config[key] = v
    for key, (lo, hi) in float_bounds.items():
        if key in body:
            try:
                v = float(body[key])
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail=f"{key} must be a number")
            if not (lo <= v <= hi):
                raise HTTPException(status_code=400, detail=f"{key} must be between {lo} and {hi}")
            config[key] = v

    _save_config_section("general", config)
    log.info("General configuration updated by administrator: %s", config)
    return config


@router.get("/anomaly-config")
async def get_anomaly_config():
    """Return current anomaly detection config — all resolved values from config module."""
    return _config_mod.get_section("anomaly")


@router.post("/anomaly-config")
async def set_anomaly_config(body: dict):
    """Persist anomaly detection config overrides to disk so they survive service restarts."""
    config: dict = {}

    float_bounds = {
        "anomaly_if_contamination": (0.01, 0.5),
        "anomaly_dbscan_pca_variance": (0.5, 1.0),
        "anomaly_dbscan_family_noise_threshold": (0.0, 1.0),
        "anomaly_centroid_dist_threshold": (0.0, 2.0),
        "anomaly_centroid_healthy_ref_threshold": (0.0, 1.0),
        "markov_family_outlier_ratio": (0.0, 1.0),
        "markov_outlier_episode_ratio": (0.0, 1.0),
        "markov_stuck_loop_threshold": (0.0, 1.0),
    }
    int_bounds = {
        "anomaly_if_n_estimators": (10, 1000),
        "anomaly_random_state": (-1, 999999),
        "anomaly_min_peers": (1, 500),
        # Integer 1–10, mapped at runtime to 0.01–0.10. Used to derive
        # DBSCAN min_samples = max(3, int(n_clients * pct)) per run.
        "anomaly_dbscan_min_samples_pct": (1, 10),
        "anomaly_centroid_healthy_ref_min": (1, 100),
        "anomaly_finding_min_size": (1, 500),
        "markov_min_episode_length": (1, 100),
        "markov_min_scoreable_episodes": (1, 100),
        "markov_stuck_loop_min_events": (1, 10000),
    }
    for key, (lo, hi) in float_bounds.items():
        if key in body:
            try:
                v = float(body[key])
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail=f"{key} must be a number")
            if not (lo <= v <= hi):
                raise HTTPException(status_code=400, detail=f"{key} must be between {lo} and {hi}")
            config[key] = v
    for key, (lo, hi) in int_bounds.items():
        if key in body:
            try:
                v = int(body[key])
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail=f"{key} must be an integer")
            if not (lo <= v <= hi):
                raise HTTPException(status_code=400, detail=f"{key} must be between {lo} and {hi}")
            config[key] = v

    _save_config_section("anomaly", config)
    log.info("Anomaly configuration updated by administrator: %s", config)
    return config


@router.get("/sites/{site_id}/progress")
async def get_site_progress(site_id: str):
    """Return the latest detection cycle progress for a site."""
    raw = await _redis_get(f"sasquatch:progress:{site_id}")
    if not raw:
        return {"phase": "idle"}
    return json.loads(raw)


@router.get("/wlans")
async def list_wlans(site_id: Optional[str] = Query(None)):
    """
    Return unique WLAN (SSID) names derived from the global event store.
    Optionally scoped to a single site via ?site_id=. Returns sorted list.
    """
    wlans = await get_wlans(site_id=site_id)
    return {"wlans": wlans, "site_id": site_id}


async def build_org_summary(redis_client, site_map: dict[str, str], wlan: str) -> dict:
    """
    Compute the /org/summary response from Redis state. Pure aggregator — no
    Mist API calls, no HTTPException raises. Called by both the route handler
    (cache miss path) and the pipeline writer (post-detection cache fill).
    """
    # Load all events once, counting per site. Per-site sorted sets are fetched
    # in a single pipeline inside get_events().
    all_events = await get_events()
    events_per_site: Counter = Counter(
        e["site_id"]
        for e in all_events
        if e.get("site_id") and e.get("wlan") == wlan
    )

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

    from ..webhook_dispatcher import (
        family_passes_dbscan_markov_gate,
        get_alarm_dbscan_markov_ratio,
        get_alarm_min_family_size,
        get_alarm_service_device_pct,
        get_health_score_threshold,
    )
    _SUMMARY_HEALTH_THRESHOLD = get_health_score_threshold()
    _SUMMARY_MIN_FAMILY_SIZE = int(get_alarm_min_family_size())
    _SUMMARY_SERVICE_DEVICE_PCT = float(get_alarm_service_device_pct())
    _SUMMARY_DBSCAN_MARKOV_RATIO = float(get_alarm_dbscan_markov_ratio())

    result = []
    for sid, site_name in sites_sorted:
        findings = findings_by_site[sid]
        health = health_by_site[sid]
        event_count = events_per_site.get(sid, 0)
        # alert_count: families that are both anomalous (in findings) AND unhealthy.
        # "Unhealthy" matches the webhook dispatch gate: health_score below
        # threshold OR enough devices in the family have individually tripped a
        # service alarm to meet the device-percentage floor. Tiny families
        # below alarm_min_family_size are suppressed to stay in sync with
        # webhook dispatch and the OrgAlerts feed.
        def _is_alert(f: dict) -> bool:
            if not family_passes_dbscan_markov_gate(f, _SUMMARY_DBSCAN_MARKOV_RATIO):
                return False
            fam_health = health.get(f.get("device_family"), {})
            score_bad = fam_health.get("health_score", 1.0) < _SUMMARY_HEALTH_THRESHOLD
            service_alarms_list = fam_health.get("service_alarms") or []
            mac_alarm_ratio = float(fam_health.get("mac_alarm_ratio", 0.0) or 0.0)
            service_bad = (
                len(service_alarms_list) > 0
                and mac_alarm_ratio >= _SUMMARY_SERVICE_DEVICE_PCT
            )
            return (
                (score_bad or service_bad)
                and (f.get("total_mac_count", 0) or 0) >= _SUMMARY_MIN_FAMILY_SIZE
            )
        alert_count = sum(1 for f in findings if _is_alert(f))
        # A family counts as "impacted" only when at least one anomaly
        # detector flag is actually set on the finding — either a family-
        # level flag (centroid, DBSCAN, Markov) or at least one per-MAC
        # Isolation-Forest outlier. Findings that exist purely because of
        # a Markov bypass but carry no set flag should not inflate the
        # card badge, and a family must not be counted twice just because
        # multiple detectors fired.
        def _has_any_flag(f: dict) -> bool:
            return bool(
                f.get("is_family_outlier")
                or f.get("is_family_dbscan_outlier")
                or f.get("is_family_markov_outlier")
                or (f.get("if_outlier_count", 0) or 0) > 0
                or (f.get("dbscan_outlier_count", 0) or 0) > 0
            )
        impacted_families = {
            f.get("device_family")
            for f in findings
            if f.get("device_family") and _has_any_flag(f)
        }
        result.append({
            "site_id": sid,
            "site_name": site_name,
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "significant"),
            "warning_count": sum(1 for f in findings if f.get("severity") == "moderate"),
            "info_count": sum(1 for f in findings if f.get("severity") == "minimal"),
            "impacted_family_count": len(impacted_families),
            "alert_count": alert_count,
            "event_count": event_count,
            "has_data": event_count > 0,
        })

    return {
        "sites": result,
        "total_sites": len(result),
        "org_significant_count": sum(1 for f in org_findings if f.get("severity") == "significant"),
        "org_moderate_count": sum(1 for f in org_findings if f.get("severity") == "moderate"),
        "org_minimal_count": sum(1 for f in org_findings if f.get("severity") == "minimal"),
        "org_alert_count": sum(
            1 for f in org_findings
            if family_passes_dbscan_markov_gate(f, _SUMMARY_DBSCAN_MARKOV_RATIO)
            and (
                f.get("health_score", 1.0) < _SUMMARY_HEALTH_THRESHOLD
                or (
                    len(f.get("service_alarms") or []) > 0
                    and float(f.get("mac_alarm_ratio", 0.0) or 0.0) >= _SUMMARY_SERVICE_DEVICE_PCT
                )
            )
            and (f.get("total_mac_count", 0) or 0) >= _SUMMARY_MIN_FAMILY_SIZE
        ),
        "org_finding_count": len(org_findings),
    }


@router.get("/org/summary")
async def get_org_summary(wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Per-site findings and event counts for the org overview.
    Reads from Redis — no real-time Mist API calls for the data itself.

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    if not MIST_ORG_ID:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID not configured.")
    if not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        cache_key = summary_cache._org_summary_key(wlan)
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        response = await build_org_summary(redis_client, site_map, wlan)
        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


async def _org_detect_background_task(site_ids: list[str], site_map: dict[str, str]) -> None:
    """
    ARCH-5 org detection pipeline run as a FastAPI background task.
    Writes progress to sasquatch:progress:org_detect.
    Sequence: build features → org-wide scoring → per-site scoring.
    """
    redis_client = _get_redis()

    async def _write_progress(data: dict) -> None:
        await redis_client.set(
            _ORG_DETECT_PROGRESS_KEY, json.dumps(data), ex=_ORG_DETECT_PROGRESS_TTL,
        )

    try:
        await run_org_pipeline(
            site_ids=site_ids,
            site_map=site_map,
            progress_callback=_write_progress,
        )
    except RuntimeError:
        # Lock already held — progress already written by run_org_pipeline
        pass
    except Exception:
        log.exception("[org detect bg] Pipeline failed")
    finally:
        await redis_client.aclose()


@router.post("/org/detect")
async def trigger_org_detect_only(background_tasks: BackgroundTasks):
    """
    ARCH-5: Trigger the org detection pipeline as a background task.

    Pipeline sequence:
      1. Build features + score health for all sites
      2. Run org-wide anomaly detection → dispatch org webhooks
      3. Run per-site anomaly detection → dispatch per-site webhooks

    Org findings appear in the UI as soon as phase 2 completes.
    Per-site findings appear incrementally as each site completes in phase 3.

    Returns 202 immediately. Poll GET /org/detect-progress for status.
    Returns 409 if an operation is already in progress (global mutex).
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    lock_status = await get_global_lock_status()
    if lock_status:
        raise HTTPException(
            status_code=409,
            detail=f"Another operation is already running: {lock_status.get('operation', 'unknown')}",
        )

    redis_client = _get_redis()
    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")
    finally:
        await redis_client.aclose()

    site_ids = list(site_map.keys())
    background_tasks.add_task(_org_detect_background_task, site_ids, site_map)

    return {
        "status": "started",
        "site_count": len(site_ids),
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

    from .. import db as _db

    results = []
    total_deleted = 0
    try:
        # Clients are now stored org-wide (MAC is the unique key across the org),
        # so delete the entire client cache once before iterating sites.
        total_deleted += await _db.delete_clients_for_org(MIST_ORG_ID)
        for sid in site_ids:
            deleted = 0
            # Flush SQLite events for this site (clients handled above, org-wide).
            deleted += await _db.delete_events_for_site(sid)
            # Flush remaining Redis keys (unknown_event_types, progress)
            static_keys = [
                f"sasquatch:unknown_event_types:{sid}",
                f"sasquatch:progress:{sid}",
            ]
            deleted += await redis_client.delete(*static_keys)
            pattern_keys: list[str] = []
            # Exclude markov_baseline keys — they are expensive to rebuild (require 24hr of
            # events) and have their own 48hr TTL. Flushing events/features/findings is
            # sufficient to force a clean redetection without losing the baseline.
            for prefix in ["sasquatch:features:", "sasquatch:anomalies:", "sasquatch:findings:",
                           "sasquatch:health:", "sasquatch:org_anomalies:", "sasquatch:org_findings:"]:
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

        # Drop every pre-computed dashboard summary so the next request
        # falls through to a live recompute (and re-populates the cache).
        total_deleted += await summary_cache.flush_org_summary_cache(redis_client)
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
    Manually trigger an org-wide client cache refresh from the Mist API.
    The cache is org-scoped (MAC unique across the org), so a single API call
    populates the entire cache.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    try:
        total_cached = await refresh_client_cache_org(MIST_ORG_ID)
    except Exception as exc:
        log.exception("Org client refresh failed")
        raise HTTPException(status_code=502, detail=f"Org client refresh failed: {exc}")

    return {
        "status": "ok",
        "org_id": MIST_ORG_ID,
        "total_clients_cached": total_cached,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/org/clients/search")
async def search_org_clients(
    mac: str = Query(..., description="MAC address prefix — colons/hyphens/whitespace optional"),
    limit: int = Query(50, ge=1, le=200, description="Max matches to return"),
):
    """
    Prefix-search the org client cache by MAC address.

    Efficient because ``clients.mac`` is the PRIMARY KEY — a leading-anchored
    ``LIKE 'prefix%'`` uses the PK index for a range scan (O(log n + results))
    rather than a full table scan. Each hit is enriched with the most-recent
    event site_id / wlan / timestamp so the frontend can click-through directly
    into a MAC drilldown that has data.

    The caller passes any common MAC format (``aa:bb:cc``, ``aa-bb-cc``,
    ``aabbcc``) — the helper strips separators and lowercases before matching.
    An input with zero hex characters returns an empty result set without
    hitting the DB.

    Returns::

      {
        "query": "aabbcc",
        "results": [
          {
            "mac": "aabbccddee01",
            "family": "MacBook",
            "manufacturer": "Apple",
            "last_username": "srv_Apple_EP",
            "last_site_id": "abc-123",
            "last_event_site_id": "abc-123",
            "last_event_wlan": "Corp-WiFi",
            "last_event_ts": 1775014952.642,
            "event_count": 142
          },
          ...
        ],
        "truncated": false
      }
    """
    from .. import db as _db

    # Defensive normalisation mirrors the db helper so the echoed ``query`` field
    # reflects what actually got matched against.
    import re as _re
    norm = _re.sub(r"[^0-9a-f]", "", (mac or "").lower())[:12]
    if len(norm) < 2:
        # Require at least 2 hex chars to avoid returning the entire table on a
        # single-char fragment. Common practice for search-as-you-type.
        return {"query": norm, "results": [], "truncated": False}

    results = await _db.search_clients_by_mac_prefix(
        mac_prefix=norm,
        org_id=MIST_ORG_ID or None,
        limit=limit,
    )
    return {
        "query": norm,
        "results": results,
        "truncated": len(results) >= limit,
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


@router.get("/org/detect-progress")
async def get_org_detect_progress():
    """
    ARCH-5: Return progress of the org detection pipeline.

    Response shape:
    {
      "phase": "building_features" | "org_scoring" | "site_scoring" | "complete" | "error" | "idle",
      "current_site": "Building West" | null,
      "sites_complete": 12,
      "total_sites": 50,
      "started_at": 1712678400.0,
      "org_complete": true
    }
    """
    redis_client = _get_redis()
    try:
        raw = await redis_client.get(_ORG_DETECT_PROGRESS_KEY)
    finally:
        await redis_client.aclose()

    if not raw:
        return {
            "phase": "idle",
            "current_site": None,
            "sites_complete": 0,
            "total_sites": 0,
            "started_at": None,
            "org_complete": False,
        }

    return json.loads(raw)


async def build_org_findings(redis_client, site_map: dict[str, str], wlan: str) -> dict:
    """
    Build the /org/findings response from Redis state. Pure aggregator — no
    Mist API calls. Called by the route handler (cache miss path) and the
    pipeline writer (post-detection cache fill).
    """
    raw = await redis_client.get(_org_findings_redis_key(wlan))
    if not raw:
        return {"findings": [], "count": 0, "wlan": wlan}

    findings = json.loads(raw)
    for f in findings:
        for sa in f.get("sites_affected", []):
            sa["site_name"] = site_map.get(sa["site_id"], sa["site_id"])

    return {"findings": findings, "count": len(findings), "wlan": wlan}


@router.get("/org/findings")
async def get_org_findings_endpoint(wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Return org-wide anomaly findings produced by the cross-site detection job.

    Reads from sasquatch:org_findings:{wlan} — a single key written by score_org_wide()
    where every MAC was scored against the full org population. Each finding covers one
    device family across ALL sites (e.g. "iPhone: 41/41 devices org-wide") rather than
    one per-site slice. The sites_affected list on each finding is annotated with
    site_name for display.

    Returns an empty list when the org-wide job has not yet run.

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        cache_key = summary_cache._org_findings_key(wlan)
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        response = await build_org_findings(redis_client, site_map, wlan)
        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


async def build_org_alerts(redis_client, site_map: dict[str, str], wlan: str) -> dict:
    """
    Build the /org/alerts response from Redis state. Pure aggregator — no
    Mist API calls. Called by the route handler (cache miss path) and the
    pipeline writer (post-detection cache fill).
    """
    from ..webhook_dispatcher import (
        family_passes_dbscan_markov_gate,
        get_alarm_dbscan_markov_ratio,
        get_alarm_min_family_size,
        get_alarm_service_device_pct,
        get_health_score_threshold,
    )
    _ALERT_HEALTH_THRESHOLD = get_health_score_threshold()
    _ALARM_MIN_FAMILY_SIZE = int(get_alarm_min_family_size())
    _ALARM_SERVICE_DEVICE_PCT = float(get_alarm_service_device_pct())
    _ALARM_DBSCAN_MARKOV_RATIO = float(get_alarm_dbscan_markov_ratio())

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

    # Org-wide alerts: family must qualify via the centroid OR the
    # DBSCAN-or-Markov rollup gate, AND be unhealthy by health score or
    # service-alarm device-pct, AND meet the alarm_min_family_size floor.
    # Mirrors webhook_dispatcher.evaluate_and_dispatch.
    org_alerts = [
        f for f in org_findings
        if family_passes_dbscan_markov_gate(f, _ALARM_DBSCAN_MARKOV_RATIO)
        and (
            f.get("health_score", 1.0) < _ALERT_HEALTH_THRESHOLD
            or (
                len(f.get("service_alarms") or []) > 0
                and float(f.get("mac_alarm_ratio", 0.0) or 0.0) >= _ALARM_SERVICE_DEVICE_PCT
            )
        )
        and (f.get("total_mac_count", 0) or 0) >= _ALARM_MIN_FAMILY_SIZE
    ]
    for f in org_alerts:
        for sa in f.get("sites_affected", []):
            sa["site_name"] = site_map.get(sa["site_id"], sa["site_id"])

    # Per-site alerts: per-site findings cross-referenced with per-site health.
    # Same gate as org_alerts above.
    site_alerts = []
    for sid, site_name in sites_sorted:
        findings = findings_by_site[sid]
        health = health_by_site[sid]
        alerts = []
        for f in findings:
            if not family_passes_dbscan_markov_gate(f, _ALARM_DBSCAN_MARKOV_RATIO):
                continue
            family_health = health.get(f.get("device_family"), {})
            fam_health_score = family_health.get("health_score", 1.0)
            fam_service_alarms = family_health.get("service_alarms") or []
            fam_mac_alarm_ratio = float(family_health.get("mac_alarm_ratio", 0.0) or 0.0)
            unhealthy_by_score = fam_health_score < _ALERT_HEALTH_THRESHOLD
            unhealthy_by_service = (
                len(fam_service_alarms) > 0
                and fam_mac_alarm_ratio >= _ALARM_SERVICE_DEVICE_PCT
            )
            if (
                (unhealthy_by_score or unhealthy_by_service)
                and (f.get("total_mac_count", 0) or 0) >= _ALARM_MIN_FAMILY_SIZE
            ):
                alerts.append({
                    **f,
                    "health_score": fam_health_score,
                    "health_components": family_health.get("components"),
                    "service_alarms": fam_service_alarms,
                    "service_health": family_health.get("service_health") or {},
                    "mac_alarm_ratio": fam_mac_alarm_ratio,
                })
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


@router.get("/org/alerts")
async def get_org_alerts(wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Return org-wide alerts AND per-site alerts in a single response.

    Org-wide alerts: org findings (cross-site scoring) where health_score < 0.75.
    Site alerts: per-site findings where the family health_score < 0.75, grouped by site.
    Only sites with at least one alert are included in site_alerts.

    All data is read from Redis — no real-time Mist API calls.

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        cache_key = summary_cache._org_alerts_key(wlan)
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        response = await build_org_alerts(redis_client, site_map, wlan)
        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


async def build_org_alerts_full(redis_client, site_map: dict[str, str]) -> dict:
    """
    Build the /org/alerts-full response from Redis state. Pure aggregator —
    no Mist API calls. Called by the route handler (cache miss path) and the
    pipeline writer (post-detection cache fill).
    """
    from ..webhook_dispatcher import (
        family_passes_dbscan_markov_gate,
        get_alarm_dbscan_markov_ratio,
        get_alarm_min_family_size,
        get_alarm_service_device_pct,
        get_health_score_threshold,
    )
    _ALERT_HEALTH_THRESHOLD = get_health_score_threshold()
    _ALARM_MIN_FAMILY_SIZE = int(get_alarm_min_family_size())
    _ALARM_SERVICE_DEVICE_PCT = float(get_alarm_service_device_pct())
    _ALARM_DBSCAN_MARKOV_RATIO = float(get_alarm_dbscan_markov_ratio())

    wlans = await get_wlans(site_id=None)

    sites_sorted = sorted(site_map.items(), key=lambda x: x[1].lower())

    # One pipelined read across every (site, wlan) pair plus every org-wide
    # findings key. Each WLAN contributes 2*len(sites) + 1 reads to the pipeline.
    pipe = redis_client.pipeline()
    for wlan in wlans:
        for sid, _ in sites_sorted:
            pipe.get(_findings_redis_key(sid, wlan))
            pipe.get(_health_redis_key(sid, wlan))
        pipe.get(_org_findings_redis_key(wlan))
    pipeline_results = await pipe.execute() if wlans else []

    n_sites = len(sites_sorted)
    stride = n_sites * 2 + 1

    org_alerts: list[dict] = []
    # site_id -> list of alert dicts (each tagged with its wlan)
    site_alerts_by_site: dict[str, list[dict]] = {sid: [] for sid, _ in sites_sorted}

    for wi, wlan in enumerate(wlans):
        base = wi * stride
        findings_by_site: dict[str, list] = {}
        health_by_site: dict[str, dict] = {}
        for i, (sid, _) in enumerate(sites_sorted):
            raw_f = pipeline_results[base + i * 2]
            raw_h = pipeline_results[base + i * 2 + 1]
            findings_by_site[sid] = json.loads(raw_f) if raw_f else []
            health_by_site[sid] = json.loads(raw_h) if raw_h else {}
        raw_org = pipeline_results[base + n_sites * 2]
        org_findings_for_wlan = json.loads(raw_org) if raw_org else []

        # Org-wide alerts for this WLAN (same gate as /org/alerts)
        for f in org_findings_for_wlan:
            if not family_passes_dbscan_markov_gate(f, _ALARM_DBSCAN_MARKOV_RATIO):
                continue
            unhealthy = (
                f.get("health_score", 1.0) < _ALERT_HEALTH_THRESHOLD
                or (
                    len(f.get("service_alarms") or []) > 0
                    and float(f.get("mac_alarm_ratio", 0.0) or 0.0) >= _ALARM_SERVICE_DEVICE_PCT
                )
            )
            meets_floor = (f.get("total_mac_count", 0) or 0) >= _ALARM_MIN_FAMILY_SIZE
            if unhealthy and meets_floor:
                tagged = {**f, "wlan": f.get("wlan") or wlan}
                for sa in tagged.get("sites_affected", []):
                    sa["site_name"] = site_map.get(sa["site_id"], sa["site_id"])
                org_alerts.append(tagged)

        # Per-site alerts for this WLAN
        for sid, _ in sites_sorted:
            findings = findings_by_site[sid]
            health = health_by_site[sid]
            for f in findings:
                if not family_passes_dbscan_markov_gate(f, _ALARM_DBSCAN_MARKOV_RATIO):
                    continue
                family_health = health.get(f.get("device_family"), {})
                fam_health_score = family_health.get("health_score", 1.0)
                fam_service_alarms = family_health.get("service_alarms") or []
                fam_mac_alarm_ratio = float(family_health.get("mac_alarm_ratio", 0.0) or 0.0)
                unhealthy = (
                    fam_health_score < _ALERT_HEALTH_THRESHOLD
                    or (
                        len(fam_service_alarms) > 0
                        and fam_mac_alarm_ratio >= _ALARM_SERVICE_DEVICE_PCT
                    )
                )
                meets_floor = (f.get("total_mac_count", 0) or 0) >= _ALARM_MIN_FAMILY_SIZE
                if unhealthy and meets_floor:
                    site_alerts_by_site[sid].append({
                        **f,
                        "wlan": f.get("wlan") or wlan,
                        "health_score": fam_health_score,
                        "health_components": family_health.get("components"),
                        "service_alarms": fam_service_alarms,
                        "service_health": family_health.get("service_health") or {},
                        "mac_alarm_ratio": fam_mac_alarm_ratio,
                    })

    site_alerts = []
    for sid, site_name in sites_sorted:
        alerts = site_alerts_by_site.get(sid, [])
        if alerts:
            site_alerts.append({
                "site_id": sid,
                "site_name": site_name,
                "alerts": alerts,
            })

    return {
        "org_alerts": org_alerts,
        "site_alerts": site_alerts,
        "wlans": wlans,
    }


@router.get("/org/alerts-full")
async def get_org_alerts_full():
    """
    Cross-WLAN aggregation of /org/alerts.

    Enumerates every WLAN with events in the retention window, then applies the
    same dual-gate (family-level anomaly + unhealthy + min family size) used by
    /org/alerts against each WLAN's org findings and per-site findings/health.

    Every returned alert carries a `wlan` field so the UI can display which SSID
    the alarm fired on. `site_alerts` is grouped first by site, then each site's
    alert list spans all WLANs (each alert tagged with its own `wlan`).

    This endpoint powers the "Full Alert Summary" tab — the default landing view
    on the Organization page. It is a pure aggregation of existing Redis state;
    no Mist API calls beyond the org site map.

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        cache_key = summary_cache._org_alerts_full_key()
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        response = await build_org_alerts_full(redis_client, site_map)
        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


@router.get("/org/alert-history")
async def get_org_alert_history(
    wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required."),
    days: int = Query(7, ge=1, le=30),
    tz_offset: int = Query(0, description="Browser timezone offset in minutes (JS getTimezoneOffset())"),
):
    """
    Return alert session history for the past N days (default 7), grouped by UTC day.

    Each session represents a contiguous period where a device family at a specific site
    passed the dual alert gate (is_family_outlier + health_score < threshold).

    Sessions that span multiple days appear in each day they were active, with
    window_start/window_end clipped to that day's UTC boundaries.

    Response shape:
      {
        "days": [
          {
            "date": "2026-04-06",
            "label": "Today" | "Yesterday" | "Mon Apr 5",
            "alarms": [
              {
                "family": str,
                "site_id": str,
                "site_name": str,
                "wlan": str,
                "window_start": ISO8601,  // clipped to this day's UTC boundaries
                "window_end":   ISO8601,  // last_seen if active, resolved_at if resolved
                "status": "active" | "resolved",
                "session_first_seen": ISO8601,  // actual alarm start (may be earlier day)
                "total_duration_seconds": int   // full session length so far
              }
            ]
          }
        ],
        "total_sessions": int
      }
    """
    from datetime import timedelta

    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        sessions = await alert_tracker.get_recent_sessions(days=days, wlan=wlan, redis_client=redis_client)
    finally:
        await redis_client.aclose()

    now_ts = _time.time()

    # Build day buckets for the past `days` days in the browser's local timezone, newest first.
    # tz_offset is JS getTimezoneOffset(): minutes *behind* UTC (EDT=+240, UTC+5:30=-330).
    local_offset_sec = -tz_offset * 60  # convert to seconds ahead of UTC
    local_tz = timezone(timedelta(seconds=local_offset_sec))
    today_local = datetime.now(local_tz).replace(hour=0, minute=0, second=0, microsecond=0)
    day_buckets: list[dict] = []
    for offset in range(days):
        day_start_dt = today_local - timedelta(days=offset)
        day_end_dt   = day_start_dt + timedelta(days=1)
        day_start_ts = day_start_dt.timestamp()
        day_end_ts   = day_end_dt.timestamp()

        if offset == 0:
            label = "Today"
        elif offset == 1:
            label = "Yesterday"
        else:
            label = day_start_dt.strftime("%a %b") + " " + str(day_start_dt.day)

        day_buckets.append({
            "date":  day_start_dt.strftime("%Y-%m-%d"),  # local date
            "label": label,
            "day_start_ts": day_start_ts,
            "day_end_ts":   day_end_ts,
            "alarms": [],
        })

    # Expand each session across the days it spans.
    for session in sessions:
        s_start = session.get("first_seen", 0)
        s_end   = session.get("resolved_at") or session.get("last_seen") or now_ts
        status  = session.get("status", "resolved")
        family  = session.get("family", "")
        site_id = session.get("site_id", "")
        site_name = site_map.get(site_id, site_id)
        total_duration = int(s_end - s_start)

        for bucket in day_buckets:
            d_start = bucket["day_start_ts"]
            d_end   = bucket["day_end_ts"]

            # Session overlaps with this day
            if s_start >= d_end or s_end <= d_start:
                continue

            window_start = max(s_start, d_start)
            window_end   = min(s_end, d_end)

            # For today's active alarms, extend window_end to now so it reflects
            # the live duration rather than the last detection cycle timestamp.
            if status == "active" and d_start <= now_ts < d_end:
                window_end = min(now_ts, d_end)

            bucket["alarms"].append({
                "family": family,
                "site_id": site_id,
                "site_name": site_name,
                "wlan": session.get("wlan", wlan),
                "window_start": datetime.fromtimestamp(window_start, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "window_end":   datetime.fromtimestamp(window_end,   tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": status,
                "session_first_seen": datetime.fromtimestamp(s_start, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "total_duration_seconds": total_duration,
                # Finding snapshot fields — populated from the last detection cycle
                "severity":           session.get("severity"),
                "outlier_ratio":      session.get("outlier_ratio"),
                "affected_mac_count": session.get("affected_mac_count"),
                "total_mac_count":    session.get("total_mac_count"),
                "health_score":       session.get("health_score"),
                "health_components":  session.get("health_components") or {},
                "probable_pattern":   session.get("probable_pattern"),
                "top_features":       session.get("top_features") or [],
                "predominant_wlan":   session.get("predominant_wlan"),
            })

    # Sort alarms within each day: active first, then by window_start ascending.
    for bucket in day_buckets:
        bucket["alarms"].sort(key=lambda a: (a["status"] != "active", a["window_start"]))

    # Drop the internal timestamp fields before returning; drop empty days.
    result_days = []
    for bucket in day_buckets:
        if not bucket["alarms"]:
            continue
        result_days.append({
            "date":   bucket["date"],
            "label":  bucket["label"],
            "alarms": bucket["alarms"],
        })

    return {
        "days": result_days,
        "total_sessions": len(sessions),
        "wlan": wlan,
    }


async def build_org_family_insights(redis_client, site_map: dict[str, str], wlan: str) -> dict:
    """
    Build the /org/family-insights response from Redis state. Pure aggregator —
    no Mist API calls. Called by the route handler (cache miss path) and the
    pipeline writer (post-detection cache fill).
    """
    # Fetch per-site findings, anomalies, health scores, pre-computed family event
    # counts, and the org-wide findings in one pipeline round trip.
    site_ids_ordered = list(site_map.keys())
    pipe = redis_client.pipeline()
    for sid in site_ids_ordered:
        pipe.get(_findings_redis_key(sid, wlan))
        pipe.get(_health_redis_key(sid, wlan))
        pipe.get(_family_event_counts_redis_key(sid, wlan))
    pipe.get(_org_findings_redis_key(wlan))
    pipeline_results = await pipe.execute()
    n = len(site_ids_ordered)
    findings_by_site = {
        sid: (json.loads(pipeline_results[i * 3]) if pipeline_results[i * 3] else [])
        for i, sid in enumerate(site_ids_ordered)
    }
    health_by_site = {
        sid: (json.loads(pipeline_results[i * 3 + 1]) if pipeline_results[i * 3 + 1] else {})
        for i, sid in enumerate(site_ids_ordered)
    }
    event_counts_by_site = {
        sid: (json.loads(pipeline_results[i * 3 + 2]) if pipeline_results[i * 3 + 2] else {})
        for i, sid in enumerate(site_ids_ordered)
    }
    # family_is_family_outlier and family_worst_dbscan_severity come exclusively from
    # org-wide detection, not per-site findings. IF and DBSCAN badges mean the family
    # was flagged across the whole org population, not just at one site.
    raw_org_findings = pipeline_results[n * 3]
    org_findings_list: list[dict] = json.loads(raw_org_findings) if raw_org_findings else []
    family_is_family_outlier: dict[str, bool] = {
        f["device_family"]: True
        for f in org_findings_list
        if f.get("is_family_outlier") and f.get("device_family")
    }
    SEVERITY_RANK = {"significant": 3, "moderate": 2, "minimal": 1}

    # Org-wide DBSCAN severity, Markov ratio, and DBSCAN outlier site count — all read
    # directly from org findings (not aggregated from per-site findings).
    org_family_dbscan_severity: dict[str, str] = {}
    org_family_markov_ratio: dict[str, float] = {}
    org_family_markov_is_outlier: dict[str, bool] = {}
    org_family_markov_reason: dict[str, str | None] = {}
    org_family_dbscan_site_count: dict[str, int] = {}
    for f in org_findings_list:
        fam = f.get("device_family")
        if not fam:
            continue
        sev = f.get("dbscan_severity")
        if sev and SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(org_family_dbscan_severity.get(fam, ""), 0):
            org_family_dbscan_severity[fam] = sev
        ratio = f.get("markov_family_anomaly_ratio")
        if ratio is not None:
            org_family_markov_ratio[fam] = ratio
        if f.get("is_family_markov_outlier"):
            org_family_markov_is_outlier[fam] = True
        reason = f.get("markov_family_reason")
        if reason and fam not in org_family_markov_reason:
            org_family_markov_reason[fam] = reason
        cnt = f.get("dbscan_outlier_site_count")
        if cnt is not None:
            org_family_dbscan_site_count[fam] = cnt

    family_event_counts: dict[str, Counter] = defaultdict(Counter)
    family_total_events: Counter = Counter()
    family_worst_severity: dict[str, str] = {}
    family_outlier_sites: dict[str, list[str]] = defaultdict(list)
    family_is_markov_outlier: dict[str, bool] = defaultdict(bool)
    family_worst_markov_ratio: dict[str, float] = {}
    family_site_count: Counter = Counter()
    # mac_count is summed across sites (same device at multiple sites counted once per site).
    family_mac_count: Counter = Counter()
    # Health score aggregation: weighted sum and total weight per family for averaging
    family_health_weighted_sum: dict[str, float] = defaultdict(float)
    family_health_weight_total: dict[str, float] = defaultdict(float)
    family_health_components_sum: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    # Per-service org rollup: sum active/unhealthy MAC counts and active-weighted
    # health values per family across all sites. Org-level service alarm fires when
    # the summed unhealthy/active ratio exceeds FAMILY_SERVICE_ALARM_THRESHOLD across
    # the full device-family scope (matches the user-specified ">50% of clients in
    # the total device family scope" semantic).
    from ..health_scorer import (
        SERVICES as _HSCORE_SERVICES,
        FAMILY_SERVICE_ALARM_THRESHOLD as _HSCORE_FAMILY_SVC_THRESHOLD,
    )
    family_svc_active: dict[str, dict[str, int]] = defaultdict(
        lambda: {svc: 0 for svc in _HSCORE_SERVICES}
    )
    family_svc_unhealthy: dict[str, dict[str, int]] = defaultdict(
        lambda: {svc: 0 for svc in _HSCORE_SERVICES}
    )
    family_svc_health_wsum: dict[str, dict[str, float]] = defaultdict(
        lambda: {svc: 0.0 for svc in _HSCORE_SERVICES}
    )
    sites_with_data = 0

    for site_id, site_name in site_map.items():
        site_counts = event_counts_by_site.get(site_id, {})
        if not site_counts:
            continue
        sites_with_data += 1
        findings: list[dict] = findings_by_site[site_id]

        # Aggregate pre-computed family event category counts.
        for family, fdata in site_counts.items():
            for cat, cnt in fdata.get("categories", {}).items():
                family_event_counts[family][cat] += cnt
            family_total_events[family] += fdata.get("total_events", 0)
            family_mac_count[family] += fdata.get("mac_count", 0)
            family_site_count[family] += 1

        for finding in findings:
            fam = finding.get("device_family")
            if not fam:
                continue
            sev = finding.get("severity")
            if sev and SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(family_worst_severity.get(fam, ""), 0):
                family_worst_severity[fam] = sev
            if finding.get("is_family_markov_outlier"):
                family_is_markov_outlier[fam] = True
            markov_ratio = finding.get("markov_family_anomaly_ratio")
            if markov_ratio is not None and markov_ratio > family_worst_markov_ratio.get(fam, 0.0):
                family_worst_markov_ratio[fam] = markov_ratio
            # dbscan_severity is sourced from org-wide findings, not per-site findings.
            if sev in SEVERITY_RANK:
                family_outlier_sites[fam].append(site_name)

        # Accumulate health scores — mac_count-weighted so every device gets equal vote,
        # matching the per-device-average principle in health_scorer.py and the weighting
        # used when attaching health to org findings in score_org_wide().
        site_health = health_by_site.get(site_id, {})
        for fam, hdata in site_health.items():
            weight = hdata.get("mac_count", 0)
            if weight > 0:
                family_health_weighted_sum[fam] += hdata.get("health_score", 1.0) * weight
                family_health_weight_total[fam] += weight
                for comp, rate in hdata.get("components", {}).items():
                    family_health_components_sum[fam][comp] += rate * weight
            # Sum service alarm counts and health across sites for org rollup.
            site_svc_counts = hdata.get("service_alarm_counts", {}) or {}
            site_svc_health = hdata.get("service_health", {}) or {}
            for svc in _HSCORE_SERVICES:
                info = site_svc_counts.get(svc) or {}
                a = int(info.get("active", 0))
                u = int(info.get("unhealthy", 0))
                family_svc_active[fam][svc] += a
                family_svc_unhealthy[fam][svc] += u
                sh_val = site_svc_health.get(svc)
                if sh_val is not None and a > 0:
                    family_svc_health_wsum[fam][svc] += float(sh_val) * a

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
        # Org-wide service rollup: alarm fires when summed unhealthy/active > threshold.
        svc_active_map = family_svc_active.get(family, {})
        svc_unhealthy_map = family_svc_unhealthy.get(family, {})
        svc_health_wsum_map = family_svc_health_wsum.get(family, {})
        service_health_out: dict[str, float | None] = {}
        service_alarm_counts_out: dict[str, dict[str, int]] = {}
        service_alarms_out: list[str] = []
        for svc in _HSCORE_SERVICES:
            a = svc_active_map.get(svc, 0)
            u = svc_unhealthy_map.get(svc, 0)
            service_alarm_counts_out[svc] = {"active": a, "unhealthy": u}
            if a > 0:
                service_health_out[svc] = round(svc_health_wsum_map.get(svc, 0.0) / a, 4)
                if (u / a) > _HSCORE_FAMILY_SVC_THRESHOLD:
                    service_alarms_out.append(svc)
            else:
                service_health_out[svc] = None
        is_sa = family.endswith(".service_account")
        families_out[family] = {
            "family_kind": "service_account" if is_sa else "device_family",
            "service_account_label": family[: -len(".service_account")] if is_sa else "",
            "total_events": total,
            "client_count": family_mac_count[family],
            "site_count": family_site_count[family],
            "worst_severity": family_worst_severity.get(family),
            "worst_dbscan_severity": org_family_dbscan_severity.get(family),
            "dbscan_outlier_site_count": org_family_dbscan_site_count.get(family, 0),
            "is_family_outlier_any_site": family_is_family_outlier.get(family, False),
            "is_family_markov_outlier_any_site": org_family_markov_is_outlier.get(family, False),
            "worst_markov_ratio": org_family_markov_ratio.get(family),
            "markov_family_reason": org_family_markov_reason.get(family),
            "outlier_sites": family_outlier_sites.get(family, []),
            "health_score": health_score,
            "health_components": health_components,
            "service_health": service_health_out,
            "service_alarm_counts": service_alarm_counts_out,
            "service_alarms": service_alarms_out,
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


@router.get("/org/family-insights")
async def get_org_family_insights(wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Aggregate event category counts and anomaly findings per device family across all org sites.
    Optionally scoped to a specific WLAN via ?wlan=.

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    try:
        cache_key = summary_cache._org_family_insights_key(wlan)
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        response = await build_org_family_insights(redis_client, site_map, wlan)
        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


@router.get("/org/families/{family}/drilldown")
async def get_org_family_drilldown(family: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Org-wide per-MAC drilldown for a single device family.

    Service-account families ("{label}.service_account") are handled via a
    separate code path: their underlying events are still tagged with the
    real device family, so the rows are derived from sa anomaly records and
    each row carries `primary_device_family` so the GUI can show the mix of
    underlying device types sharing the username.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    is_sa_family = family.endswith(".service_account")
    family_kind = "service_account" if is_sa_family else "device_family"
    sa_label = family[: -len(".service_account")] if is_sa_family else ""

    redis_client = _get_redis()
    rows: list[dict] = []
    total_if_outliers = 0
    total_dbscan_outliers = 0
    total_markov_outliers = 0
    sa_member_families: set[str] = set()

    try:
        try:
            site_map = await _get_org_site_map(redis_client)
        except Exception:
            raise HTTPException(status_code=502, detail="Could not reach Mist API")

        # Load all events once from SQLite.
        all_events = await get_events()
        events_by_site: dict[str, list[dict]] = defaultdict(list)
        for evt in all_events:
            sid = evt.get("site_id")
            if sid and evt.get("wlan") == wlan:
                events_by_site[sid].append(evt)

        # Fetch anomalies and findings from Redis, client caches from SQLite.
        #
        # Fallback chain for per-site anomalies:
        #   1. sasquatch:anomalies:{site}:{wlan}      — written by score() in Phase 4
        #   2. sasquatch:org_anomalies:{site}:{wlan}  — written by score_org_wide() in Phase 3
        #
        # Phase 4 silently skips (site, wlan) combos where build_features wrote an
        # empty feature dict (every MAC below ANOMALY_MIN_MAC_EVENTS), but Phase 3
        # still scores those MACs via the org-wide peer pool and writes
        # org_anomalies keyed by real MAC with an identical record shape. Without
        # this fallback, the drilldown under-counts any alert card whose MACs were
        # only scored org-wide — mirroring the fallback already in place in
        # `get_mac_anomaly` (see routes.py ~2396).
        site_ids_ordered = list(site_map.keys())
        pipe = redis_client.pipeline()
        for sid in site_ids_ordered:
            pipe.get(_anomalies_redis_key(sid, wlan))
            pipe.get(_findings_redis_key(sid, wlan))
            pipe.get(_org_anomalies_redis_key(sid, wlan))
        pipeline_results = await pipe.execute()
        anomalies_by_site = {}
        for i, sid in enumerate(site_ids_ordered):
            per_site_raw = pipeline_results[i * 3]
            org_raw = pipeline_results[i * 3 + 2]
            if per_site_raw:
                anomalies_by_site[sid] = json.loads(per_site_raw)
            elif org_raw:
                anomalies_by_site[sid] = json.loads(org_raw)
            else:
                anomalies_by_site[sid] = None
        findings_by_site = {
            sid: (json.loads(pipeline_results[i * 3 + 1]) if pipeline_results[i * 3 + 1] else [])
            for i, sid in enumerate(site_ids_ordered)
        }

        # Client cache is org-wide (MAC unique across the org) — load once.
        org_client_cache: dict = await get_client_cache() or {}

        for site_id, site_name in site_map.items():
            anomalies_raw_data = anomalies_by_site.get(site_id)
            if not anomalies_raw_data:
                continue

            anomalies: dict = anomalies_raw_data
            client_cache: dict = org_client_cache

            if is_sa_family:
                # Service-account branch: gather sa records (composite "{mac}#sa"
                # keys whose device_family equals the sa family name). Each sa
                # record points at a real primary_mac whose events still live
                # under the primary device_family in events_by_site.
                site_sa_records: dict[str, dict] = {}  # primary_mac → sa anomaly record
                for ck, data in anomalies.items():
                    if data.get("device_family") != family:
                        continue
                    if not data.get("is_service_account_record"):
                        continue
                    primary_mac = data.get("primary_mac") or ck
                    site_sa_records[primary_mac] = data

                if not site_sa_records:
                    continue

                mac_categories: dict[str, Counter] = defaultdict(Counter)
                mac_total: dict[str, int] = defaultdict(int)
                for event in events_by_site.get(site_id, []):
                    mac = (event.get("mac") or "").replace(":", "").lower()
                    if not mac or mac not in site_sa_records:
                        continue
                    mac_categories[mac][event.get("event_category", "OTHER")] += 1
                    mac_total[mac] += 1

                for primary_mac, data in site_sa_records.items():
                    is_if_outlier = data.get("is_if_outlier", False)
                    is_dbscan_outlier = data.get("is_dbscan_outlier", False)
                    is_markov_outlier = data.get("is_markov_outlier", False)
                    if is_if_outlier:
                        total_if_outliers += 1
                    if is_dbscan_outlier:
                        total_dbscan_outliers += 1
                    if is_markov_outlier:
                        total_markov_outliers += 1
                    primary_device_family = (
                        data.get("primary_device_family")
                        or client_cache.get(primary_mac, {}).get("family", "Unknown")
                    )
                    if primary_device_family:
                        sa_member_families.add(primary_device_family)
                    rows.append({
                        "mac": primary_mac,
                        "site_id": site_id,
                        "site_name": site_name,
                        "if_score": data.get("if_score"),
                        "is_if_outlier": is_if_outlier,
                        "is_dbscan_outlier": is_dbscan_outlier,
                        "is_markov_outlier": is_markov_outlier,
                        "markov_episode_anomaly_ratio": data.get("markov_episode_anomaly_ratio", 0.0),
                        "markov_scoreable_episodes": data.get("markov_scoreable_episodes", 0),
                        "markov_anomalous_episodes": data.get("markov_anomalous_episodes", 0),
                        "markov_reason": data.get("markov_reason"),
                        "event_count": data.get("event_count", 0),
                        "random_mac": data.get("random_mac", False),
                        "client_metadata": client_cache.get(primary_mac, {}),
                        "categories": {cat: mac_categories[primary_mac].get(cat, 0) for cat in EVENT_CATEGORIES},
                        "total_events": mac_total.get(primary_mac, data.get("event_count", 0)),
                        "primary_device_family": primary_device_family,
                        "last_username": data.get("last_username", ""),
                        "is_service_account_record": True,
                    })
                continue

            mac_categories = defaultdict(Counter)
            mac_total = defaultdict(int)
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
                is_dbscan_outlier = data.get("is_dbscan_outlier", False)
                is_markov_outlier = data.get("is_markov_outlier", False)
                if is_if_outlier:
                    total_if_outliers += 1
                if is_dbscan_outlier:
                    total_dbscan_outliers += 1
                if is_markov_outlier:
                    total_markov_outliers += 1
                rows.append({
                    "mac": mac,
                    "site_id": site_id,
                    "site_name": site_name,
                    "if_score": data.get("if_score"),
                    "is_if_outlier": is_if_outlier,
                    "is_dbscan_outlier": is_dbscan_outlier,
                    "is_markov_outlier": is_markov_outlier,
                    "markov_episode_anomaly_ratio": data.get("markov_episode_anomaly_ratio", 0.0),
                    "markov_scoreable_episodes": data.get("markov_scoreable_episodes", 0),
                    "markov_anomalous_episodes": data.get("markov_anomalous_episodes", 0),
                    "markov_reason": data.get("markov_reason"),
                    "event_count": data.get("event_count", 0),
                    "random_mac": data.get("random_mac", False),
                    "client_metadata": client_cache.get(mac, {}),
                    "categories": {cat: mac_categories[mac].get(cat, 0) for cat in EVENT_CATEGORIES},
                    "total_events": mac_total.get(mac, data.get("event_count", 0)),
                    "service_account": data.get("service_account"),
                })
    finally:
        await redis_client.aclose()

    if not rows:
        raise HTTPException(status_code=404, detail=f"No data found for family '{family}' across any site.")

    rows.sort(key=lambda x: (x["if_score"] is None, x["if_score"] or 0))

    return {
        "family": family,
        "family_kind": family_kind,
        "service_account_label": sa_label,
        "service_account_member_families": sorted(sa_member_families),
        "total_count": len(rows),
        "if_outlier_count": total_if_outliers,
        "dbscan_outlier_count": total_dbscan_outliers,
        "markov_outlier_count": total_markov_outliers,
        "rows": rows,
        "category_keys": list(EVENT_CATEGORIES.keys()),
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
async def get_org_cluster_viz(wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    PCA 2D projection of all MAC feature vectors across every org site.
    Optionally scoped to a specific WLAN via ?wlan=.

    Outlier flags come from sasquatch:org_anomalies:{site}:{wlan} (written by
    score_org_wide), so a MAC is circled only when it is an outlier relative
    to the combined org-wide population of its family — not just within its
    own site. This matches the org-wide finding rollup and keeps the Org PCA
    plot consistent with what surfaces on the Org Findings tab.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        raise HTTPException(status_code=500, detail="MIST_ORG_ID or MIST_API_TOKEN not configured.")

    redis_client = _get_redis()
    keyed_features: dict[str, dict] = {}
    keyed_anomalies: dict[str, dict] = {}
    key_site: dict[str, str] = {}

    try:
        site_map = await _get_org_site_map(redis_client)
        # Fetch features and org-wide anomalies for all sites in one pipeline round trip
        site_ids_ordered = list(site_map.keys())
        pipe = redis_client.pipeline()
        for sid in site_ids_ordered:
            pipe.get(_features_redis_key(sid, wlan))
            pipe.get(_org_anomalies_redis_key(sid, wlan))
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


async def build_site_findings(site_id: str, wlan: str) -> dict:
    """Build the /sites/{id}/findings response. Pure aggregator."""
    findings = await get_findings(site_id, wlan)
    return {"site_id": site_id, "wlan": wlan, "findings": findings, "count": len(findings)}


@router.get("/sites/{site_id}/findings")
async def get_site_findings(site_id: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """Current anomaly findings from Redis for a site, optionally scoped to a WLAN.

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    redis_client = _get_redis()
    try:
        cache_key = summary_cache._site_findings_key(site_id, wlan)
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        response = await build_site_findings(site_id, wlan)
        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


async def build_site_health(site_id: str, wlan: str) -> dict:
    """Build the /sites/{id}/health response. Pure aggregator."""
    health = await get_health(site_id, wlan)
    return {"site_id": site_id, "wlan": wlan, "health": health}


@router.get("/sites/{site_id}/health")
async def get_site_health(site_id: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Per-family health scores for a site, optionally scoped to a WLAN.
    Returns {family: {health_score, components, total_events, mac_count}}.
    health_score ranges 0.0 (all failures) to 1.0 (no failures).

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    redis_client = _get_redis()
    try:
        cache_key = summary_cache._site_health_key(site_id, wlan)
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        response = await build_site_health(site_id, wlan)
        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


@router.get("/sites/{site_id}/clients")
async def get_site_clients(site_id: str):
    """
    Client list with device type breakdown for a specific site.

    The client cache is org-scoped (MAC unique across the org), so this endpoint
    loads the org cache and filters to clients whose ``last_site_id`` matches
    the requested site. A client's "site" is the most recent site Mist saw it
    at — the same MAC seen tomorrow at a different site will move to that site.
    """
    org_cache = await get_client_cache()
    if org_cache is None:
        raise HTTPException(status_code=404, detail="Client cache not found. Run /org/refresh first.")

    site_clients = {
        mac: meta
        for mac, meta in org_cache.items()
        if meta.get("last_site_id") == site_id
    }
    family_counts: Counter = Counter(v.get("family", "Unknown") for v in site_clients.values())
    return {
        "site_id": site_id,
        "total_clients": len(site_clients),
        "by_family": dict(family_counts),
        "clients": site_clients,
    }


async def build_site_events_summary(site_id: str, wlan: str) -> dict | None:
    """
    Build the /sites/{id}/events/summary response. Pure aggregator. Returns
    None when no events exist for the (site, wlan) pair so the caller can
    translate that to a 404.
    """
    events = await get_events(
        site_id=site_id,
        wlan=wlan,
    )
    if not events:
        return None

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

    # Aggregate per-family Markov stats from anomaly records. Uses the canonical
    # family rollup rules from markov_analyzer.run_markov_analysis so the Site
    # WLAN Family Insights badge lights up only when a finding would actually
    # fire — single source of truth with anomaly_detector.score's rollup:
    #   1. ratio = anomalous_macs / total_family_macs  (NOT anomalous / evaluatable)
    #   2. is_family_markov_outlier = ratio >= markov_family_outlier_ratio
    #   3. total_family_macs >= anomaly_finding_min_size
    # Also discovers virtual service-account family membership for synthetic row
    # construction below.
    family_markov: dict[str, dict] = {}
    sa_family_members: dict[str, set[str]] = defaultdict(set)
    sa_member_families_map: dict[str, set[str]] = defaultdict(set)
    try:
        anomalies_raw = await get_anomalies(site_id, wlan)
        if anomalies_raw:
            markov_family_ratio_threshold = _config_mod.get("anomaly", "markov_family_outlier_ratio")
            finding_min_size = _config_mod.get("anomaly", "anomaly_finding_min_size")
            fam_total: dict[str, int] = defaultdict(int)
            fam_evaluatable: dict[str, int] = defaultdict(int)
            fam_anomalous: dict[str, int] = defaultdict(int)
            fam_reason_counts: dict[str, Counter] = defaultdict(Counter)
            for mac_data in anomalies_raw.values():
                fam = mac_data.get("device_family", "Unknown")
                fam_total[fam] += 1
                scoreable = mac_data.get("markov_scoreable_episodes", 0)
                is_stuck = mac_data.get("is_stuck_loop", False)
                is_markov_out = mac_data.get("is_markov_outlier", False)
                if scoreable > 0 or is_stuck:
                    fam_evaluatable[fam] += 1
                if is_markov_out:
                    fam_anomalous[fam] += 1
                    reason = mac_data.get("markov_reason")
                    if reason:
                        fam_reason_counts[fam][reason] += 1
                # Discover sa family membership for synthetic row construction.
                if mac_data.get("is_service_account_record"):
                    primary_mac = mac_data.get("primary_mac")
                    if primary_mac:
                        sa_family_members[fam].add(primary_mac)
                    primary_family = mac_data.get("primary_device_family", "")
                    if primary_family:
                        sa_member_families_map[fam].add(primary_family)
            for fam, total in fam_total.items():
                anomalous = fam_anomalous.get(fam, 0)
                evaluatable = fam_evaluatable.get(fam, 0)
                ratio = anomalous / total if total > 0 else 0.0
                is_outlier = (
                    ratio >= markov_family_ratio_threshold
                    and total >= finding_min_size
                )
                reason: str | None = None
                if is_outlier:
                    counts = fam_reason_counts.get(fam, Counter())
                    repeated_n = counts.get("repeated", 0)
                    anomaly_n = counts.get("anomaly", 0)
                    if repeated_n or anomaly_n:
                        reason = "repeated" if repeated_n >= anomaly_n else "anomaly"
                family_markov[fam] = {
                    "markov_evaluatable_count": evaluatable,
                    "markov_family_anomalous_count": anomalous,
                    "markov_family_anomaly_ratio": round(ratio, 4),
                    "is_family_markov_outlier": is_outlier,
                    "markov_family_reason": reason,
                }
    except Exception:
        log.debug("Markov aggregation skipped for events/summary — anomaly data not yet available")

    # Synthesize service-account heatmap rows by summing member MAC events.
    # The same MAC appears in BOTH its primary device family row AND its sa
    # family row — by design, dual-family visibility.
    if sa_family_members:
        for sa_family, member_macs in sa_family_members.items():
            sa_counts: Counter = Counter()
            sa_total = 0
            for event in events:
                mac = (event.get("mac") or "").replace(":", "").lower()
                if mac and mac in member_macs:
                    sa_counts[event.get("event_category", "OTHER")] += 1
                    sa_total += 1
            if sa_total == 0:
                continue
            summary[sa_family] = sa_counts
            family_totals[sa_family] = sa_total
            family_macs[sa_family] = set(member_macs)

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

    family_metadata = {
        fam: {
            "family_kind": "service_account" if fam.endswith(".service_account") else "device_family",
            "service_account_label": fam[: -len(".service_account")] if fam.endswith(".service_account") else "",
            "service_account_member_families": sorted(sa_member_families_map.get(fam, set())),
        }
        for fam in result.keys()
    }

    return {
        "site_id": site_id,
        "wlan": wlan,
        "total_events": len(events),
        "families": result,
        "family_client_counts": {fam: len(macs) for fam, macs in family_macs.items()},
        "family_markov": family_markov,
        "family_metadata": family_metadata,
        "categories": list(EVENT_CATEGORIES.keys()),
    }


@router.get("/sites/{site_id}/events/summary")
async def get_events_summary(site_id: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Event category counts per device family — used for heatmap in SiteOverview.
    Optionally scoped to a specific WLAN via ?wlan=.

    Cache-first: pre-computed by the detection pipeline tail. On miss, the
    response is built live and the cache is opportunistically populated.
    """
    redis_client = _get_redis()
    try:
        cache_key = summary_cache._site_events_summary_key(site_id, wlan)
        cached = await summary_cache.cache_get(redis_client, cache_key)
        if cached is not None:
            return cached

        response = await build_site_events_summary(site_id, wlan)
        if response is None:
            raise HTTPException(status_code=404, detail="No events found for site.")

        await summary_cache.cache_set(redis_client, cache_key, response)
        return response
    finally:
        await redis_client.aclose()


@router.get("/sites/{site_id}/families/{family}/if-outliers")
async def get_family_if_outliers(site_id: str, family: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    MACs within a device family that triggered an Isolation Forest deviation.
    Used by the Family Drilldown view. Optionally scoped to a WLAN.

    Service-account families ("{label}.service_account") are handled via a
    separate path: rows are derived from sa anomaly records (composite "{mac}#sa"
    keys) and each row carries `primary_device_family` so the GUI can show the
    mix of underlying device types sharing the username.
    """
    anomalies = await get_anomalies(site_id, wlan)
    if not anomalies:
        raise HTTPException(status_code=404, detail="No anomaly data found. Run detection first.")

    client_cache = await get_client_cache() or {}

    is_sa_family = family.endswith(".service_account")
    family_kind = "service_account" if is_sa_family else "device_family"
    sa_label = family[: -len(".service_account")] if is_sa_family else ""
    sa_member_families: set[str] = set()

    if is_sa_family:
        # sa records use composite keys; iterate over all and pick those whose
        # device_family matches the sa family name. Each row's `mac` is the
        # primary (real) MAC for drilldown navigation.
        family_keys = [
            ck for ck, data in anomalies.items()
            if data.get("device_family") == family
            and data.get("is_service_account_record")
        ]
        if not family_keys:
            raise HTTPException(status_code=404, detail=f"No clients found for family '{family}'.")

        all_clients = []
        for ck in family_keys:
            data = anomalies[ck]
            primary_mac = data.get("primary_mac") or ck
            primary_device_family = (
                data.get("primary_device_family")
                or client_cache.get(primary_mac, {}).get("family", "Unknown")
            )
            if primary_device_family:
                sa_member_families.add(primary_device_family)
            all_clients.append({
                "mac": primary_mac,
                "if_score": data.get("if_score"),
                "is_if_outlier": data.get("is_if_outlier", False),
                "is_dbscan_outlier": data.get("is_dbscan_outlier", False),
                "is_markov_outlier": data.get("is_markov_outlier", False),
                "markov_episode_anomaly_ratio": data.get("markov_episode_anomaly_ratio"),
                "markov_reason": data.get("markov_reason"),
                "event_count": data.get("event_count", 0),
                "random_mac": data.get("random_mac", False),
                "client_metadata": client_cache.get(primary_mac, {}),
                "primary_device_family": primary_device_family,
                "last_username": data.get("last_username", ""),
                "is_service_account_record": True,
            })

        all_clients.sort(key=lambda x: (x["if_score"] is None, x["if_score"] or 0))
        if_outlier_count = sum(1 for c in all_clients if c["is_if_outlier"])

        centroid_dist_score = next(
            (anomalies[k].get("family_centroid_dist_score")
             for k in family_keys
             if anomalies[k].get("family_centroid_dist_score") is not None),
            None,
        )
        findings = await get_findings(site_id, wlan)
        family_finding = next((f for f in findings if f.get("device_family") == family), None)
        family_top_features = family_finding.get("top_features", []) if family_finding else []

        return {
            "site_id": site_id,
            "family": family,
            "family_kind": family_kind,
            "service_account_label": sa_label,
            "service_account_member_families": sorted(sa_member_families),
            "wlan": wlan,
            "total_family_count": len(family_keys),
            "if_outlier_count": if_outlier_count,
            "outliers": all_clients,
            "centroid_dist_score": centroid_dist_score,
            "top_features": family_top_features,
        }

    family_macs = [
        mac for mac, data in anomalies.items()
        if data.get("device_family") == family
        and not data.get("is_service_account_record")
    ]
    if not family_macs:
        raise HTTPException(status_code=404, detail=f"No clients found for family '{family}'.")

    all_clients = [
        {
            "mac": mac,
            "if_score": anomalies[mac].get("if_score"),
            "is_if_outlier": anomalies[mac].get("is_if_outlier", False),
            "is_dbscan_outlier": anomalies[mac].get("is_dbscan_outlier", False),
            "is_markov_outlier": anomalies[mac].get("is_markov_outlier", False),
            "markov_episode_anomaly_ratio": anomalies[mac].get("markov_episode_anomaly_ratio"),
            "markov_reason": anomalies[mac].get("markov_reason"),
            "event_count": anomalies[mac].get("event_count", 0),
            "random_mac": anomalies[mac].get("random_mac", False),
            "client_metadata": client_cache.get(mac, {}),
            "service_account": anomalies[mac].get("service_account"),
        }
        for mac in family_macs
    ]

    all_clients.sort(key=lambda x: (x["if_score"] is None, x["if_score"] or 0))
    if_outlier_count = sum(1 for c in all_clients if c["is_if_outlier"])

    # Pull centroid_dist_score from anomaly records (available for all families where
    # centroid distance ran, regardless of whether a finding was generated).
    # Fall back to the stored finding for top_features.
    centroid_dist_score = next(
        (anomalies[m].get("family_centroid_dist_score")
         for m in family_macs
         if anomalies[m].get("family_centroid_dist_score") is not None),
        None,
    )
    findings = await get_findings(site_id, wlan)
    family_finding = next((f for f in findings if f.get("device_family") == family), None)
    family_top_features = family_finding.get("top_features", []) if family_finding else []

    return {
        "site_id": site_id,
        "family": family,
        "family_kind": family_kind,
        "service_account_label": sa_label,
        "service_account_member_families": [],
        "wlan": wlan,
        "total_family_count": len(family_macs),
        "if_outlier_count": if_outlier_count,
        "outliers": all_clients,
        "centroid_dist_score": centroid_dist_score,
        "top_features": family_top_features,
    }


@router.post("/sites/{site_id}/families/{family}/tshoot")
async def trigger_family_tshoot(
    site_id: str,
    family: str,
    wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required."),
):
    """
    Manually trigger a Mist client TSHOOT for the worst-health MACs in a device family.

    Reads worst_health_macs from the current finding for this family (if present)
    and dispatches concurrent TSHOOT calls to the Mist site-level troubleshoot API.
    The staleness check is skipped for manual triggers — operator intent is assumed.

    Returns the TSHOOT results for each MAC immediately (synchronous response).
    Requires MIST_API_TOKEN to be configured; returns 503 if not.
    """
    if not os.getenv("MIST_API_TOKEN", ""):
        raise HTTPException(status_code=503, detail="MIST_API_TOKEN not configured.")

    results = await run_family_tshoot(site_id=site_id, family=family, wlan=wlan)
    if results is None or (
        not results
        and not await get_findings(site_id, wlan)
    ):
        raise HTTPException(
            status_code=404,
            detail=f"No finding found for family '{family}' at site '{site_id}' on WLAN '{wlan}'.",
        )

    return {
        "site_id": site_id,
        "family": family,
        "wlan": wlan,
        "mac_count": len(results),
        "tshoot": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/sites/{site_id}/families/{family}/event-counts")
async def get_family_event_counts(site_id: str, family: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Per-MAC event category counts for all clients in a device family.
    Used by the Family Drilldown Event Counts view. Optionally scoped to a WLAN.

    Service-account families select MACs by sa membership (from anomaly records)
    rather than by event device_family — events are tagged with the underlying
    primary family, not the sa family.
    """
    events = await get_events(
        site_id=site_id,
        wlan=wlan,
    )
    if not events:
        raise HTTPException(status_code=404, detail="No events found for site.")

    client_cache = await get_client_cache() or {}

    is_sa_family = family.endswith(".service_account")
    sa_member_macs: set[str] = set()
    if is_sa_family:
        anomalies = await get_anomalies(site_id, wlan)
        for ck, data in (anomalies or {}).items():
            if data.get("device_family") != family:
                continue
            if not data.get("is_service_account_record"):
                continue
            primary_mac = data.get("primary_mac") or ck
            sa_member_macs.add(primary_mac)
        if not sa_member_macs:
            raise HTTPException(status_code=404, detail=f"No clients found for family '{family}'.")

    mac_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    mac_total: dict[str, int] = defaultdict(int)
    family_macs: set[str] = set()

    for event in events:
        mac = (event.get("mac") or "").replace(":", "").lower()
        if not mac:
            continue
        if is_sa_family:
            if mac not in sa_member_macs:
                continue
        else:
            if event.get("device_family") != family:
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
async def get_mac_anomaly(site_id: str, mac: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """
    Full event timeline + anomaly scores for one MAC.
    Used by MAC Drill-down view. Optionally scoped to a WLAN.
    """
    mac_normalized = mac.replace(":", "").lower()

    # Fallback chain for per-MAC anomaly scores:
    #   1. Per-site anomalies (written by score() in Phase 4 of the org pipeline)
    #   2. Org anomalies (written by score_org_wide() in Phase 3 — explicitly persisted
    #      per-site keyed by MAC for exactly this drilldown use case)
    # The per-site key is absent for many (site, wlan) combinations in practice
    # (e.g. when Phase 4 was skipped or the WLAN had too few peers to run per-family
    # IF), so falling back to the org-wide record lets drilldown work whenever ANY
    # scoring pass covered this MAC. If neither pass includes it, we still return
    # a useful payload — events + metadata with empty scores — rather than 404'ing.
    anomalies = await get_anomalies(site_id, wlan)
    mac_scores = anomalies.get(mac_normalized)
    if mac_scores is None:
        raw_org_anomalies = await _redis_get(_org_anomalies_redis_key(site_id, wlan))
        if raw_org_anomalies:
            org_anomalies = json.loads(raw_org_anomalies)
            mac_scores = org_anomalies.get(mac_normalized)

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

    client_cache = await get_client_cache() or {}
    client_meta = client_cache.get(mac_normalized, {})

    # Only 404 if we have nothing to show — no scores, no features, no events, and
    # no client cache entry. That's the true "unknown MAC" case.
    if mac_scores is None and not mac_features and not mac_events and not client_meta:
        raise HTTPException(status_code=404, detail=f"No data for MAC {mac}")

    if mac_scores is None:
        mac_scores = {}

    mac_vec = mac_features.get("vector", {})

    # Per-MAC health: aggregate score, per-service health, and any service alarms.
    # Computed on demand from the MAC's feature vector — no separate Redis key needed.
    from ..health_scorer import (
        _mac_health_score,
        mac_service_health,
        mac_service_alarms,
    )
    if mac_vec:
        mac_health_score, mac_health_components = _mac_health_score(mac_vec)
        mac_health_score = round(mac_health_score, 4)
        mac_service_health_out = mac_service_health(mac_vec)
        mac_service_alarms_out = mac_service_alarms(mac_vec)
    else:
        mac_health_score = None
        mac_health_components = {}
        mac_service_health_out = {}
        mac_service_alarms_out = []

    return {
        "mac": mac_normalized,
        "site_id": site_id,
        "wlan": wlan,
        "client_metadata": client_meta,
        "anomaly_scores": mac_scores,
        "feature_vector": mac_features.get("vector", {}),
        "health_score": mac_health_score,
        "health_components": mac_health_components,
        "service_health": mac_service_health_out,
        "service_alarms": mac_service_alarms_out,
        "event_count": len(mac_events),
        "events": mac_events,
    }


@router.post("/sites/{site_id}/markov-baseline")
async def trigger_markov_baseline(site_id: str):
    """
    Manually trigger a Markov Chain baseline rebuild for all WLANs at a site.
    Reads the last 24hr of events from Redis and rebuilds the transition matrices.
    If no events are present in Redis, returns with zero counts and no baseline is written —
    run a Full Discovery first to populate events, then call this endpoint.
    """
    try:
        event_type_index = await get_event_type_index(site_id)
        wlans = await get_wlans(site_id=site_id)
        if not wlans:
            return {"site_id": site_id, "status": "no_wlans", "results": [],
                    "timestamp": datetime.now(timezone.utc).isoformat()}
        results = []
        for wlan in wlans:
            result = await build_markov_baseline(site_id, wlan, event_type_index)
            results.append({"wlan": wlan, **result})
        return {
            "site_id": site_id,
            "status": "ok",
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        log.exception(f"Markov baseline rebuild failed for site {site_id}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/sites/{site_id}/flush")
async def flush_site_redis(site_id: str):
    """
    Delete all sasquatch state for a site (SQLite events + per-site Redis keys).
    The org-scoped client cache is preserved — use POST /org/flush to clear it.
    """
    from .. import db as _db

    client = _get_redis()
    deleted = 0
    try:
        # Delete SQLite events for this site. Clients are org-scoped now —
        # the per-site flush leaves them in place; use POST /org/flush to wipe
        # the org-wide client cache.
        deleted += await _db.delete_events_for_site(site_id)
        # Delete remaining Redis keys (unknown_event_types, progress)
        static_keys = [
            f"sasquatch:unknown_event_types:{site_id}",
            f"sasquatch:progress:{site_id}",
        ]
        deleted += await client.delete(*static_keys)

        # Scan for per-WLAN feature/anomaly/finding keys.
        # markov_baseline keys are intentionally excluded — they are expensive to rebuild
        # and have their own 48hr TTL. Preserving them avoids silent Markov scoring gaps
        # after a flush-and-rerun cycle.
        pattern_keys: list[str] = []
        for prefix in ["sasquatch:features:", "sasquatch:anomalies:", "sasquatch:findings:",
                       "sasquatch:health:", "sasquatch:org_anomalies:"]:
            scan_cursor = 0
            while True:
                scan_cursor, found = await client.scan(scan_cursor, match=f"{prefix}{site_id}:*", count=100)
                pattern_keys.extend(found)
                if scan_cursor == 0:
                    break
        if pattern_keys:
            deleted += await client.delete(*pattern_keys)

        # Drop site-scoped + org-level dashboard summary cache entries —
        # the org views aggregate this site's contribution.
        deleted += await summary_cache.flush_site_summary_cache(client, site_id)

    finally:
        await client.aclose()

    log.info(f"Flushed {deleted} Redis keys for site {site_id}")
    return {
        "site_id": site_id,
        "status": "ok",
        "entries_removed": deleted,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/unlock")
async def unlock_global_operation():
    """Force-release the global operation lock."""
    client = _get_redis()
    try:
        deleted = await client.delete(_GLOBAL_LOCK_KEY)
    finally:
        await client.aclose()
    return {
        "status": "ok" if deleted else "no_lock",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/sites/{site_id}/cluster-viz")
async def get_cluster_viz(site_id: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
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
            "is_if_outlier": anom.get("is_if_outlier", False),
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
async def get_site_status(site_id: str, wlan: str = Query(..., description="WLAN (SSID) name to scope results to. Required.")):
    """Last run metadata: event count, finding count, key TTLs."""
    from .. import db as _db

    client = _get_redis()
    try:
        features_ttl = await client.ttl(_features_redis_key(site_id, wlan))
        anomalies_ttl = await client.ttl(_anomalies_redis_key(site_id, wlan))
        findings_ttl = await client.ttl(_findings_redis_key(site_id, wlan))

        raw_findings = await client.get(_findings_redis_key(site_id, wlan))
        finding_count = len(json.loads(raw_findings)) if raw_findings else 0

        unknown_types = await client.smembers(f"sasquatch:unknown_event_types:{site_id}")
    finally:
        await client.aclose()

    # Event count from SQLite (lightweight count query — no full JSON load)
    event_count = await _db.get_event_count(site_id=site_id, wlan=wlan)
    clients_present = await _db.has_org_client_cache(MIST_ORG_ID) if MIST_ORG_ID else False

    return {
        "site_id": site_id,
        "wlan": wlan,
        "event_count": event_count,
        "finding_count": finding_count,
        "redis_ttls": {
            "clients": 1 if clients_present else -2,  # 1 = exists, -2 = missing (compat)
            "features": features_ttl,
            "anomalies": anomalies_ttl,
            "findings": findings_ttl,
        },
        "unknown_event_types": list(unknown_types),
    }

"""
alert_tracker.py — Persistent alert session history.

Tracks when device families enter and exit the dual-gate alert state
(is_family_outlier + health_score < threshold). Each contiguous period
where a family passes the gate at a given site is one "session".

Called from webhook_dispatcher.evaluate_and_dispatch() after qualifying
findings are computed — runs regardless of whether ANOMALY_WEBHOOK_URL
is configured, so history is always recorded.

Redis keys:
  sasquatch:alert_active:{site_id}:{wlan_key}
    Hash, no TTL — lifecycle managed explicitly.
    field = family name
    value = JSON {"first_seen": float, "last_seen": float}
    Entries are removed when the session resolves.

  sasquatch:alert_sessions
    Sorted set, no TTL.
    score  = first_seen unix timestamp
    member = session_key: "{site_id}||{wlan_key}||{family}||{first_seen_int}"
    Entries older than PRUNE_AFTER_DAYS are pruned on each write cycle.

  sasquatch:alert_session:{session_key}
    JSON string, SESSION_TTL expiry.
    {site_id, family, wlan, first_seen, last_seen, resolved_at, status}
"""

import json
import logging
import os
import time

import redis.asyncio as aioredis

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

SESSION_TTL = 8 * 24 * 3600      # 8 days — buffer beyond the 7-day display window
PRUNE_AFTER_DAYS = 8
SESSIONS_ZSET_KEY = "sasquatch:alert_sessions"


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _active_key(site_id: str, wlan_key: str) -> str:
    return f"sasquatch:alert_active:{site_id}:{wlan_key}"


def _session_data_key(session_key: str) -> str:
    return f"sasquatch:alert_session:{session_key}"


def _make_session_key(site_id: str, wlan_key: str, family: str, first_seen_int: int) -> str:
    # Double-pipe separator — family names and wlan keys don't contain "||"
    return f"{site_id}||{wlan_key}||{family}||{first_seen_int}"


# ---------------------------------------------------------------------------
# Write path — called after each successful detection cycle
# ---------------------------------------------------------------------------

def _snapshot(finding: dict) -> dict:
    """Extract the fields worth storing per detection cycle."""
    return {
        "severity":          finding.get("severity"),
        "outlier_ratio":     finding.get("outlier_ratio"),
        "affected_mac_count": finding.get("affected_mac_count"),
        "total_mac_count":   finding.get("total_mac_count"),
        "health_score":      finding.get("health_score"),
        "health_components": finding.get("health_components") or {},
        "probable_pattern":  finding.get("probable_pattern"),
        "top_features":      (finding.get("top_features") or [])[:3],
    }


async def record_cycle(
    site_id: str,
    wlan: str,
    active_findings: dict[str, dict],
    redis_client=None,
) -> None:
    """
    Update alert session state for one site + wlan scope.

    active_findings: dict mapping device family name → qualifying finding dict
    for families that currently pass the dual alert gate. Pass an empty dict
    if no families are currently in alert state.

    For each family in active_findings:
      - If already active: extend last_seen and refresh the finding snapshot.
      - If new: open a new session.

    For each family previously active but absent from active_findings:
      - Mark the session resolved (preserves last snapshot for display).

    This function never raises — failures are logged and swallowed so a
    tracker error never kills the scheduler job.
    """
    from .event_collector import sanitize_wlan_key

    wlan_key = sanitize_wlan_key(wlan)
    active_key = _active_key(site_id, wlan_key)
    now = time.time()
    prune_before = now - PRUNE_AFTER_DAYS * 86400

    own_redis = redis_client is None
    if own_redis:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    try:
        raw_active = await redis_client.hgetall(active_key)
        current_active: dict[str, dict] = {
            k: json.loads(v) for k, v in raw_active.items()
        }

        pipe = redis_client.pipeline()

        for family, finding in active_findings.items():
            snap = _snapshot(finding)
            if family in current_active:
                # Continuing session — extend last_seen, refresh snapshot
                session = current_active[family]
                session["last_seen"] = now
                pipe.hset(active_key, family, json.dumps(session))
                sk = _make_session_key(site_id, wlan_key, family, int(session["first_seen"]))
                pipe.set(_session_data_key(sk), json.dumps({
                    "site_id": site_id,
                    "family": family,
                    "wlan": wlan,
                    "first_seen": session["first_seen"],
                    "last_seen": now,
                    "resolved_at": None,
                    "status": "active",
                    **snap,
                }), ex=SESSION_TTL)
            else:
                # New session
                sk = _make_session_key(site_id, wlan_key, family, int(now))
                pipe.hset(active_key, family, json.dumps({
                    "first_seen": now,
                    "last_seen": now,
                }))
                pipe.zadd(SESSIONS_ZSET_KEY, {sk: now})
                pipe.set(_session_data_key(sk), json.dumps({
                    "site_id": site_id,
                    "family": family,
                    "wlan": wlan,
                    "first_seen": now,
                    "last_seen": now,
                    "resolved_at": None,
                    "status": "active",
                    **snap,
                }), ex=SESSION_TTL)

        # For resolving sessions: read existing blobs first so we can preserve snapshots.
        resolving_families = [f for f in current_active if f not in active_findings]
        resolving_blobs: dict[str, dict] = {}
        if resolving_families:
            read_pipe = redis_client.pipeline()
            for family in resolving_families:
                session = current_active[family]
                sk = _make_session_key(site_id, wlan_key, family, int(session["first_seen"]))
                read_pipe.get(_session_data_key(sk))
            existing_raws = await read_pipe.execute()
            for family, raw in zip(resolving_families, existing_raws):
                if raw:
                    try:
                        resolving_blobs[family] = json.loads(raw)
                    except json.JSONDecodeError:
                        resolving_blobs[family] = {}

        for family in resolving_families:
            session = current_active[family]
            sk = _make_session_key(site_id, wlan_key, family, int(session["first_seen"]))
            existing = resolving_blobs.get(family, {})
            pipe.hdel(active_key, family)
            pipe.set(_session_data_key(sk), json.dumps({
                **existing,                        # preserves snapshot fields from last active cycle
                "site_id": site_id,
                "family": family,
                "wlan": wlan,
                "first_seen": session["first_seen"],
                "last_seen": session["last_seen"],
                "resolved_at": now,
                "status": "resolved",
            }), ex=SESSION_TTL)

        # Prune the sorted set — keep sorted set tidy even if session data TTLs handle cleanup
        pipe.zremrangebyscore(SESSIONS_ZSET_KEY, "-inf", prune_before)

        await pipe.execute()
        log.debug(
            "alert_tracker: site=%s wlan=%s active=%d previously_active=%d",
            site_id, wlan, len(active_findings), len(current_active),
        )

    except Exception:
        log.exception(
            "alert_tracker.record_cycle failed for site=%s wlan=%s (non-fatal)",
            site_id, wlan,
        )
    finally:
        if own_redis:
            await redis_client.aclose()


# ---------------------------------------------------------------------------
# Read path — called by the history API endpoint
# ---------------------------------------------------------------------------

async def get_recent_sessions(
    days: int = 7,
    wlan: str = "",
    redis_client=None,
) -> list[dict]:
    """
    Return all alert sessions (active and resolved) from the past `days` days.

    If wlan is provided, only sessions for that exact WLAN are returned.
    Results are sorted oldest-first (ascending first_seen).
    """
    from .event_collector import sanitize_wlan_key

    wlan_key = sanitize_wlan_key(wlan)
    since = time.time() - days * 86400

    own_redis = redis_client is None
    if own_redis:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    try:
        session_keys = await redis_client.zrangebyscore(SESSIONS_ZSET_KEY, since, "+inf")
        if not session_keys:
            return []

        # Filter by wlan scope when a specific WLAN is requested
        if wlan_key:
            session_keys = [k for k in session_keys if k.startswith(f"{k.split('||')[0]}||{wlan_key}||")]

        pipe = redis_client.pipeline()
        for sk in session_keys:
            pipe.get(_session_data_key(sk))
        raw_results = await pipe.execute()

        sessions = []
        for raw in raw_results:
            if raw:
                try:
                    sessions.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass

        return sorted(sessions, key=lambda s: s.get("first_seen", 0))

    except Exception:
        log.exception("alert_tracker.get_recent_sessions failed")
        return []
    finally:
        if own_redis:
            await redis_client.aclose()

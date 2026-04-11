"""
summary_cache.py — pre-computed dashboard aggregates.

The hourly poll → detect cycle is the only thing that mutates the data these
endpoints read from. Between cycles, every request to /org/summary,
/org/alerts, /org/findings, /org/family-insights, /sites/{id}/findings,
/sites/{id}/health, and /sites/{id}/events/summary recomputes the same
aggregate. This module materializes those aggregates into Redis at the tail of
the detection pipeline so request handlers become a single Redis GET.

Drilldown endpoints (per-MAC, per-family) intentionally bypass this cache —
they are infrequent and need fresh per-row state.

Cache invalidation:
  - Pipeline tail (writer): ``write_*`` functions overwrite the keys atomically
    after detection completes, inside the global mutex. Same key, new value.
  - /org/flush + /sites/{id}/flush: ``flush_org_summary_cache()`` /
    ``flush_site_summary_cache(site_id)`` DEL the affected keys so a stale
    cache cannot outlive its underlying findings/health data.
  - 2-hour safety TTL: hourly cycle is the upper bound on freshness; the TTL
    is just a backstop in case a writer is skipped (e.g. detection failure)
    so callers eventually fall through to the live recompute path.

Anomaly-config writes (POST /anomaly-config) deliberately do NOT invalidate
the cache. Threshold changes only take effect on the next detection cycle —
the GUI surfaces this expectation to the user.
"""

import json
import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis

from .event_collector import sanitize_wlan_key

log = logging.getLogger(__name__)

# 2 hours — comfortably longer than the 1-hour detection cycle so a single
# missed cycle still serves cached data, but short enough that a stuck writer
# eventually falls through to the live path.
SUMMARY_CACHE_TTL = 7200

_PREFIX = "sasquatch:summary"


def _org_summary_key(wlan: str) -> str:
    return f"{_PREFIX}:org_summary:{sanitize_wlan_key(wlan)}"


def _org_findings_key(wlan: str) -> str:
    return f"{_PREFIX}:org_findings:{sanitize_wlan_key(wlan)}"


def _org_alerts_key(wlan: str) -> str:
    return f"{_PREFIX}:org_alerts:{sanitize_wlan_key(wlan)}"


def _org_alerts_full_key() -> str:
    # Cross-WLAN aggregation — single key, no wlan dimension.
    return f"{_PREFIX}:org_alerts_full"


def _org_family_insights_key(wlan: str) -> str:
    return f"{_PREFIX}:org_family_insights:{sanitize_wlan_key(wlan)}"


def _site_findings_key(site_id: str, wlan: str) -> str:
    return f"{_PREFIX}:site_findings:{site_id}:{sanitize_wlan_key(wlan)}"


def _site_health_key(site_id: str, wlan: str) -> str:
    return f"{_PREFIX}:site_health:{site_id}:{sanitize_wlan_key(wlan)}"


def _site_events_summary_key(site_id: str, wlan: str) -> str:
    return f"{_PREFIX}:site_events_summary:{site_id}:{sanitize_wlan_key(wlan)}"


def _stamp(payload: dict) -> dict:
    """Tag a cache payload with the time it was built."""
    payload["_built_at"] = datetime.now(timezone.utc).isoformat()
    return payload


async def cache_get(redis_client: aioredis.Redis, key: str) -> dict | None:
    """Read a cached aggregate. Returns None on miss or decode error."""
    try:
        raw = await redis_client.get(key)
    except Exception:
        log.exception("summary_cache get failed for %s", key)
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        log.warning("summary_cache decode failed for %s — treating as miss", key)
        return None


async def cache_set(redis_client: aioredis.Redis, key: str, payload: dict) -> None:
    """Write a cached aggregate with the standard TTL and built-at stamp."""
    try:
        await redis_client.set(key, json.dumps(_stamp(payload)), ex=SUMMARY_CACHE_TTL)
    except Exception:
        log.exception("summary_cache set failed for %s", key)


async def _delete_pattern(redis_client: aioredis.Redis, pattern: str) -> int:
    """SCAN+DEL helper for wildcard invalidation."""
    deleted = 0
    cursor = 0
    while True:
        cursor, found = await redis_client.scan(cursor, match=pattern, count=100)
        if found:
            deleted += await redis_client.delete(*found)
        if cursor == 0:
            break
    return deleted


async def flush_org_summary_cache(redis_client: aioredis.Redis) -> int:
    """Delete every summary cache key — used by /org/flush."""
    return await _delete_pattern(redis_client, f"{_PREFIX}:*")


async def flush_site_summary_cache(redis_client: aioredis.Redis, site_id: str) -> int:
    """Delete site-scoped summary cache keys for one site, plus org-level keys.

    Org-level aggregates (org_summary, org_alerts, org_alerts_full,
    org_family_insights) include this site's contribution, so a per-site flush
    must invalidate them too — otherwise the org views show stale per-site
    data until the next detection cycle.
    """
    deleted = 0
    deleted += await _delete_pattern(redis_client, f"{_PREFIX}:site_findings:{site_id}:*")
    deleted += await _delete_pattern(redis_client, f"{_PREFIX}:site_health:{site_id}:*")
    deleted += await _delete_pattern(redis_client, f"{_PREFIX}:site_events_summary:{site_id}:*")
    deleted += await _delete_pattern(redis_client, f"{_PREFIX}:org_summary:*")
    deleted += await _delete_pattern(redis_client, f"{_PREFIX}:org_alerts:*")
    deleted += await _delete_pattern(redis_client, f"{_PREFIX}:org_alerts_full")
    deleted += await _delete_pattern(redis_client, f"{_PREFIX}:org_family_insights:*")
    return deleted

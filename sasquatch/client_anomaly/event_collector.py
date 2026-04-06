"""
event_collector.py — Pull client events, enrich with device metadata, store in Redis.

Events are stored in per-site Redis sorted sets (sasquatch:events:{site_id}) scored by
Unix timestamp. Each site has its own set. Entries survive for 7 days (EVENTS_TTL);
stale entries are purged on each write via ZREMRANGEBYSCORE.

A companion set sasquatch:wlans:{site_id} tracks unique SSIDs seen per site for O(1)
WLAN enumeration without scanning event data.

Scheduled runs fetch only the last hour and append to the rolling dataset.
A full 24hr backfill is only performed when explicitly requested via the API.
"""

import json
import logging
import os
import re
import time
from typing import Optional

import httpx
import redis.asyncio as aioredis

from .client_cache import get_client_cache

log = logging.getLogger(__name__)

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Events are kept for 7 days in the global sorted set.
EVENTS_TTL = 7 * 24 * 3600
EVENT_TYPE_INDEX_TTL = 7 * 24 * 3600  # 7 days

# DHCPv6 failure events are excluded from analysis — they are frequent noise on
# dual-stack networks and do not correlate with actionable client connectivity issues.
IGNORED_EVENT_TYPES: frozenset[str] = frozenset({
    "MARVIS_EVENT_CLIENT_DHCPV6_NAK",
    "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
})

# Known Mist client event types — used to define the ML feature vector dimensions.
# Fetched live from /api/v1/const/client_events at startup and cached in Redis,
# but this list serves as a safe fallback.
MIST_CLIENT_EVENT_TYPES = [
    # DHCP
    "CLIENT_IP_ASSIGNED",
    "CLIENT_IPV6_ASSIGNED",
    "MARVIS_EVENT_CLIENT_DHCP_NAK",
    "MARVIS_EVENT_CLIENT_DHCP_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCP_STUCK",
    "MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM",
    # DNS
    "CLIENT_DNS_OK",
    "MARVIS_DNS_FAILURE",
    # Initial auth / association
    "CLIENT_AUTHENTICATED",
    "CLIENT_AUTH_ASSOCIATION",
    "CLIENT_AUTH_ASSOCIATION_11R",
    "CLIENT_AUTH_ASSOCIATION_OKC",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_DENIED",
    "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
    "MARVIS_EVENT_SAE_AUTH_FAILURE",
    "SA_QUERY_TIMEOUT",
    "CLIENT_ASSOCIATION",
    "CLIENT_ASSOCIATION_FAILURE",
    # Roam / reassociation (success)
    "CLIENT_AUTH_REASSOCIATION",
    "CLIENT_AUTH_REASSOCIATION_11R",
    "CLIENT_AUTH_REASSOCIATION_OKC",
    "CLIENT_REASSOCIATION",
    "CLIENT_REASSOCIATION_PMKC",
    "CLIENT_ASSOCIATION_PMKC",
    # Roam / reassociation (failure)
    "MARVIS_EVENT_CLIENT_FBT_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",
    "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
    "CLIENT_REASSOCIATION_FAILURE",
    # Disassociation / deauth
    "CLIENT_DEASSOCIATION",
    "CLIENT_DEAUTHENTICATION",
    "CLIENT_DEAUTHENTICATED",
    "MARVIS_EVENT_STA_LEAVING",
    # ARP / gateway
    "CLIENT_GW_ARP_OK",
    "CLIENT_GW_ARP_FAILURE",
    "CLIENT_ARP_FAILURE",
    "CLIENT_EXCESSIVE_ARPING_GW",
    # Captive portal
    "MARVIS_EVENT_WXLAN_CAPTIVE_PORT_FLOW_REDIRECT",
    "HTTP_REDIR_PROCESSED",
    "MARVIS_EVENT_CAPTIVE_PORTAL_AUTHORIZED",
    "MARVIS_EVENT_CLIENT_WXLAN_POLICY_LOOKUP_FAILURE",
    # Security
    "DEFAULT_GATEWAY_SPOOFING_DETECTED",
    "MARVIS_EVENT_CLIENT_STATIC_IP_BLOCKED",
    # Collaboration
    "CLIENT_JOINED_CALL",
    "CLIENT_LEFT_CALL",
    "CLIENT_DISCONNECTED_FROM_CALL",
    "HIGH_CPU_OBSERVED",
    # Other
    "RADIUS_DAS_NOTIFY",
]

# Category buckets — used only for post-hoc explainer and GUI charts, NOT ML input.
EVENT_CATEGORIES: dict[str, list[str]] = {
    "DHCP_SUCCESS": ["CLIENT_IP_ASSIGNED", "CLIENT_IPV6_ASSIGNED"],
    "DHCP_FAILURE": [
        "MARVIS_EVENT_CLIENT_DHCP_NAK",
        "MARVIS_EVENT_CLIENT_DHCP_FAILURE",
        "MARVIS_EVENT_CLIENT_DHCP_STUCK",
        "MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM",
    ],
    "DNS_SUCCESS": ["CLIENT_DNS_OK"],
    "DNS_FAILURE": ["MARVIS_DNS_FAILURE"],
    "AUTH_SUCCESS": [
        "CLIENT_AUTHENTICATED",
        "CLIENT_AUTH_ASSOCIATION",
        "CLIENT_AUTH_ASSOCIATION_11R",
        "CLIENT_AUTH_ASSOCIATION_OKC",
    ],
    "AUTH_FAILURE": [
        "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
        "MARVIS_EVENT_CLIENT_AUTH_DENIED",
        "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
        "MARVIS_EVENT_SAE_AUTH_FAILURE",
        "SA_QUERY_TIMEOUT",
    ],
    "ROAM_SUCCESS": [
        "CLIENT_AUTH_REASSOCIATION",
        "CLIENT_AUTH_REASSOCIATION_11R",
        "CLIENT_AUTH_REASSOCIATION_OKC",
        "CLIENT_REASSOCIATION",
        "CLIENT_REASSOCIATION_PMKC",
        "CLIENT_ASSOCIATION_PMKC",
    ],
    "ROAM_FAILURE": [
        "MARVIS_EVENT_CLIENT_FBT_FAILURE",
        "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
        "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",
        "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
        "CLIENT_REASSOCIATION_FAILURE",
    ],
    "DISASSOC": [
        "CLIENT_DEASSOCIATION",
        "CLIENT_DEAUTHENTICATION",
        "CLIENT_DEAUTHENTICATED",
        "MARVIS_EVENT_STA_LEAVING",
    ],
    "ARP_SUCCESS": [
        "CLIENT_GW_ARP_OK",
    ],
    "ARP_FAILURE": [
        "CLIENT_GW_ARP_FAILURE",
        "CLIENT_ARP_FAILURE",
        "CLIENT_EXCESSIVE_ARPING_GW",
    ],
    "CAPTIVE_PORTAL": [
        "MARVIS_EVENT_WXLAN_CAPTIVE_PORT_FLOW_REDIRECT",
        "HTTP_REDIR_PROCESSED",
        "MARVIS_EVENT_CAPTIVE_PORTAL_AUTHORIZED",
        "MARVIS_EVENT_CLIENT_WXLAN_POLICY_LOOKUP_FAILURE",
    ],
    "SECURITY": [
        "DEFAULT_GATEWAY_SPOOFING_DETECTED",
        "MARVIS_EVENT_CLIENT_STATIC_IP_BLOCKED",
    ],
    "COLLABORATION": [
        "CLIENT_JOINED_CALL",
        "CLIENT_LEFT_CALL",
        "CLIENT_DISCONNECTED_FROM_CALL",
        "HIGH_CPU_OBSERVED",
    ],
    "OTHER": ["RADIUS_DAS_NOTIFY"],
}

# Reverse map: event_type → category
_EVENT_TYPE_TO_CATEGORY: dict[str, str] = {}
for _cat, _types in EVENT_CATEGORIES.items():
    for _t in _types:
        _EVENT_TYPE_TO_CATEGORY[_t] = _cat


def _auth_headers() -> dict:
    return {"Authorization": f"Token {MIST_API_TOKEN}"}


def _oui_lookup(mac: str) -> str:
    """
    Stub OUI lookup — returns first 3 octets as manufacturer hint.
    A real implementation would query a local OUI database.
    """
    return mac[:6].upper() if len(mac) >= 6 else "Unknown"


def sanitize_wlan_key(wlan: str) -> str:
    """
    Sanitize a WLAN (SSID) name for safe use as a Redis key segment.
    Replaces colons, slashes, and whitespace with hyphens.
    """
    if not wlan or wlan == "__all__":
        return "__all__"
    return re.sub(r"[:/\s]", "-", wlan) or "__all__"


async def fetch_event_type_index() -> list[str]:
    """
    Fetch live event type list from Mist const endpoint (no auth required).
    Falls back to the hardcoded list on failure.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://{MIST_CLOUD_HOST}/api/v1/const/client_events"
            )
            resp.raise_for_status()
            data = resp.json()
            # API returns a list of objects with a "key" or "name" field
            if isinstance(data, list):
                types = []
                for item in data:
                    if isinstance(item, dict):
                        t = item.get("key") or item.get("name") or item.get("type") or ""
                    else:
                        t = str(item)
                    if t:
                        types.append(t)
                if types:
                    return types
    except Exception as exc:
        log.warning(f"Failed to fetch live event type index: {exc} — using hardcoded list")
    return MIST_CLIENT_EVENT_TYPES


async def ensure_event_type_index(redis_client) -> list[str]:
    """
    Load event type index from Redis; refresh from Mist API if missing.
    Returns ordered list of event type strings.
    """
    raw = await redis_client.get("sasquatch:event_type_index")
    if raw:
        return json.loads(raw)

    types = await fetch_event_type_index()
    await redis_client.set(
        "sasquatch:event_type_index", json.dumps(types), ex=EVENT_TYPE_INDEX_TTL
    )
    log.info(f"Event type index cached: {len(types)} types")
    return types


async def fetch_all_events(
    site_id: str,
    duration: str = "1h",
    on_page: Optional[callable] = None,
) -> list[dict]:
    """
    Fetch all client events for the given duration, paging through cursor results.

    on_page: optional async callable(page: int, fetched: int, total: int | None)
             called after each page is fetched, useful for progress tracking.
    """
    url = (
        f"https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/events"
        f"?limit=1000&duration={duration}"
    )
    all_events: list[dict] = []
    page = 0
    total_hint: Optional[int] = None
    async with httpx.AsyncClient(timeout=30.0) as client:
        while url:
            resp = await client.get(url, headers=_auth_headers())
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("results", [])
            # Capture total record count from first response if the API provides it
            if total_hint is None and "total" in data:
                total_hint = data["total"]
            all_events.extend(batch)
            page += 1
            log.info(
                f"Events page {page}: {len(batch)} events, total so far: {len(all_events)}"
            )
            if on_page is not None:
                await on_page(page, len(all_events), total_hint)
            next_path = data.get("next")
            url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None
    log.info(f"Event collection complete: {len(all_events)} total events")
    return all_events


def _get_category(event_type: str) -> str:
    return _EVENT_TYPE_TO_CATEGORY.get(event_type, "OTHER")


def _enrich_event(event: dict, client_cache: dict[str, dict]) -> dict:
    mac = (event.get("mac") or "").replace(":", "").lower()
    client_meta = client_cache.get(mac)
    enriched = dict(event)
    enriched["event_category"] = _get_category(event.get("type", ""))

    # Store the SSID as an explicit wlan field. No longer appended to device_family —
    # WLAN is now a first-class scope dimension in the UI and detection pipeline.
    ssid = (event.get("ssid") or "").strip()
    enriched["wlan"] = ssid if ssid else None

    if client_meta:
        enriched["device_family"] = client_meta.get("family", "Unknown")
        enriched["device_model"] = client_meta.get("model", "Unknown")
        enriched["device_manufacturer"] = client_meta.get("manufacturer", "Unknown")
    else:
        enriched["device_family"] = "Unknown"
        enriched["device_model"] = "Unknown"
        enriched["device_manufacturer"] = _oui_lookup(mac)

    return enriched


def _enrich_batch(events: list[dict], client_cache: dict) -> tuple[list[dict], set[str]]:
    """Enrich a batch of raw events. Returns (enriched_events, unknown_types).

    Events in IGNORED_EVENT_TYPES are silently dropped before enrichment.
    """
    known_types = set(MIST_CLIENT_EVENT_TYPES)
    unknown_types: set[str] = set()
    enriched = []
    for event in events:
        event_type = event.get("type", "")
        if event_type in IGNORED_EVENT_TYPES:
            continue
        if event_type and event_type not in known_types:
            unknown_types.add(event_type)
        enriched.append(_enrich_event(event, client_cache))
    return enriched, unknown_types


async def _write_events_to_site_set(
    redis_client, events: list[dict], site_id: str
) -> int:
    """
    Write enriched events to the per-site sorted set (sasquatch:events:{site_id}).
    Score = Unix timestamp. Member = deterministic JSON string.
    Cleans up entries older than EVENTS_TTL (7 days) after writing.
    Also updates sasquatch:wlans:{site_id} for O(1) WLAN enumeration.
    Returns count of entries written (including already-existing duplicates).
    """
    if not events:
        return 0

    events_key = f"sasquatch:events:{site_id}"
    wlans_key = f"sasquatch:wlans:{site_id}"
    cutoff = time.time() - EVENTS_TTL

    # Guard against legacy STRING key written by old per-site schema.
    # If the key exists but isn't a sorted set, delete it before writing.
    key_type = await redis_client.type(events_key)
    if key_type not in ("zset", "none"):
        log.warning(
            f"Deleting legacy Redis key {events_key} (type={key_type}); "
            "migrating to sorted set schema."
        )
        await redis_client.delete(events_key)

    pipe = redis_client.pipeline()

    mapping: dict[str, float] = {}
    wlans: set[str] = set()
    for event in events:
        score = float(event.get("timestamp") or 0)
        member = json.dumps(event, sort_keys=True)
        mapping[member] = score
        if event.get("wlan"):
            wlans.add(event["wlan"])

    if mapping:
        pipe.zadd(events_key, mapping)

    # Purge entries older than 7 days and refresh TTL
    pipe.zremrangebyscore(events_key, "-inf", cutoff)
    pipe.expire(events_key, EVENTS_TTL)

    # Track WLANs seen for this site for O(1) enumeration
    if wlans:
        pipe.sadd(wlans_key, *wlans)
        pipe.expire(wlans_key, EVENTS_TTL)

    await pipe.execute()
    return len(mapping)


async def _load_events_from_site_sets(
    redis_client,
    site_id: Optional[str] = None,
    wlan: Optional[str] = None,
) -> list[dict]:
    """
    Load events from per-site sorted sets, optionally filtered by site and/or WLAN.
    Returns events from the last EVENTS_TTL window (7 days).

    For a single site: one targeted ZRANGEBYSCORE call.
    For org-level (no site_id): all site keys discovered via SCAN and fetched in
    a single pipeline — one Redis round trip regardless of site count.
    """
    cutoff = time.time() - EVENTS_TTL

    if site_id:
        # Guard against legacy STRING key written by old per-site schema
        key_type = await redis_client.type(f"sasquatch:events:{site_id}")
        keys = [f"sasquatch:events:{site_id}"] if key_type == "zset" else []
    else:
        # _type="zset" skips any legacy STRING keys written by the old per-site schema
        keys = [k async for k in redis_client.scan_iter("sasquatch:events:*", _type="zset")]

    if not keys:
        return []

    pipe = redis_client.pipeline()
    for key in keys:
        pipe.zrangebyscore(key, cutoff, "+inf")
    results = await pipe.execute()

    events = [json.loads(m) for batch in results for m in batch]

    if wlan and wlan != "__all__":
        events = [e for e in events if e.get("wlan") == wlan]

    return events


async def collect(site_id: str) -> int:
    """
    Incremental collect: pull last 1hr of events from Mist and append to the global
    sorted set. Used by the scheduler. Fails fast if client cache is missing.
    Returns total count of events written (new + already-present).
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        client_cache = await get_client_cache(site_id)
        if not client_cache:
            raise RuntimeError(
                f"Client cache missing for site {site_id}. "
                "Run client_cache.refresh_client_cache() first."
            )

        new_raw = await fetch_all_events(site_id, duration="1h")
        if not new_raw:
            log.info(f"No new events in last 1hr for site {site_id}")
            return 0

        new_enriched, unknown_types = _enrich_batch(new_raw, client_cache)

        if unknown_types:
            await redis_client.sadd(f"sasquatch:unknown_event_types:{site_id}", *unknown_types)
            log.warning(f"Unknown event types found: {unknown_types}")

        written = await _write_events_to_site_set(redis_client, new_enriched, site_id)
        log.info(
            f"Incremental collect: {len(new_enriched)} events processed for site {site_id} "
            f"({written} unique members written to site set)"
        )
        return written

    finally:
        await redis_client.aclose()


async def collect_full(site_id: str, on_page: Optional[callable] = None) -> int:
    """
    Full collect: pull last 24hr of events from Mist and add to the global sorted set.
    Used by manual API trigger only. Does not replace existing history — events from
    previous days (up to 7 days) are preserved. Same-day events are deduplicated by
    the sorted set's unique member constraint.

    on_page: optional async callable forwarded to fetch_all_events for progress tracking.
    Returns count of event members written.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        client_cache = await get_client_cache(site_id)
        if not client_cache:
            raise RuntimeError(
                f"Client cache missing for site {site_id}. "
                "Run client_cache.refresh_client_cache() first."
            )

        events = await fetch_all_events(site_id, duration="1d", on_page=on_page)
        if not events:
            log.warning(f"No events returned for site {site_id}")
            return 0

        enriched, unknown_types = _enrich_batch(events, client_cache)

        if unknown_types:
            await redis_client.sadd(f"sasquatch:unknown_event_types:{site_id}", *unknown_types)
            log.warning(f"Unknown event types found: {unknown_types}")

        written = await _write_events_to_site_set(redis_client, enriched, site_id)
        log.info(f"Full collect: {len(enriched)} events processed, {written} written → site set")
        return written

    finally:
        await redis_client.aclose()


async def get_events(
    site_id: Optional[str] = None,
    wlan: Optional[str] = None,
) -> list[dict]:
    """
    Load events from per-site sorted sets, optionally filtered by site and/or WLAN.
    wlan=None or wlan="__all__" returns all WLANs.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        return await _load_events_from_site_sets(
            redis_client,
            site_id=site_id,
            wlan=wlan if (wlan and wlan != "__all__") else None,
        )
    finally:
        await redis_client.aclose()


async def get_wlans(site_id: Optional[str] = None) -> list[str]:
    """
    Return sorted list of unique WLAN (SSID) names for a site or org-wide.
    For a single site, reads from sasquatch:wlans:{site_id} set — O(1).
    Falls back to scanning event data only if the WLAN set is missing.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        if site_id:
            members = await redis_client.smembers(f"sasquatch:wlans:{site_id}")
            if members:
                return sorted(members)
        # Org-level or fallback: union all site WLAN sets in one pipeline
        wlan_keys = [k async for k in redis_client.scan_iter("sasquatch:wlans:*")]
        if wlan_keys:
            pipe = redis_client.pipeline()
            for k in wlan_keys:
                pipe.smembers(k)
            results = await pipe.execute()
            all_wlans = sorted({w for batch in results for w in batch})
            if not site_id:
                return all_wlans
        # Last resort: derive from event data (handles cold start before first write)
        events = await _load_events_from_site_sets(redis_client, site_id=site_id)
        return sorted({e["wlan"] for e in events if e.get("wlan")})
    finally:
        await redis_client.aclose()


async def get_event_type_index(site_id: Optional[str] = None) -> list[str]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        return await ensure_event_type_index(redis_client)
    finally:
        await redis_client.aclose()

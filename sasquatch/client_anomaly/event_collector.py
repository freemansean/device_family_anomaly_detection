"""
event_collector.py — Pull client events, enrich with device metadata, store in SQLite.

Events are stored in a SQLite events table, deduplicated by (mac, event_type, timestamp,
bssid).  Events survive for 7 days; stale entries are purged by db.purge_old_events().

Scheduled runs fetch only the last hour and append to the rolling dataset.
A full 24hr backfill is only performed when explicitly requested via the API.

Cache misses during enrichment: events whose MAC is absent from the client cache
are enriched via OUI lookup (manufacturer derived from the first 3 octets of the
MAC). The client cache is NEVER refreshed mid-collect — refresh is owned by the
"Build Cache" path (`_org_collect_background_task` Phase 1) and the daily job in
client_cache.py. A cache-miss-triggered refresh used to exist here, but it caused
a stuck-loop where every collect ran a multi-thousand-page client search and then
refetched events.
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Optional

import httpx
import redis.asyncio as aioredis

from .client_cache import get_client_cache
from .client_cache import unknown_family_label
from .oui_lookup import lookup as oui_lookup
from . import db

log = logging.getLogger(__name__)

from . import config

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Reserve a buffer of API calls so other scheduled jobs (client cache refresh,
# health checks, etc.) don't get starved while a large pagination is running.
_RATE_LIMIT_RESERVE = 200

# Flush raw events to SQLite in chunks of this size during org-level pagination.
# Keeps memory bounded and ensures partial progress is preserved if the fetch
# fails mid-stream (e.g. a 429 or network error after several million events).
_ORG_FLUSH_BATCH_SIZE = 100_000

# Lower flush threshold for the hourly incremental collect. A typical hourly
# org run produces well under 100k events, so the default threshold means the
# hourly path effectively does a single end-of-run write — losing the partial-
# progress and memory-bounding benefits the streaming flush is meant to give.
# 25k makes the hourly collector flush several times per run for active orgs
# while still keeping per-flush overhead modest.
_ORG_HOURLY_FLUSH_BATCH_SIZE = 25_000


async def _check_rate_limit(resp: httpx.Response, page: int, label: str) -> None:
    """Sleep if the Mist rate limit budget is running low.

    Mist may return these headers on every response:
      X-RateLimit-Remaining — calls left in the current window
      X-RateLimit-Reset     — Unix timestamp when the window resets
      X-RateLimit-Limit     — total window size

    If no rate limit headers are returned, fall back to a simple per-request
    throttle calibrated to stay under 5000 calls/hour (≈ 0.72s/request).
    """
    # On page 1, log whatever rate-limit-related headers we see so we can
    # diagnose why backoff didn't trigger in the past.
    if page == 1:
        rl_headers = {k: v for k, v in resp.headers.items() if "ratelimit" in k.lower() or "retry" in k.lower()}
        log.info(f"[{label}] Rate limit headers on page 1: {rl_headers or 'NONE'}")

    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset_at = resp.headers.get("X-RateLimit-Reset")

    if remaining is None:
        # No rate limit signal from the API. Throttle conservatively to stay
        # under 5000/hr (Mist's documented default). 0.8s/request ≈ 4500/hr.
        await asyncio.sleep(0.8)
        return

    remaining = int(remaining)
    if remaining > _RATE_LIMIT_RESERVE:
        return

    # Budget is low — sleep until the reset window opens.
    if reset_at is not None:
        wait = max(float(reset_at) - time.time(), 1.0)
    else:
        # No reset header — conservative 60s pause.
        wait = 60.0

    log.warning(
        f"[{label}] Rate limit low: {remaining} calls remaining after page {page}. "
        f"Sleeping {wait:.0f}s until reset."
    )
    await asyncio.sleep(wait)

# Events are kept for 7 days in SQLite.
EVENTS_TTL = 7 * 24 * 3600
EVENT_TYPE_INDEX_TTL = 7 * 24 * 3600  # 7 days

# DHCPv6 failure events are excluded from analysis — they are frequent noise on
# dual-stack networks and do not correlate with actionable client connectivity issues.
IGNORED_EVENT_TYPES: frozenset[str] = frozenset({
    "MARVIS_EVENT_CLIENT_DHCPV6_NAK",
    "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
})

# Auth-family events with these status codes are transmission failures at the radio
# layer (frame not acknowledged) — the AP never received the client's frame, so there
# is no auth decision. These are caused by poor RF coverage, not device-level
# authentication behavior. Counting them as auth failures inflates failure ratios and
# depresses health scores for devices in marginal coverage areas.
#
# Mist reports this code with inconsistent sign across event types and over time,
# so both signs are ignored for every affected event type.
_TRANSMISSION_FAILURE_IGNORED: dict[str, frozenset[int]] = {
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE": frozenset({79, -79}),
    "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE": frozenset({79, -79}),
}


def _transmission_filter_summary() -> str:
    parts = [
        f"{etype}={sorted(codes)}"
        for etype, codes in _TRANSMISSION_FAILURE_IGNORED.items()
    ]
    return ", ".join(parts)

# Events with RSSI weaker than the configured threshold are discarded during
# enrichment, regardless of event type. Rationale: at the RF fringe, every
# event outcome is unreliable — successes may be racing retransmits, DHCP/DNS
# latencies inflate, and transient failures cannot be distinguished from
# coverage artifacts. Events without an `rssi` field (None) are always passed
# through since they are typically synthetic or boundary markers (e.g.
# MARVIS_EVENT_STA_LEAVING) and have no signal-strength to evaluate. The
# threshold is read from `config.get("general", "anomaly_rssi_min_threshold")`
# (env var `ANOMALY_RSSI_MIN_THRESHOLD`, default -87 dBm).

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
    """Resolve MAC OUI to manufacturer name via the local IEEE registry."""
    return oui_lookup(mac)


def sanitize_wlan_key(wlan: str) -> str:
    """
    Sanitize a WLAN (SSID) name for safe use as a Redis key segment.
    Replaces colons, slashes, and whitespace with hyphens.
    """
    return re.sub(r"[:/\s]", "-", wlan) if wlan else ""


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


async def iter_events_org(
    org_id: str,
    duration: str = "1h",
    batch_size: int = _ORG_FLUSH_BATCH_SIZE,
    on_page: Optional[callable] = None,
    start: Optional[int] = None,
    end: Optional[int] = None,
):
    """
    Async generator that paginates through org-level client events and yields
    raw event batches of approximately `batch_size` events at a time.

    Uses GET /api/v1/orgs/{org_id}/clients/events with cursor pagination.
    Each event includes a site_id field identifying which site it belongs to.

    Yielding in chunks lets the caller enrich and persist to SQLite incrementally,
    so a failure partway through a multi-million-event collection does not lose
    the progress that's already been written.

    Window selection: when both `start` and `end` Unix timestamps are provided,
    they are used verbatim and `duration` is ignored. Otherwise the relative
    `duration` parameter is used.

    on_page: optional async callable(page: int, fetched: int, total: int | None)
             called after each page is fetched, useful for progress tracking.
    """
    if start is not None and end is not None:
        window_qs = f"start={int(start)}&end={int(end)}"
    else:
        window_qs = f"duration={duration}"
    url = (
        f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/events"
        f"?limit=1000&{window_qs}"
    )
    buffer: list[dict] = []
    total_fetched = 0
    page = 0
    total_hint: Optional[int] = None
    async with httpx.AsyncClient(timeout=30.0) as client:
        while url:
            resp = await client.get(url, headers=_auth_headers())
            resp.raise_for_status()
            data = resp.json()
            # Debug: log response shape to diagnose empty-results issues
            if page == 0:
                if isinstance(data, dict):
                    log.info(
                        f"[org] Response keys: {list(data.keys())}, "
                        f"total={data.get('total')}, "
                        f"results type={type(data.get('results')).__name__}, "
                        f"results len={len(data.get('results', []))}"
                    )
                else:
                    log.warning(
                        f"[org] Unexpected response type: {type(data).__name__}, "
                        f"len={len(data) if hasattr(data, '__len__') else 'N/A'}"
                    )
            batch = data.get("results", [])
            if total_hint is None and "total" in data:
                total_hint = data["total"]
            buffer.extend(batch)
            total_fetched += len(batch)
            page += 1
            log.info(
                f"[org] Events page {page}: {len(batch)} events, "
                f"total so far: {total_fetched}"
            )
            if on_page is not None:
                await on_page(page, total_fetched, total_hint)
            await _check_rate_limit(resp, page, "org")
            next_path = data.get("next")
            url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None

            # Flush the buffer whenever it reaches the batch threshold so the
            # caller can persist it before we fetch more.
            if len(buffer) >= batch_size:
                yield buffer
                buffer = []

    # Final flush of any remaining events after pagination completes.
    if buffer:
        yield buffer
    log.info(f"[org] Event collection complete: {total_fetched} total events")


async def fetch_all_events_org(
    org_id: str,
    duration: str = "1h",
    on_page: Optional[callable] = None,
    start: Optional[int] = None,
    end: Optional[int] = None,
) -> list[dict]:
    """
    Non-streaming wrapper around iter_events_org. Accumulates all events into
    a single list before returning. Prefer iter_events_org for large collections
    to keep memory bounded and preserve partial progress on failure.
    """
    all_events: list[dict] = []
    async for batch in iter_events_org(
        org_id, duration=duration, on_page=on_page, start=start, end=end
    ):
        all_events.extend(batch)
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
        family = client_meta.get("family", "Unknown")
        manufacturer = client_meta.get("manufacturer", "Unknown")
        # Cache-hit but the cache stored a bare "Unknown" (Mist had no
        # fingerprint and OUI also returned nothing usable at write time).
        # Try OUI again here — the local OUI database may have been updated
        # since the cache was last written, and either way it's cheap. Any
        # vendor we recover lands in an Unknown/<vendor> sub-bucket via the
        # shared helper so cache-hit and cache-miss labels stay identical.
        if family == "Unknown":
            oui_mfg = _oui_lookup(mac)
            if oui_mfg != "Unknown":
                family = unknown_family_label(oui_mfg)
                if not manufacturer or manufacturer == "Unknown":
                    manufacturer = oui_mfg
        enriched["device_family"] = family
        enriched["device_model"] = client_meta.get("model", "Unknown")
        enriched["device_manufacturer"] = manufacturer
        enriched["last_username"] = client_meta.get("last_username", "")
    else:
        # Cache miss — fall back to OUI for both the manufacturer label and
        # the family sub-bucket. unknown_family_label() handles the bucket
        # name format (and returns bare "Unknown" when OUI gave nothing).
        mfg = _oui_lookup(mac)
        enriched["device_manufacturer"] = mfg
        enriched["device_model"] = "Unknown"
        enriched["last_username"] = ""
        enriched["device_family"] = unknown_family_label(mfg)

    return enriched


def _dedup_events(events: list[dict]) -> list[dict]:
    """Collapse Mist API variant duplicates and strip volatile fields.

    Mist returns MARVIS_EVENT_CLIENT_AUTH_FAILURE (and potentially other MARVIS
    events) in up to 3 variants per logical event, all at the same timestamp:
      - one with has_pcap=False + pcap_url
      - one with no has_pcap / no pcap_url
      - one with has_pcap=True + pcap_url

    The pcap_url field is a short-lived JWT (~2hr expiry). Re-fetching the same
    event on a subsequent collect() cycle produces a new JWT → a new JSON member
    string → a new sorted-set entry, multiplying events on every 15-minute cycle.

    Fix: strip pcap_url before deduplication (and storage), then collapse variants
    sharing the same (mac, type, timestamp, bssid) to a single representative,
    preferring the has_pcap=True variant for maximum information value.
    """
    seen: dict[tuple, int] = {}  # dedup key → index into result
    result: list[dict] = []

    for event in events:
        # Strip pcap_url — short-lived JWT, useless after ~2hr and causes
        # dedup failures when the JWT rotates across collect() cycles.
        e = {k: v for k, v in event.items() if k != "pcap_url"}

        key = (
            (e.get("mac") or "").replace(":", "").lower(),
            e.get("type", ""),
            e.get("timestamp", 0),
            e.get("bssid", ""),
        )

        if key not in seen:
            seen[key] = len(result)
            result.append(e)
        elif e.get("has_pcap") is True and not result[seen[key]].get("has_pcap"):
            # Upgrade to the has_pcap=True variant — it's the most informative
            result[seen[key]] = e

    return result


def _enrich_batch(
    events: list[dict],
    client_cache: dict,
    rssi_threshold: int,
    stats: dict[str, int] | None = None,
) -> tuple[list[dict], set[str], set[str]]:
    """Enrich a batch of raw events.

    Returns (enriched_events, unknown_types, cache_miss_macs).

    unknown_types: event type strings not in the known list.
    cache_miss_macs: distinct MAC addresses absent from client_cache (excluding
        MACs that are empty strings). Used by collect() to decide whether to
        trigger a cache refresh for newly joined devices.

    Events in IGNORED_EVENT_TYPES are silently dropped before enrichment.
    Mist API variant duplicates (has_pcap variants, pcap_url JWT rotation) are
    collapsed by _dedup_events before enrichment.

    RSSI filtering is blanket: any event with `rssi < rssi_threshold` is
    dropped regardless of type. Events with `rssi is None` (synthetic /
    boundary markers like MARVIS_EVENT_STA_LEAVING) always pass through.

    If `stats` is provided, the in/out counters for this batch are added to
    the accumulator keys `transmission_failure_skipped` and
    `weak_signal_skipped` so the caller can log a per-collect summary.
    """
    events = _dedup_events(events)
    known_types = set(MIST_CLIENT_EVENT_TYPES)
    unknown_types: set[str] = set()
    cache_miss_macs: set[str] = set()
    enriched = []
    transmission_failure_skipped = 0
    weak_signal_skipped = 0
    for event in events:
        event_type = event.get("type", "")
        if event_type in IGNORED_EVENT_TYPES:
            continue
        ignored_codes = _TRANSMISSION_FAILURE_IGNORED.get(event_type)
        if ignored_codes is not None and event.get("status_code") in ignored_codes:
            transmission_failure_skipped += 1
            continue
        rssi = event.get("rssi")
        if rssi is not None and rssi < rssi_threshold:
            weak_signal_skipped += 1
            continue
        if event_type and event_type not in known_types:
            unknown_types.add(event_type)
        mac = (event.get("mac") or "").replace(":", "").lower()
        if mac and mac not in client_cache:
            cache_miss_macs.add(mac)
        enriched.append(_enrich_event(event, client_cache))
    if stats is not None:
        stats["transmission_failure_skipped"] = (
            stats.get("transmission_failure_skipped", 0) + transmission_failure_skipped
        )
        stats["weak_signal_skipped"] = (
            stats.get("weak_signal_skipped", 0) + weak_signal_skipped
        )
    return enriched, unknown_types, cache_miss_macs


async def _write_events_to_sqlite(events: list[dict], site_id: str) -> int:
    """
    Write enriched events to SQLite.  Duplicates (same mac, event_type,
    timestamp, bssid) are silently ignored.
    Returns count of rows inserted.
    """
    return await db.insert_events(events, site_id)


async def reenrich_stale_events(site_id: str, client_cache: dict[str, dict]) -> int:
    """
    Re-enrich stored events whose device_family is "Unknown" (or "Unknown/...").

    Two enrichment paths run in a single pass:
    - Cache-hit MACs: re-enriched from client_cache (may now have a resolved family).
    - Cache-miss MACs: re-enriched via OUI lookup (updated OUI DB may now resolve the
      manufacturer, upgrading "Unknown" to "Unknown/<Manufacturer>"). These are IoT/
      unregistered devices that never appear in Mist's clients/search results.

    Returns the count of events re-enriched.
    """
    def _enricher(event: dict, cache: dict) -> dict:
        mac = (event.get("mac") or "").replace(":", "").lower()
        cache_for_mac = cache if mac in cache else {}
        return _enrich_event(event, cache_for_mac)

    return await db.reenrich_events(site_id, _enricher, client_cache)


async def _enrich_and_write_org_batch(
    events_by_site: dict[str, list[dict]],
    client_cache: dict[str, dict],
    rssi_threshold: int,
    stats: dict[str, int] | None = None,
) -> tuple[dict[str, int], set[str]]:
    """
    Enrich and write org-level events grouped by site_id.

    A single org-wide client cache is shared across every site group — MACs are
    unique across the org so the same lookup table serves every site.

    Returns ({site_id: rows_written}, all_unknown_types).
    """
    site_counts: dict[str, int] = {}
    all_unknown_types: set[str] = set()

    for site_id, site_events in events_by_site.items():
        if not site_events:
            continue

        enriched, unknown_types, miss_macs = _enrich_batch(
            site_events, client_cache, rssi_threshold, stats
        )
        all_unknown_types.update(unknown_types)

        if miss_macs:
            log.info(
                f"[org] {len(miss_macs)} cache-miss MACs for site {site_id} — "
                "enriched via OUI lookup (no client cache refresh)"
            )

        written = await _write_events_to_sqlite(enriched, site_id)
        site_counts[site_id] = written
        log.info(
            f"[org] Site {site_id}: {len(enriched)} events enriched, "
            f"{written} rows inserted"
        )

    return site_counts, all_unknown_types


async def _persist_unknown_types(unknown_types: set[str]) -> None:
    """Write unknown event types to the org-level Redis set."""
    if not unknown_types:
        return
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis_client.sadd("sasquatch:unknown_event_types:org", *unknown_types)
    finally:
        await redis_client.aclose()
    log.warning(f"[org] Unknown event types found: {unknown_types}")


async def _flush_org_batch(
    raw_batch: list[dict],
    site_counts: dict[str, int],
    all_unknown_types: set[str],
    batch_num: int,
    client_cache: dict[str, dict],
    rssi_threshold: int,
    filter_stats: dict[str, int] | None = None,
) -> None:
    """
    Group a raw event batch by site_id, enrich, and write to SQLite.
    Updates site_counts and all_unknown_types in place.

    Called repeatedly during org-level pagination so that each ~100k-event chunk
    is persisted as it arrives, instead of accumulating in memory until the end.

    `client_cache` is the org-wide MAC -> metadata map loaded once at the start
    of the streaming run and shared across every batch and every site.

    `rssi_threshold` is the per-collect RSSI floor (dBm) resolved once at the
    start of the collect. `filter_stats` is a mutable accumulator updated in
    place by `_enrich_batch` so the streaming caller can log a single
    per-collect summary at the end.
    """
    events_by_site: dict[str, list[dict]] = {}
    for event in raw_batch:
        sid = event.get("site_id", "")
        if sid:
            events_by_site.setdefault(sid, []).append(event)

    log.info(
        f"[org] Flushing batch {batch_num}: {len(raw_batch)} events across "
        f"{len(events_by_site)} sites → SQLite"
    )
    batch_site_counts, batch_unknown = await _enrich_and_write_org_batch(
        events_by_site, client_cache, rssi_threshold, filter_stats
    )
    for sid, count in batch_site_counts.items():
        site_counts[sid] = site_counts.get(sid, 0) + count
    all_unknown_types.update(batch_unknown)


async def _collect_org_streaming(
    org_id: str,
    duration: str,
    on_page: Optional[callable],
    label: str,
    start: Optional[int] = None,
    end: Optional[int] = None,
    batch_size: int = _ORG_FLUSH_BATCH_SIZE,
) -> dict[str, int]:
    """
    Shared streaming implementation for collect_org and collect_org_full.

    Iterates over iter_events_org and flushes each batch to SQLite as it arrives,
    bounding memory usage and preserving partial progress if the fetch fails.
    On exception, logs how much was already written and re-raises.

    When `start`/`end` Unix timestamps are supplied, they replace `duration`
    in the underlying API query.

    `batch_size` controls how many events are buffered before being flushed to
    SQLite. The hourly path overrides this to a smaller value so that even
    short runs flush mid-stream rather than only at the very end.

    The org-wide client cache is loaded once before pagination begins and
    threaded through every batch flush — MACs are unique across the org so the
    same lookup table serves every site.
    """
    client_cache = await get_client_cache()
    if client_cache is None:
        raise RuntimeError(
            "Org client cache missing. "
            "Run client_cache.refresh_client_cache_org() first."
        )
    if not client_cache:
        log.warning(
            "[org] Client cache is empty — proceeding with OUI-only enrichment."
        )

    # Resolve the RSSI floor once per collect so every batch uses a consistent
    # value even if the override is edited mid-run.
    rssi_threshold = int(config.get("general", "anomaly_rssi_min_threshold"))

    site_counts: dict[str, int] = {}
    all_unknown_types: set[str] = set()
    filter_stats: dict[str, int] = {
        "transmission_failure_skipped": 0,
        "weak_signal_skipped": 0,
    }
    batch_num = 0

    try:
        async for raw_batch in iter_events_org(
            org_id,
            duration=duration,
            batch_size=batch_size,
            on_page=on_page,
            start=start,
            end=end,
        ):
            batch_num += 1
            await _flush_org_batch(
                raw_batch,
                site_counts,
                all_unknown_types,
                batch_num,
                client_cache,
                rssi_threshold,
                filter_stats,
            )
    except Exception as exc:
        total_so_far = sum(site_counts.values())
        log.error(
            f"[org] {label} failed after {batch_num} batches "
            f"({total_so_far} rows already written to SQLite): {exc}"
        )
        await _persist_unknown_types(all_unknown_types)
        raise

    if batch_num == 0:
        log.warning(f"[org] No events returned for {label}")
        return {}

    await _persist_unknown_types(all_unknown_types)

    total = sum(site_counts.values())
    log.info(
        f"[org] {label} complete: {total} rows written across "
        f"{len(site_counts)} sites in {batch_num} batches"
    )
    log.info(
        f"[org] {label} filter summary: "
        f"{filter_stats['weak_signal_skipped']} events dropped "
        f"(rssi < {rssi_threshold} dBm, all types); "
        f"{filter_stats['transmission_failure_skipped']} auth events "
        f"dropped (transmission failures: {_transmission_filter_summary()})"
    )
    return site_counts


async def collect_org(
    org_id: str,
    duration: str = "1h",
    on_page: Optional[callable] = None,
) -> dict[str, int]:
    """
    Org-level incremental collect: stream events org-wide via a single API call,
    enriching and writing each batch to SQLite as it arrives.

    The window is expressed as explicit Unix timestamps so the bound is anchored
    at the moment the poll fired (consistent with collect_org_full and immune to
    pagination latency).

    Uses `_ORG_HOURLY_FLUSH_BATCH_SIZE` (smaller than the full-collect threshold)
    so even modest hourly volumes flush to SQLite multiple times during a run,
    matching the partial-progress / memory-bounding behavior of collect_org_full.

    Returns {site_id: rows_written} for each site that had events. On failure,
    returns the partial counts already persisted before the error.
    """
    end_ts = int(time.time())
    start_ts = end_ts - 3600
    return await _collect_org_streaming(
        org_id,
        duration=duration,
        on_page=on_page,
        label="Incremental collect (1h)",
        start=start_ts,
        end=end_ts,
        batch_size=_ORG_HOURLY_FLUSH_BATCH_SIZE,
    )


async def collect_org_full(
    org_id: str,
    on_page: Optional[callable] = None,
) -> dict[str, int]:
    """
    Org-level full collect for the most recent 12 hours via a single API call.
    Used by manual trigger (POST /api/v1/org/collect-full).

    The window is expressed as explicit Unix timestamps (`start`/`end`) rather
    than a relative `duration` so the bound is anchored at the moment the
    collect was triggered and is unaffected by retries or pagination latency.

    Streams events in ~100k-event batches, writing each to SQLite as it arrives,
    so a mid-stream failure (429, network error, etc.) does not discard the
    events that have already been paginated and enriched.

    Returns {site_id: rows_written} for each site that had events.
    """
    end_ts = int(time.time())
    start_ts = end_ts - 12 * 3600
    return await _collect_org_streaming(
        org_id,
        duration="12h",
        on_page=on_page,
        label="Full collect (12h)",
        start=start_ts,
        end=end_ts,
    )


async def get_events(
    site_id: Optional[str] = None,
    wlan: Optional[str] = None,
    since: Optional[float] = None,
) -> list[dict]:
    """
    Load events from SQLite, optionally filtered by site and/or WLAN.
    wlan=None returns all events regardless of WLAN.
    since: optional Unix timestamp cutoff (default: 7 days ago).
    """
    return await db.get_events(site_id=site_id, wlan=wlan, since=since)


async def get_wlans(site_id: Optional[str] = None) -> list[str]:
    """
    Return sorted list of unique WLAN (SSID) names for a site or org-wide.
    Reads directly from the SQLite events table via SELECT DISTINCT.
    """
    return await db.get_wlans(site_id=site_id)


async def get_event_type_index(site_id: Optional[str] = None) -> list[str]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        return await ensure_event_type_index(redis_client)
    finally:
        await redis_client.aclose()

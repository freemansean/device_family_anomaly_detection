"""
event_collector.py — Pull 24hr client events, enrich with device metadata, store in Redis.
"""

import json
import logging
import os
from typing import Optional

import httpx
import redis.asyncio as aioredis

from .client_cache import get_client_cache

log = logging.getLogger(__name__)

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

EVENTS_TTL = 24 * 3600  # 24 hours
EVENT_TYPE_INDEX_TTL = 7 * 24 * 3600  # 7 days

# Known Mist client event types — used to define the ML feature vector dimensions.
# Fetched live from /api/v1/const/client_events at startup and cached in Redis,
# but this list serves as a safe fallback.
MIST_CLIENT_EVENT_TYPES = [
    # DHCP
    "CLIENT_IP_ASSIGNED",
    "CLIENT_IPV6_ASSIGNED",
    "MARVIS_EVENT_CLIENT_DHCP_NAK",
    "MARVIS_EVENT_CLIENT_DHCPV6_NAK",
    "MARVIS_EVENT_CLIENT_DHCP_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCP_STUCK",
    "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
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
    "CLIENT_ASSOCIATION",
    "CLIENT_ASSOCIATION_FAILURE",
    # Roam / reassociation (success)
    "CLIENT_AUTH_REASSOCIATION",
    "CLIENT_AUTH_REASSOCIATION_11R",
    "CLIENT_AUTH_REASSOCIATION_OKC",
    "CLIENT_REASSOCIATION",
    "CLIENT_REASSOCIATION_PMKC",
    # Roam / reassociation (failure)
    "MARVIS_EVENT_CLIENT_FBT_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",
    "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
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
        "MARVIS_EVENT_CLIENT_DHCPV6_NAK",
        "MARVIS_EVENT_CLIENT_DHCP_FAILURE",
        "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
        "MARVIS_EVENT_CLIENT_DHCP_STUCK",
        "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
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
    ],
    "ROAM_SUCCESS": [
        "CLIENT_AUTH_REASSOCIATION",
        "CLIENT_AUTH_REASSOCIATION_11R",
        "CLIENT_AUTH_REASSOCIATION_OKC",
        "CLIENT_REASSOCIATION",
        "CLIENT_REASSOCIATION_PMKC",
    ],
    "ROAM_FAILURE": [
        "MARVIS_EVENT_CLIENT_FBT_FAILURE",
        "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
        "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",
        "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
    ],
    "DISASSOC": [
        "CLIENT_DEASSOCIATION",
        "CLIENT_DEAUTHENTICATION",
        "CLIENT_DEAUTHENTICATED",
        "MARVIS_EVENT_STA_LEAVING",
    ],
    "ARP": [
        "CLIENT_GW_ARP_OK",
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


async def fetch_all_events(site_id: str) -> list[dict]:
    url = (
        f"https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/events"
        f"?limit=1000&duration=1d"
    )
    all_events = []
    page = 0
    async with httpx.AsyncClient(timeout=30.0) as client:
        while url:
            resp = await client.get(url, headers=_auth_headers())
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("results", [])
            all_events.extend(batch)
            page += 1
            log.info(
                f"Events page {page}: {len(batch)} events, total so far: {len(all_events)}"
            )
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

    if client_meta:
        enriched["device_family"] = client_meta.get("family", "Unknown")
        enriched["device_model"] = client_meta.get("model", "Unknown")
        enriched["device_manufacturer"] = client_meta.get("manufacturer", "Unknown")
    else:
        enriched["device_family"] = "Unknown"
        enriched["device_model"] = "Unknown"
        enriched["device_manufacturer"] = _oui_lookup(mac)

    return enriched


async def collect(site_id: str) -> int:
    """
    Pull 24hr events from Mist, enrich with client cache, store in Redis.
    Fails fast if client cache is missing — does NOT make a redundant client list call.
    Returns count of events stored.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        # Fail fast if client cache is missing
        client_cache = await get_client_cache(site_id)
        if not client_cache:
            raise RuntimeError(
                f"Client cache missing for site {site_id}. "
                "Run client_cache.refresh_client_cache() first."
            )

        events = await fetch_all_events(site_id)
        if not events:
            log.warning(f"No events returned for site {site_id}")
            return 0

        # Track unknown event types
        known_types = set(MIST_CLIENT_EVENT_TYPES)
        unknown_types: set[str] = set()

        enriched_events = []
        for event in events:
            event_type = event.get("type", "")
            if event_type and event_type not in known_types:
                unknown_types.add(event_type)
            enriched_events.append(_enrich_event(event, client_cache))

        # Log unknown event types to Redis for review
        if unknown_types:
            unk_key = f"sasquatch:unknown_event_types:{site_id}"
            await redis_client.sadd(unk_key, *unknown_types)
            log.warning(f"Unknown event types found: {unknown_types}")

        key = f"sasquatch:events:{site_id}"
        await redis_client.set(key, json.dumps(enriched_events), ex=EVENTS_TTL)
        log.info(f"Stored {len(enriched_events)} events → {key}")
        return len(enriched_events)

    finally:
        await redis_client.aclose()


async def get_events(site_id: str) -> list[dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(f"sasquatch:events:{site_id}")
    finally:
        await redis_client.aclose()
    if not raw:
        return []
    return json.loads(raw)


async def get_event_type_index(site_id: Optional[str] = None) -> list[str]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        return await ensure_event_type_index(redis_client)
    finally:
        await redis_client.aclose()

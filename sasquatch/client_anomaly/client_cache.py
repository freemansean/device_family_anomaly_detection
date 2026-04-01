"""
client_cache.py — Daily client device lookup table refresh.

Pulls all clients for a site from the Mist API, classifies each into a device family,
and stores MAC → metadata in Redis with a 25hr TTL.
"""

import json
import logging
import os

import httpx
import redis.asyncio as aioredis

log = logging.getLogger(__name__)

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

CLIENT_CACHE_TTL = 25 * 3600  # 25 hours


def _auth_headers() -> dict:
    return {"Authorization": f"Token {MIST_API_TOKEN}"}


def classify_family(client: dict) -> str:
    model = (client.get("last_model") or "").strip()
    device = (client.get("last_device") or "").strip()
    os_str = (client.get("last_os") or "").strip()
    mfg = (client.get("mfg") or "").strip()

    combined = f"{model} {device} {os_str} {mfg}".lower()

    if "iphone" in combined:
        return "iPhone"
    if "ipad" in combined:
        return "iPad"
    if "mac" in combined and "apple" in combined:
        return "MacBook"
    if "apple" in combined:
        return "Apple"
    if "android" in combined and "tablet" in combined:
        return "Android Tablet"
    if "android" in combined:
        return "Android Phone"
    if "windows" in combined:
        return "Windows"
    if "chrome" in combined:
        return "Chromebook"
    if "linux" in combined:
        return "Linux"
    if "printer" in combined or "print" in combined:
        return "Printer"
    if mfg and model == "" and os_str == "":
        return f"IoT ({mfg})"
    return "Unknown"


async def fetch_all_clients(site_id: str) -> list[dict]:
    url = f"https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/search?limit=1000"
    all_clients = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        while url:
            resp = await client.get(url, headers=_auth_headers())
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("results", [])
            all_clients.extend(batch)
            log.info(f"Clients page: {len(batch)} records, total so far: {len(all_clients)}")
            next_path = data.get("next")
            url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None
    log.info(f"Client fetch complete: {len(all_clients)} total clients")
    return all_clients


def _build_client_record(client: dict) -> dict:
    # last_model / last_os / last_device are scalar strings in the enriched search results.
    # The raw client record may also have array fields; prefer last_* scalars.
    return {
        "family": classify_family(client),
        "model": client.get("last_model") or "",
        "os": client.get("last_os") or "",
        "manufacturer": client.get("mfg") or "",
        "random_mac": client.get("random_mac", False),
        "last_ssid": client.get("last_ssid") or "",
        "last_ap": client.get("last_ap") or "",
    }


async def refresh_client_cache(site_id: str) -> int:
    """
    Fetch all clients from Mist API, build MAC → metadata dict, store in Redis.
    Returns count of clients stored.
    """
    clients = await fetch_all_clients(site_id)
    if not clients:
        log.warning(f"No clients returned for site {site_id}")
        return 0

    lookup: dict[str, dict] = {}
    for c in clients:
        mac = (c.get("mac") or "").replace(":", "").lower()
        if not mac:
            continue
        lookup[mac] = _build_client_record(c)

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        key = f"sasquatch:clients:{site_id}"
        await redis_client.set(key, json.dumps(lookup), ex=CLIENT_CACHE_TTL)
        log.info(f"Stored {len(lookup)} client records → {key} (TTL {CLIENT_CACHE_TTL}s)")
    finally:
        await redis_client.aclose()

    return len(lookup)


async def get_client_cache(site_id: str) -> dict[str, dict]:
    """
    Load client cache from Redis. Returns empty dict if missing.
    Callers that depend on this data should fail fast if the result is empty.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(f"sasquatch:clients:{site_id}")
    finally:
        await redis_client.aclose()

    if not raw:
        return {}
    return json.loads(raw)

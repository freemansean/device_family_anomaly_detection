"""
client_cache.py — Daily client device lookup table refresh.

Pulls all clients for the configured org from the Mist API, classifies each
into a device family, and stores MAC -> metadata in SQLite. The cache is
org-scoped: MACs uniquely identify clients across the entire organization, so
event enrichment loads one org-wide map regardless of which site emitted the
event.
"""

import asyncio
import logging
import os
import time

import httpx
from .oui_lookup import lookup as oui_lookup
from . import db

log = logging.getLogger(__name__)

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")


def _auth_headers() -> dict:
    return {"Authorization": f"Token {MIST_API_TOKEN}"}


def _normalize_family(name: str) -> str:
    """
    Normalize a dynamic (non-hardcoded) family name for consistent grouping.
    Strips trailing punctuation/whitespace then truncates to 12 characters so that
    variants like "Zebra Technologies Inc" and "Zebra Technologies Inc." map to the
    same family label.
    """
    cleaned = name.rstrip(".,; ").strip()
    return cleaned[:12].strip() if len(cleaned) > 12 else cleaned


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
    if "awair" in combined:
        return "Awair"
    # Use OS type if available; fall back to manufacturer name.
    # Skip generic IoT/embedded markers that Mist uses as placeholder OS labels —
    # they add no information over the manufacturer name.
    # Normalize to first 12 chars so minor variants (punctuation, trailing text)
    # collapse into the same family group.
    _GENERIC_OS = {"iot", "iot device", "embedded", "other"}
    if os_str and os_str.lower() not in _GENERIC_OS:
        return _normalize_family(os_str)
    if mfg:
        return _normalize_family(mfg)
    return "Unknown"


async def _check_rate_limit(resp: httpx.Response, page: int, label: str) -> None:
    """Sleep if the Mist rate limit budget is running low.

    Falls back to a per-request throttle (0.8s/call ≈ 4500/hr) when the API
    does not return rate limit headers.
    """
    if page == 1:
        rl_headers = {
            k: v for k, v in resp.headers.items()
            if "ratelimit" in k.lower() or "retry" in k.lower()
        }
        log.info(f"[{label}] Rate limit headers on page 1: {rl_headers or 'NONE'}")

    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset_at = resp.headers.get("X-RateLimit-Reset")
    if remaining is None:
        await asyncio.sleep(0.8)
        return
    remaining = int(remaining)
    if remaining > 200:
        return
    wait = max(float(reset_at) - time.time(), 1.0) if reset_at else 60.0
    log.warning(
        f"[{label}] Rate limit low: {remaining} calls remaining after page {page}. "
        f"Sleeping {wait:.0f}s until reset."
    )
    await asyncio.sleep(wait)


def _build_client_record(client: dict, mac: str = "") -> dict:
    # last_model / last_os / last_device are scalar strings in the enriched search results.
    # The raw client record may also have array fields; prefer last_* scalars.
    #
    # When Mist returns no mfg, supplement with a local OUI lookup so that
    # classify_family() has something to match against (e.g. "Awair" IoT devices
    # that Mist tracks as clients but has no manufacturer string for).
    _mfg_raw = (client.get("mfg") or "").strip()
    # Treat Mist's placeholder strings as empty — they carry no information.
    _MFG_PLACEHOLDERS = {"unknown", "unknown manufacturer", "private", ""}
    mfg = "" if _mfg_raw.lower() in _MFG_PLACEHOLDERS else _mfg_raw
    if not mfg and mac:
        oui_result = oui_lookup(mac)
        if oui_result != "Unknown":
            mfg = oui_result
    # Inject resolved mfg back into the dict so classify_family sees it.
    enriched_client = dict(client)
    if mfg:
        enriched_client["mfg"] = mfg
    # The Mist clients/search endpoint exposes the most recent authenticated
    # username for each client in `last_username`. Captured here so that
    # feature engineering can roll up shared usernames into service-account
    # device families (see feature_engineer.build_features).
    last_username = (client.get("last_username") or "").strip()
    return {
        "family": classify_family(enriched_client),
        "model": client.get("last_model") or "",
        "os": client.get("last_os") or "",
        "manufacturer": mfg or client.get("mfg") or "",
        "random_mac": client.get("random_mac", False),
        "last_ssid": client.get("last_ssid") or "",
        "last_ap": client.get("last_ap") or "",
        "last_site_id": client.get("site_id") or "",
        "last_username": last_username,
    }


async def fetch_all_clients_org(org_id: str, on_page=None) -> list[dict]:
    """Fetch all clients across the entire org via a single API call.

    Uses the org-level endpoint which returns every client with ``site_id``
    on each record.  Same cursor pagination pattern as the per-site variant.

    ``on_page`` is an optional async callable invoked after each page with
    ``(page_number, total_clients_fetched, total_hint)``. ``total_hint`` is
    the ``total`` field from the Mist API response (the full record count the
    paginated stream will eventually yield), so callers can project how many
    pages remain and drive a progress bar off concrete work rather than a
    heuristic.
    """
    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{org_id}/clients/search?limit=1000"
    all_clients: list[dict] = []
    page = 0
    total_hint: int | None = None
    async with httpx.AsyncClient(timeout=30.0) as client:
        while url:
            resp = await client.get(url, headers=_auth_headers())
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("results", [])
            # Capture total record count the first time the API reports it —
            # Mist does not necessarily include it on every page, so latch the
            # first value we see and keep using it.
            if total_hint is None and "total" in data:
                total_hint = data["total"]
            all_clients.extend(batch)
            page += 1
            log.info(
                "Org clients page: %d records, total so far: %d (api total=%s)",
                len(batch), len(all_clients), total_hint,
            )
            if on_page is not None:
                try:
                    await on_page(page, len(all_clients), total_hint)
                except Exception:
                    log.exception("on_page callback failed during org client fetch")
            await _check_rate_limit(resp, page, "clients org")
            next_path = data.get("next")
            url = f"https://{MIST_CLOUD_HOST}{next_path}" if next_path else None
    log.info("Org client fetch complete: %d total clients", len(all_clients))
    return all_clients


async def refresh_client_cache_org(org_id: str, on_page=None) -> int:
    """Fetch all clients org-wide in one API call, classify, and store per-org.

    Each client record from the org endpoint carries a ``site_id`` field which
    is preserved on the row as ``last_site_id`` so the dashboard can still show
    "clients at site X". The MAC remains the unique key — the same MAC seen at
    a different site later in the day overwrites the previous record on the
    next refresh.

    Always writes to SQLite — even when the API returns zero clients — so that
    subsequent ``get_client_cache`` calls can distinguish "cache populated but
    empty" from "cache never written".

    Returns the total number of client rows stored.
    """
    clients = await fetch_all_clients_org(org_id, on_page=on_page)

    lookup: dict[str, dict] = {}
    for c in clients:
        mac = (c.get("mac") or "").replace(":", "").lower()
        if not mac:
            continue
        lookup[mac] = _build_client_record(c, mac)

    count = await db.upsert_clients_org(org_id, lookup)
    if lookup:
        log.info("Org client cache refresh complete: %d clients", count)
    else:
        log.warning("No clients returned for org %s — empty cache written", org_id)
    return count


async def get_client_cache() -> dict[str, dict] | None:
    """
    Load the org-wide client cache from SQLite.

    Returns:
      None  -- never refreshed (refresh_client_cache_org has not run).
      {}    -- refreshed but zero clients (empty org, or API returned nothing).
      {...} -- normal populated cache: MAC -> {family, model, os, manufacturer, ...}

    Callers that must distinguish "never refreshed" from "refreshed but empty"
    should check ``if result is None`` rather than ``if not result``.
    """
    if not MIST_ORG_ID:
        log.error("MIST_ORG_ID not configured — client cache cannot be loaded")
        return None
    return await db.get_org_client_cache(MIST_ORG_ID)

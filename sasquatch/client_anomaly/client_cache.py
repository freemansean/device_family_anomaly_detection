"""
client_cache.py — Daily client device lookup table refresh.

Pulls all clients for the configured org from the Mist API, classifies each
into a device family, and stores MAC -> metadata in SQLite. The cache is
org-scoped: MACs uniquely identify clients across the entire organization, so
event enrichment loads one org-wide map regardless of which site emitted the
event.
"""

import asyncio
import json
import logging
import os
import re
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


# Corporate suffixes stripped from manufacturer strings so "Apple", "Apple Inc",
# and "Apple Inc." all collapse to the same token. Order matters for the regex —
# longer multi-word suffixes must be tried before shorter ones.
_CORP_SUFFIX_RE = re.compile(
    r"[,.\s]+("
    r"incorporated|corporation|technologies|electronics|international"
    r"|company|limited|holdings|systems"
    r"|inc|llc|ltd|gmbh|co|corp|sa|ag|nv|bv|plc|kk|srl|oy|ab"
    r")\.?$",
    re.IGNORECASE,
)

# Mist placeholder strings that carry no fingerprint information.
_PLACEHOLDER_TOKENS = {
    "", "unknown", "unknown manufacturer", "private",
    "iot", "iot device", "embedded", "other", "n/a", "none", "null",
}


def _clean_token(value: str) -> str:
    """Strip corporate suffixes, punctuation, and collapse whitespace.

    "Apple, Inc." → "Apple"
    "Zebra Technologies Inc" → "Zebra"
    "Hewlett-Packard Company" → "Hewlett-Packard"
    """
    if not value:
        return ""
    cleaned = value.strip().rstrip(".,;:")
    # Repeatedly strip suffixes so "Foo Technologies, Inc." → "Foo".
    for _ in range(4):
        new = _CORP_SUFFIX_RE.sub("", cleaned).strip().rstrip(".,;:")
        if new == cleaned:
            break
        cleaned = new
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if cleaned.lower() in _PLACEHOLDER_TOKENS:
        return ""
    return cleaned


def unknown_family_label(mfg: str) -> str:
    """Build the ``Unknown/<vendor>`` sub-bucket label used as a fallback
    family when Mist gives us no fingerprint fields.

    Accepts the raw IEEE OUI manufacturer string (or anything else): trims
    corporate suffixes the cheap way (split at the first comma) and caps the
    visible label at 24 chars on a word boundary so peer-group keys stay
    readable in the GUI. Returns the bare ``"Unknown"`` string when the input
    has no usable signal — collapsing every signal-free MAC into one bucket
    is correct, since they have nothing else in common.

    Shared between ``client_cache._build_client_record`` (cache-write path)
    and ``event_collector._enrich_event`` (cache-miss path) so the two
    paths can never drift.
    """
    raw = (mfg or "").strip()
    if not raw or raw.lower() in {"unknown", ""}:
        return "Unknown"
    # Drop everything from the first comma ("Nokia ..., Ltd." → "Nokia ...").
    base = raw.split(",")[0].strip()
    if not base:
        return "Unknown"
    if len(base) > 24:
        # Truncate at the last word boundary within 24 chars so the key
        # doesn't end mid-word (e.g. "Extreme Networks" not "Extreme Network").
        base = base[:24].rsplit(" ", 1)[0] or base[:24]
    return f"Unknown/{base}"


def _os_major(os_str: str) -> str:
    """Collapse OS strings to major-version granularity.

    "iOS 17.2.1" → "iOS 17"
    "Windows 11.0.22631" → "Windows 11"
    "macOS 14.4" → "macOS 14"
    "Android 13" → "Android 13"
    "iPadOS" → "iPadOS"
    """
    cleaned = (os_str or "").strip()
    if not cleaned or cleaned.lower() in _PLACEHOLDER_TOKENS:
        return ""
    # Match "<name> <major>[.<rest>]" — keep name + major only.
    m = re.match(r"^(.*?)[\s_-]+(\d+)(?:[._]\d+)*\b", cleaned)
    if m:
        name = m.group(1).strip()
        major = m.group(2)
        return f"{name} {major}".strip()
    return cleaned


def classify_family(client: dict) -> str:
    """Build a device family key from Mist fingerprint fields.

    Priority: a unique combination of Manufacturer → Model → OS (major version)
    when Mist provides them. Tokens are joined with " | " so the field count
    is visually obvious and 2-field composites stay distinct from 3-field ones.

    Falls back to a single-token family (manufacturer or OS alone) when Mist
    only provides one field, or to the OUI-derived manufacturer that
    `_build_client_record()` injects as `mfg` when Mist provides nothing.

    Last resort: when nothing survives cleaning (raw mfg was "Private", OS
    was "iot", every field was empty, etc.), bucket the device under
    ``Unknown/<raw_mfg>`` if there is any raw mfg signal at all — that
    keeps Apple-block private MACs from colliding with Cisco-block private
    MACs in the alerts feed. Only when there is literally no manufacturer
    signal does the family collapse to bare ``"Unknown"``.
    """
    mfg = _clean_token(client.get("mfg") or "")
    model = _clean_token(client.get("last_model") or "")
    os_str = _os_major(client.get("last_os") or "")
    # last_device is a coarse type label ("Phone", "Laptop") — use it only as
    # a model fallback when Mist omits the specific model string.
    if not model:
        model = _clean_token(client.get("last_device") or "")

    parts = [p for p in (mfg, model, os_str) if p]
    if parts:
        return " | ".join(parts)
    return unknown_family_label(
        client.get("mfg") or client.get("mfg_fallback") or ""
    )


def is_bare_one_token_family(name: str | None) -> bool:
    """True if `name` is a single-token family (no ' | ' separator) that is
    neither a truly-empty ``Unknown``/``Unknown/<mfg>`` bucket nor a virtual
    family (service account, MFG rollup).

    Bare-1-token families are coverage artifacts: Mist only resolved the
    manufacturer (or the OS/device token) for these MACs, typically because
    the device never fully connected. They are suppressed from family-level
    detector rollups — the MAC still participates in the detector passes
    and carries its own per-MAC flags, but the "family" doesn't earn a
    DBSCAN / IF / Markov badge of its own.
    """
    if not name:
        return False
    if " | " in name:
        return False
    if name == "Unknown" or name.startswith("Unknown/"):
        return False
    # Virtual families carry their own suffixes — never treat them as bare.
    if name.endswith(".service_account") or name.endswith("-MFG"):
        return False
    return True


# Single-token OS / device labels that unambiguously imply a manufacturer when
# Mist omits the mfg field. Kept strict on purpose — only resolve families
# where the back-assignment is obvious. Anything ambiguous stays unresolved
# and that MAC contributes no MFG rollup record.
_OS_DEVICE_TO_MFG: dict[str, str] = {
    # Apple ecosystem
    "iOS": "Apple",
    "iPadOS": "Apple",
    "macOS": "Apple",
    "tvOS": "Apple",
    "watchOS": "Apple",
    "iPhone": "Apple",
    "iPad": "Apple",
    "Mac": "Apple",
    "MacBook": "Apple",
    "MacBook Pro": "Apple",
    "MacBook Air": "Apple",
    "Apple TV": "Apple",
    "Apple OS": "Apple",
    # Google / Android
    "Android": "Google",
}


def _strip_version_suffix(token: str) -> str:
    """Collapse 'iOS 17', 'Android 10', 'macOS 14' to their bare labels for
    manufacturer back-resolution lookup."""
    if not token:
        return ""
    return re.sub(r"\s+\d+(?:[._]\d+)*\s*$", "", token.strip())


def resolve_manufacturer_from_family(device_family: str, device_manufacturer: str = "") -> str:
    """Back-resolve manufacturer from an enriched-event row.

    Events carry ``device_manufacturer`` (populated from the client cache at
    enrichment time) and ``device_family`` (the composite fingerprint label).
    This helper prefers the explicit manufacturer when present, and falls back
    to tokenizing ``device_family`` through the same strict back-resolve map
    used by ``resolve_manufacturer`` — so a bare ``"iPhone"`` family resolves
    to ``"Apple"`` even when the event row has no mfg field.

    Returns '' if nothing resolves.
    """
    mfg = _clean_token(device_manufacturer or "")
    if mfg:
        return mfg
    if not device_family:
        return ""
    # Ignore HIDDEN families — they have no manufacturer signal to speak of.
    if device_family == "Unknown" or device_family.startswith("Unknown/"):
        return ""
    parts = [p.strip() for p in device_family.split(" | ") if p.strip()]
    if not parts:
        return ""
    # Multi-token family: the first token IS the manufacturer by construction
    # (classify_family builds "mfg | model | os").
    if len(parts) > 1:
        return _clean_token(parts[0])
    # Bare one-token family. First check if the token is a known OS / device
    # label that back-resolves to a vendor (iOS → Apple, Android → Google).
    # If not, the token itself is the manufacturer — that's how a bare-1-token
    # family is built in the first place.
    token = parts[0]
    pseudo = {"mfg": "", "last_os": token, "last_model": token, "last_device": token}
    vendor = resolve_manufacturer(pseudo)
    if vendor:
        return vendor
    return _clean_token(token)


def resolve_manufacturer(client: dict) -> str:
    """Return the normalized manufacturer string to use for -MFG bucketing,
    or '' when nothing resolves.

    Priority:
      1. Cleaned ``mfg`` field (already the normal fingerprint path).
      2. OUI-derived manufacturer when Mist omitted the mfg (the enricher
         path in ``_build_client_record`` injects this back as ``mfg``, but
         callers holding a raw event row use ``device_manufacturer``).
      3. Back-resolve from a known OS/device token (``iOS 17`` → Apple,
         ``Android 10`` → Google). Strict whitelist — see ``_OS_DEVICE_TO_MFG``.

    Kept deliberately conservative. Any OS we can't attribute with confidence
    stays unresolved, and the MAC gets no -MFG record that cycle.
    """
    mfg = _clean_token(client.get("mfg") or client.get("device_manufacturer") or "")
    if mfg:
        return mfg

    # Back-resolve from the OS string or the device token. Try the raw label
    # first (handles "iPadOS"), then strip trailing version numbers ("iOS 17"
    # → "iOS").
    for raw in (client.get("last_os"), client.get("last_model"), client.get("last_device")):
        if not raw:
            continue
        token = _clean_token(str(raw))
        if not token:
            continue
        if token in _OS_DEVICE_TO_MFG:
            return _OS_DEVICE_TO_MFG[token]
        stripped = _strip_version_suffix(token)
        if stripped in _OS_DEVICE_TO_MFG:
            return _OS_DEVICE_TO_MFG[stripped]

    return ""


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
    # Treat Mist's placeholder strings as empty for the *primary* mfg slot —
    # they carry no fingerprint signal — but keep the original around as
    # `_mfg_fallback` so classify_family can still use it as an Unknown/<bucket>
    # sub-key when nothing else survives.
    _MFG_PLACEHOLDERS = {"unknown", "unknown manufacturer", "private", ""}
    mfg = "" if _mfg_raw.lower() in _MFG_PLACEHOLDERS else _mfg_raw
    _mfg_fallback = ""
    if not mfg and mac:
        oui_result = oui_lookup(mac)
        if oui_result != "Unknown":
            mfg = oui_result
        else:
            # OUI gave us nothing usable either. Keep the raw Mist mfg
            # ("Private", etc.) as a fallback so we don't collapse every
            # signal-free MAC into a single bucket.
            _mfg_fallback = _mfg_raw
    # Inject resolved mfg back into the dict so classify_family sees it.
    enriched_client = dict(client)
    if mfg:
        enriched_client["mfg"] = mfg
    elif _mfg_fallback:
        enriched_client["mfg_fallback"] = _mfg_fallback
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
    # Hard ceiling — 10k pages × 1000/page = 10M clients, far larger than any real org.
    # Guards against a malformed circular `next` cursor from Mist.
    _MAX_PAGES = 10000
    async with httpx.AsyncClient(timeout=30.0) as client:
        while url:
            if page >= _MAX_PAGES:
                raise RuntimeError(
                    f"Org client pagination exceeded {_MAX_PAGES} pages — aborting. "
                    f"Last URL: {url[:200]}"
                )
            resp = await client.get(url, headers=_auth_headers())
            resp.raise_for_status()
            try:
                data = resp.json()
            except json.JSONDecodeError as exc:
                snippet = resp.text[:200] if resp.text else "<empty>"
                raise RuntimeError(
                    f"Org client fetch: non-JSON response on page {page + 1}: {exc}. "
                    f"Body prefix: {snippet}"
                ) from exc
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

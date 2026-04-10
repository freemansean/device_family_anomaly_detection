"""
feature_engineer.py — Per-MAC feature vector construction.

DESIGN PRINCIPLE: Volume is not anomaly.
The ML models receive ratio/timing features ONLY — not raw counts.
All features are normalized so that active clients are not penalized for being active.

Feature vector — event category frequency vector + concentration features:
  - 13 dimensions: one per event category (all EVENT_CATEGORIES except COLLABORATION).
    Value = fraction of this MAC's events that fall in that category.
    Zero-filled for categories with no events.
    The category dimensions always sum to 1.0.
  - 2 concentration features: top_category_fraction, top_failure_category_fraction

Post-hoc explainer features are computed separately, only for flagged MACs.

Redis key scheme:
  sasquatch:features:{site_id}:{wlan_key}
  where wlan_key is a sanitized SSID name.
"""

import json
import logging
import math
import os
import statistics  # used by build_posthoc_features
from collections import Counter, defaultdict

import redis.asyncio as aioredis

from .event_collector import (
    EVENT_CATEGORIES,
    MIST_CLIENT_EVENT_TYPES,
    get_events,
    sanitize_wlan_key,
)

from . import config
from . import db as _db

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# Service-account dual-family identifiers.
#
# A MAC that belongs to a qualifying service-account username is emitted into
# the feature dict TWICE: once under its real MAC (primary record, real device
# family like "MacBook"), and once under a composite key built by `sa_record_key`
# with `device_family = "{label}.service_account"`. The two records share the
# same vector but are scored under different family groups so the device-family
# detection passes treat them independently.
#
# Downstream code identifies sa records by:
#   - is_sa_record_key(key)         — composite key form, used in features dict
#   - is_service_account_family(name) — family-name suffix check
#   - underlying_mac(key)            — strip the suffix to recover the real MAC
# ─────────────────────────────────────────────────────────────────────
SERVICE_ACCOUNT_SUFFIX = ".service_account"
_SA_KEY_SUFFIX = "#sa"


def sa_record_key(mac: str) -> str:
    """Composite features-dict key for a MAC's service-account record."""
    return f"{mac}{_SA_KEY_SUFFIX}"


def is_sa_record_key(key: str) -> bool:
    """True if a features-dict key is the service-account variant of a MAC."""
    return key.endswith(_SA_KEY_SUFFIX)


def underlying_mac(key: str) -> str:
    """Strip the sa suffix from a composite key to recover the real MAC."""
    if is_sa_record_key(key):
        return key[: -len(_SA_KEY_SUFFIX)]
    return key


def is_service_account_family(name: str | None) -> bool:
    """True if a device-family name is a virtual service-account family."""
    return bool(name) and name.endswith(SERVICE_ACCOUNT_SUFFIX)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
FEATURES_TTL = 24 * 3600

# For post-hoc explainer
DHCP_SUCCESS_TYPES = {"CLIENT_IP_ASSIGNED", "CLIENT_IPV6_ASSIGNED"}
ROAM_FAILURE_TYPES = {
    "MARVIS_EVENT_CLIENT_FBT_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",
    "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
}

# Collaboration events are excluded from the ML feature vector.
# They are application-layer signals (Zoom/Teams calls, CPU spikes) that have no
# bearing on network connectivity behaviour and are absent for most device types,
# which would create spurious anomaly signal against devices that do have them.
_COLLABORATION_EVENT_TYPES: frozenset[str] = frozenset(EVENT_CATEGORIES["COLLABORATION"])

# Event categories used as ML input dimensions — collaboration excluded.
_ML_CATEGORIES: list[str] = [cat for cat in EVENT_CATEGORIES if cat != "COLLABORATION"]

# Failure-class categories — used for failure concentration scoring and feature weighting.
_FAILURE_CATEGORIES: frozenset[str] = frozenset({
    "DHCP_FAILURE", "DNS_FAILURE", "AUTH_FAILURE", "ROAM_FAILURE", "ARP_FAILURE"
})

# Canonical feature key ordering — guarantees vector consistency across MACs and runs.
# Category dimensions first (in _ML_CATEGORIES order), then concentration.
FEATURE_KEYS: list[str] = _ML_CATEGORIES + ["top_category_fraction", "top_failure_category_fraction"]


def _features_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:features:{site_id}:{sanitize_wlan_key(wlan)}"


def _family_event_counts_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:family_event_counts:{site_id}:{sanitize_wlan_key(wlan)}"


def build_mac_feature_vector(mac_events: list[dict]) -> dict[str, float]:
    """
    Build the ML input feature vector for a single MAC.

    Dimensions:
      [0–N-1]  One frequency per event category (excluding COLLABORATION):
               count of events in that category / total non-collaboration events.
               Zero-filled for categories with no events. Dimensions sum to 1.0.
      [N, N+1] top_category_fraction, top_failure_category_fraction
    """
    if not mac_events:
        return {k: 0.0 for k in FEATURE_KEYS}

    # Strip collaboration events — they are not network signals and are absent for most
    # device types, so including them would create spurious cross-device anomaly signal.
    ml_events = [e for e in mac_events if e.get("type") not in _COLLABORATION_EVENT_TYPES]
    if not ml_events:
        return {k: 0.0 for k in FEATURE_KEYS}

    total = len(ml_events)
    type_counts: Counter = Counter(e.get("type", "") for e in ml_events)

    vec: dict[str, float] = {}

    # Per-category normalized frequency.
    for cat in _ML_CATEGORIES:
        cat_count = sum(type_counts.get(t, 0) for t in EVENT_CATEGORIES.get(cat, []))
        vec[cat] = cat_count / total

    # Concentration features — amplify signal for clients stuck in a single-category loop.
    vec["top_category_fraction"] = max(vec[cat] for cat in _ML_CATEGORIES)
    vec["top_failure_category_fraction"] = max(
        (vec[cat] for cat in _FAILURE_CATEGORIES), default=0.0
    )

    return vec


def build_posthoc_features(mac_events: list[dict]) -> dict:
    """
    Post-hoc explainer features — computed only for flagged MACs.
    Encodes domain knowledge about healthy chain patterns.
    NOT fed to ML models.
    """
    if not mac_events:
        return {}

    total = len(mac_events)
    type_counts: Counter = Counter(e.get("type", "") for e in mac_events)

    # PMKID failures: CLIENT_REASSOCIATION_FAILURE with status_code 53
    pmkid_failure_count = sum(
        1
        for e in mac_events
        if e.get("type") == "CLIENT_REASSOCIATION_FAILURE"
        and e.get("status_code") == 53
    )

    # GAS/ANQP timeout: MARVIS_EVENT_CLIENT_AUTH_FAILURE with status_code 62
    gas_timeout_count = sum(
        1
        for e in mac_events
        if e.get("type") == "MARVIS_EVENT_CLIENT_AUTH_FAILURE"
        and e.get("status_code") == 62
    )

    # Unique DHCP transaction IDs (deduplicates retransmits)
    dhcp_xids = {
        e.get("dhcp_xid")
        for e in mac_events
        if e.get("type") in DHCP_SUCCESS_TYPES and e.get("dhcp_xid") is not None
    }
    dhcp_unique_xid_count = len(dhcp_xids)

    # DHCP burst detection
    dhcp_success_timestamps = sorted(
        e.get("timestamp", 0)
        for e in mac_events
        if e.get("type") in DHCP_SUCCESS_TYPES
    )
    dhcp_success_count = len(dhcp_success_timestamps)

    BURST_WINDOW = 300  # 5 minutes in seconds
    dhcp_max_burst_5min = 0
    for i, t_start in enumerate(dhcp_success_timestamps):
        burst = sum(1 for t in dhcp_success_timestamps[i:] if t - t_start <= BURST_WINDOW)
        if burst > dhcp_max_burst_5min:
            dhcp_max_burst_5min = burst

    if dhcp_success_count >= 2:
        gaps = [
            dhcp_success_timestamps[i + 1] - dhcp_success_timestamps[i]
            for i in range(dhcp_success_count - 1)
        ]
        dhcp_median_gap_seconds = statistics.median(gaps)
    else:
        dhcp_median_gap_seconds = -1

    dns_ok_count = type_counts.get("CLIENT_DNS_OK", 0)
    dns_to_dhcp_xid_ratio = (
        dns_ok_count / dhcp_unique_xid_count if dhcp_unique_xid_count > 0 else 0.0
    )

    roam_failure_types_seen = {
        e.get("type") for e in mac_events if e.get("type") in ROAM_FAILURE_TYPES
    }

    if type_counts:
        top_event_type, top_count = type_counts.most_common(1)[0]
        top_event_fraction = top_count / total
    else:
        top_event_type = ""
        top_event_fraction = 0.0

    auth_success = sum(
        type_counts.get(t, 0)
        for t in [
            "CLIENT_AUTHENTICATED",
            "CLIENT_AUTH_ASSOCIATION",
            "CLIENT_AUTH_ASSOCIATION_11R",
            "CLIENT_AUTH_ASSOCIATION_OKC",
        ]
    )
    auth_failure = sum(
        type_counts.get(t, 0)
        for t in [
            "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
            "MARVIS_EVENT_CLIENT_AUTH_DENIED",
            "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
        ]
    )
    auth_total = auth_success + auth_failure
    auth_fail_recovery_ratio = auth_success / auth_total if auth_total > 0 else 1.0

    category_counts: Counter = Counter(e.get("event_category", "OTHER") for e in mac_events)
    category_ratios = {
        f"cat_ratio_{cat.lower()}": category_counts.get(cat, 0) / total
        for cat in EVENT_CATEGORIES
    }

    return {
        "pmkid_failure_count": pmkid_failure_count,
        "gas_timeout_count": gas_timeout_count,
        "dhcp_unique_xid_count": dhcp_unique_xid_count,
        "dhcp_max_burst_5min": dhcp_max_burst_5min,
        "dhcp_median_gap_seconds": dhcp_median_gap_seconds,
        "dns_to_dhcp_xid_ratio": dns_to_dhcp_xid_ratio,
        "roam_failure_types": list(roam_failure_types_seen),
        "top_event_type": top_event_type,
        "top_event_fraction": top_event_fraction,
        "auth_fail_recovery_ratio": auth_fail_recovery_ratio,
        **category_ratios,
    }


async def build_features(site_id: str, wlan: str) -> int:
    """
    Read events from the global Redis sorted set (filtered by site and WLAN),
    build per-MAC feature vectors, store in Redis.

    Returns count of MACs processed.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        events = await get_events(site_id=site_id, wlan=wlan)
        if not events:
            raise RuntimeError(
                f"No events found for site {site_id} / wlan={wlan}. "
                "Run event_collector.collect() first."
            )

        # Group events by MAC up-front — every downstream pass uses this map.
        mac_events: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            mac = (event.get("mac") or "").replace(":", "").lower()
            if mac:
                mac_events[mac].append(event)

        # ── Service-account family lookup (org-wide, evaluated once per build) ──
        # Pulls normalized usernames that ≥ N distinct client rows share across
        # the entire org. Each qualifying entry maps to a display label that
        # becomes the virtual family name "{label}.service_account". Empty when
        # SERVICE_ACCOUNT_MIN_MACS is 0 or when no clusters cross the threshold.
        sa_min = config.get("service_account", "service_account_min_macs")
        sa_lookup: dict[str, dict] = {}
        org_id = os.getenv("MIST_ORG_ID", "")
        if sa_min > 0 and org_id:
            try:
                sa_lookup = await _db.get_service_account_usernames(org_id, int(sa_min))
            except Exception:
                log.exception(
                    "service-account lookup failed; skipping virtual family emission"
                )
                sa_lookup = {}

        # Per-MAC pre-pass: compute majority-vote last_username and resolve the
        # service-account virtual family. Done before the family-event-counts
        # aggregator below so events for sa-bound MACs get binned into BOTH
        # their primary family and the virtual sa family in one walk.
        mac_to_username: dict[str, str] = {}
        mac_to_sa_family: dict[str, str] = {}
        for mac, evts in mac_events.items():
            uname_counts: dict[str, int] = {}
            for e in evts:
                u = (e.get("last_username") or "").strip()
                if u:
                    uname_counts[u] = uname_counts.get(u, 0) + 1
            if not uname_counts:
                continue
            last_username = max(uname_counts, key=uname_counts.__getitem__)
            mac_to_username[mac] = last_username
            if not sa_lookup:
                continue
            uname_norm = _db.normalize_username(last_username)
            sa_entry = sa_lookup.get(uname_norm) if uname_norm else None
            if sa_entry:
                mac_to_sa_family[mac] = f"{sa_entry['label']}{SERVICE_ACCOUNT_SUFFIX}"

        # Pre-compute per-family event category counts for the org/family-insights
        # endpoint so it can aggregate across sites without loading raw events per
        # request. Each event contributes to its primary device family and — when
        # the MAC belongs to a qualifying service-account cluster — also to the
        # virtual sa family, so the heatmap surfaces sa families as first-class rows.
        _fam_cat: dict[str, Counter] = defaultdict(Counter)
        _fam_macs: dict[str, set] = defaultdict(set)
        for _evt in events:
            _fam = _evt.get("device_family", "Unknown")
            _cat = _evt.get("event_category", "OTHER")
            _fam_cat[_fam][_cat] += 1
            _mac = (_evt.get("mac") or "").replace(":", "").lower()
            if _mac:
                _fam_macs[_fam].add(_mac)
                _sa_fam = mac_to_sa_family.get(_mac)
                if _sa_fam:
                    _fam_cat[_sa_fam][_cat] += 1
                    _fam_macs[_sa_fam].add(_mac)
        family_counts = {
            fam: {
                "total_events": sum(cats.values()),
                "mac_count": len(_fam_macs[fam]),
                "categories": dict(cats),
            }
            for fam, cats in _fam_cat.items()
        }
        await redis_client.set(
            _family_event_counts_redis_key(site_id, wlan),
            json.dumps(family_counts),
            ex=FEATURES_TTL,
        )

        # Build feature vector for each MAC
        features: dict[str, dict] = {}
        skipped = 0
        sa_emitted = 0
        min_mac_events = config.get("general", "anomaly_min_mac_events")
        for mac, evts in mac_events.items():
            if len(evts) < min_mac_events:
                skipped += 1
                continue
            vec = build_mac_feature_vector(evts)
            # Majority-vote device_family across all events for this MAC.
            # Any non-Unknown label beats Unknown — handles MACs whose events span
            # a cache refresh boundary (early events labeled Unknown, later ones correct).
            family_counts_local: dict[str, int] = {}
            for e in evts:
                f = e.get("device_family") or "Unknown"
                family_counts_local[f] = family_counts_local.get(f, 0) + 1
            non_unknown = {f: c for f, c in family_counts_local.items() if not f.startswith("Unknown")}
            if non_unknown:
                device_family = max(non_unknown, key=non_unknown.__getitem__)
            else:
                device_family = max(family_counts_local, key=family_counts_local.__getitem__)

            last_username = mac_to_username.get(mac, "")
            sa_family_name = mac_to_sa_family.get(mac, "")

            volume_concentration_weight = math.log1p(len(evts)) * vec["top_category_fraction"]
            features[mac] = {
                "vector": vec,
                "device_family": device_family,
                "event_count": len(evts),
                "random_mac": evts[0].get("random_mac", False) if evts else False,
                "volume_concentration_weight": volume_concentration_weight,
                "last_username": last_username,
                "service_account_family": sa_family_name,
            }

            # ── Dual-family emission ──
            # Same vector under a composite key with device_family overridden to
            # the virtual service-account label. The two records share weight,
            # event count, and random_mac flag — they are the SAME device viewed
            # under two grouping schemes. anomaly_detector groups by device_family,
            # so the sa record naturally lands in its own family bucket and is
            # scored independently of its physical-device-family peers.
            if sa_family_name:
                features[sa_record_key(mac)] = {
                    "vector": dict(vec),
                    "device_family": sa_family_name,
                    "event_count": len(evts),
                    "random_mac": evts[0].get("random_mac", False) if evts else False,
                    "volume_concentration_weight": volume_concentration_weight,
                    "last_username": last_username,
                    "primary_device_family": device_family,
                    "primary_mac": mac,
                    "is_service_account_record": True,
                }
                sa_emitted += 1

        key = _features_redis_key(site_id, wlan)
        await redis_client.set(key, json.dumps(features), ex=FEATURES_TTL)
        log.info(
            f"Built features for {len(features)} records "
            f"({sa_emitted} service-account dual records) → {key} "
            f"({skipped} skipped with < {min_mac_events} events) [wlan={wlan}]"
        )
        return len(features)

    finally:
        await redis_client.aclose()


async def get_features(site_id: str, wlan: str) -> dict[str, dict] | None:
    """Return the features dict for the given site/wlan, or None if the key doesn't exist.

    Returns {} (empty dict) when build_features ran but no MACs met the event threshold.
    Returns None when build_features has never been run (key missing from Redis).
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_features_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if raw is None:
        return None
    return json.loads(raw)

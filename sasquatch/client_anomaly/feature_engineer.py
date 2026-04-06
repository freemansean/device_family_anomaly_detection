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
  where wlan_key = "__all__" for all WLANs, or a sanitized SSID name.
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

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
FEATURES_TTL = 24 * 3600
MIN_MAC_EVENTS = int(os.getenv("ANOMALY_MIN_MAC_EVENTS", "5"))

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


def _features_redis_key(site_id: str, wlan: str = "__all__") -> str:
    return f"sasquatch:features:{site_id}:{sanitize_wlan_key(wlan)}"


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


async def build_features(site_id: str, wlan: str = "__all__") -> int:
    """
    Read events from the global Redis sorted set (filtered by site and WLAN),
    build per-MAC feature vectors, store in Redis.

    wlan="__all__" uses all events for the site regardless of WLAN.
    Returns count of MACs processed.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        events = await get_events(site_id=site_id, wlan=wlan if wlan != "__all__" else None)
        if not events:
            raise RuntimeError(
                f"No events found for site {site_id} / wlan={wlan}. "
                "Run event_collector.collect() first."
            )

        # Group events by MAC
        mac_events: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            mac = (event.get("mac") or "").replace(":", "").lower()
            if mac:
                mac_events[mac].append(event)

        # Build feature vector for each MAC
        features: dict[str, dict] = {}
        skipped = 0
        for mac, evts in mac_events.items():
            if len(evts) < MIN_MAC_EVENTS:
                skipped += 1
                continue
            vec = build_mac_feature_vector(evts)
            device_family = evts[0].get("device_family", "Unknown") if evts else "Unknown"
            volume_concentration_weight = math.log1p(len(evts)) * vec["top_category_fraction"]
            features[mac] = {
                "vector": vec,
                "device_family": device_family,
                "event_count": len(evts),
                "random_mac": evts[0].get("random_mac", False) if evts else False,
                "volume_concentration_weight": volume_concentration_weight,
            }

        key = _features_redis_key(site_id, wlan)
        await redis_client.set(key, json.dumps(features), ex=FEATURES_TTL)
        log.info(
            f"Built features for {len(features)} MACs → {key} "
            f"({skipped} skipped with < {MIN_MAC_EVENTS} events) [wlan={wlan}]"
        )
        return len(features)

    finally:
        await redis_client.aclose()


async def get_features(site_id: str, wlan: str = "__all__") -> dict[str, dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_features_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return {}
    return json.loads(raw)

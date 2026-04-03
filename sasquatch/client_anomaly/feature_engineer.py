"""
feature_engineer.py — Per-MAC feature vector construction.

DESIGN PRINCIPLE: Volume is not anomaly.
The ML models receive ratio/timing features ONLY — not raw counts.
All features are normalized so that active clients are not penalized for being active.

Feature vector — raw event type frequency vector + timing:
  - N dimensions: one per known event type in MIST_CLIENT_EVENT_TYPES.
    Value = count of that event type for this MAC / total events for this MAC.
    Zero-filled for event types not seen by this client.
    The event type dimensions always sum to 1.0.
  - 2 timing features: median_inter_event_seconds, inter_event_cv

Post-hoc explainer features are computed separately, only for flagged MACs.
Event category buckets (DHCP_SUCCESS, AUTH_FAILURE, etc.) are used only for the
GUI heatmap and post-hoc pattern classification — NOT fed to the ML models.
"""

import json
import logging
import os
import statistics
from collections import Counter, defaultdict

import redis.asyncio as aioredis

from .event_collector import EVENT_CATEGORIES, MIST_CLIENT_EVENT_TYPES

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

# All failure-class event types — used for failure concentration scoring in the ML vector.
_FAILURE_EVENT_TYPES: set[str] = set()
for _cat in ("DHCP_FAILURE", "DNS_FAILURE", "AUTH_FAILURE", "ROAM_FAILURE"):
    _FAILURE_EVENT_TYPES.update(EVENT_CATEGORIES.get(_cat, []))
_FAILURE_EVENT_TYPES.update([
    "CLIENT_ASSOCIATION_FAILURE",
    "CLIENT_REASSOCIATION_FAILURE",
    "CLIENT_GW_ARP_FAILURE",
    "CLIENT_ARP_FAILURE",
    "CLIENT_EXCESSIVE_ARPING_GW",
])

# Canonical feature key ordering — guarantees vector consistency across MACs and runs.
# Event type dimensions first (in MIST_CLIENT_EVENT_TYPES order), then timing and concentration.
FEATURE_KEYS: list[str] = (
    list(MIST_CLIENT_EVENT_TYPES)
    + ["median_inter_event_seconds", "inter_event_cv", "top_event_fraction", "top_failure_event_fraction"]
)


def _inter_event_stats(timestamps: list[float]) -> tuple[float, float]:
    """
    Compute median and coefficient of variation of inter-event gaps.
    Returns (median_seconds, cv) — both 0.0 if fewer than 2 events.
    """
    if len(timestamps) < 2:
        return 0.0, 0.0

    gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    gaps = [g for g in gaps if g > 0]
    if not gaps:
        return 0.0, 0.0

    med = statistics.median(gaps)
    if len(gaps) < 2:
        return med, 0.0

    mean_gap = statistics.mean(gaps)
    if mean_gap == 0:
        return med, 0.0

    cv = statistics.stdev(gaps) / mean_gap
    return med, cv


def build_mac_feature_vector(mac_events: list[dict]) -> dict[str, float]:
    """
    Build the ML input feature vector for a single MAC.

    Dimensions:
      [0–N-1]  One frequency per known event type: count / total events for this MAC.
               Zero-filled for types not seen. Dimensions sum to 1.0.
      [N, N+1] median_inter_event_seconds, inter_event_cv
    """
    if not mac_events:
        return {k: 0.0 for k in FEATURE_KEYS}

    total = len(mac_events)
    type_counts: Counter = Counter(e.get("type", "") for e in mac_events)

    vec: dict[str, float] = {}

    # Per-event-type normalized frequency — no domain bucketing, no human-defined groupings.
    for event_type in MIST_CLIENT_EVENT_TYPES:
        vec[event_type] = type_counts.get(event_type, 0) / total

    # Timing features
    timestamps = sorted(e.get("timestamp", 0) for e in mac_events)
    median_gap, cv = _inter_event_stats(timestamps)
    vec["median_inter_event_seconds"] = median_gap
    vec["inter_event_cv"] = cv

    # Concentration features — amplify signal for clients stuck in a single-event loop.
    # top_event_fraction: how dominated the stream is by any one event type.
    # top_failure_event_fraction: same, but only counting failure-class event types.
    # Both are ratios (0–1), consistent with the volume-neutral design principle.
    vec["top_event_fraction"] = max(vec[t] for t in MIST_CLIENT_EVENT_TYPES)
    top_failure_count = max(
        (type_counts.get(t, 0) for t in _FAILURE_EVENT_TYPES), default=0
    )
    vec["top_failure_event_fraction"] = top_failure_count / total

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

    # DHCP burst detection — distinguishes a storm from routine IP renewal.
    # A client getting an IP every 8 hours is normal lease renewal behaviour.
    # A client getting 10 IPs in 3 minutes is a discard loop.
    #
    # dhcp_max_burst_5min: max CLIENT_IP_ASSIGNED events in any 5-minute sliding window.
    # dhcp_median_gap_seconds: median time between consecutive CLIENT_IP_ASSIGNED events.
    #   -1 sentinel means fewer than 2 events (can't compute gap — not a storm by definition).
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
        dhcp_median_gap_seconds = -1  # sentinel: not enough events to measure cadence

    # DNS to unique DHCP XID ratio — collapses toward 0 in DHCP discard pattern
    dns_ok_count = type_counts.get("CLIENT_DNS_OK", 0)
    dns_to_dhcp_xid_ratio = (
        dns_ok_count / dhcp_unique_xid_count if dhcp_unique_xid_count > 0 else 0.0
    )

    # Roam failure types seen
    roam_failure_types_seen = {
        e.get("type") for e in mac_events if e.get("type") in ROAM_FAILURE_TYPES
    }

    # Top event type
    if type_counts:
        top_event_type, top_count = type_counts.most_common(1)[0]
        top_event_fraction = top_count / total
    else:
        top_event_type = ""
        top_event_fraction = 0.0

    # Auth fail recovery ratio: auth successes / (auth successes + auth failures)
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

    # Category bucket ratios (used for probable_pattern classification in webhook)
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


async def build_features(site_id: str) -> int:
    """
    Read events from Redis, build per-MAC feature vectors, store in Redis.
    Returns count of MACs processed.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw_events = await redis_client.get(f"sasquatch:events:{site_id}")
        if not raw_events:
            raise RuntimeError(
                f"No events found for site {site_id}. Run event_collector.collect() first."
            )
        events: list[dict] = json.loads(raw_events)

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
            features[mac] = {
                "vector": vec,
                "device_family": device_family,
                "event_count": len(evts),
                "random_mac": evts[0].get("random_mac", False) if evts else False,
            }

        key = f"sasquatch:features:{site_id}"
        await redis_client.set(key, json.dumps(features), ex=FEATURES_TTL)
        log.info(
            f"Built features for {len(features)} MACs → {key} "
            f"({skipped} skipped with < {MIN_MAC_EVENTS} events)"
        )
        return len(features)

    finally:
        await redis_client.aclose()


async def get_features(site_id: str) -> dict[str, dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(f"sasquatch:features:{site_id}")
    finally:
        await redis_client.aclose()
    if not raw:
        return {}
    return json.loads(raw)

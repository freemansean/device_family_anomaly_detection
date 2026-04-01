"""
feature_engineer.py — Per-MAC feature vector construction.

DESIGN PRINCIPLE: Volume is not anomaly.
The ML models receive ratio/entropy/timing features ONLY — not raw counts.
All features are normalized so that active clients are not penalized for being active.

Feature vector (14 dimensions) — domain-decomposed health axes:
  - 4 domains × 2 directions: {domain}_healthy_ratio, {domain}_unhealthy_ratio
    Normalized to total MAC events, NOT domain-total. This means:
      - Zero on both = client has no activity in that domain (e.g. IoT device with no DNS)
      - Healthy high, unhealthy near zero = normal
      - Unhealthy high = broken domain
      - Both nonzero = intermittent failure
  - 2 timing features: median_inter_event_seconds, inter_event_cv
  - 4 RSSI/SNR features: rssi_mean, rssi_std, rssi_p10, rssi_trend
    RSSI is tracked independently of event type — pure signal health axis.
    rssi_trend is the linear regression slope of rssi vs normalized time
    (positive = improving signal, negative = degrading).
    Sentinel 0.0 used when no RSSI data available (safe: all real RSSI values are negative).

Post-hoc explainer features are computed separately, only for flagged MACs.
"""

import json
import logging
import os
import statistics
from collections import Counter, defaultdict

import numpy as np
import redis.asyncio as aioredis

from .event_collector import EVENT_CATEGORIES

log = logging.getLogger(__name__)

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

# ---------------------------------------------------------------------------
# Domain axis definitions — the principal components of client health.
# Each axis has a healthy set and an unhealthy set.
# These become the ML feature dimensions.
# ---------------------------------------------------------------------------
DOMAIN_AXES: dict[str, dict[str, set[str]]] = {
    "auth_roam": {
        "healthy": {
            # Initial association
            "CLIENT_AUTHENTICATED",
            "CLIENT_AUTH_ASSOCIATION",
            "CLIENT_AUTH_ASSOCIATION_11R",
            "CLIENT_AUTH_ASSOCIATION_OKC",
            "CLIENT_ASSOCIATION",
            # Fast roam reassociation
            "CLIENT_AUTH_REASSOCIATION",
            "CLIENT_AUTH_REASSOCIATION_11R",
            "CLIENT_AUTH_REASSOCIATION_OKC",
            "CLIENT_REASSOCIATION",
            "CLIENT_REASSOCIATION_PMKC",
        },
        "unhealthy": {
            "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
            "MARVIS_EVENT_CLIENT_AUTH_DENIED",
            "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
            "CLIENT_ASSOCIATION_FAILURE",
            # Roam failures
            "MARVIS_EVENT_CLIENT_FBT_FAILURE",
            "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
            "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",
            "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
        },
    },
    "dhcp": {
        "healthy": {
            "CLIENT_IP_ASSIGNED",
            "CLIENT_IPV6_ASSIGNED",
        },
        "unhealthy": {
            "MARVIS_EVENT_CLIENT_DHCP_NAK",
            "MARVIS_EVENT_CLIENT_DHCPV6_NAK",
            "MARVIS_EVENT_CLIENT_DHCP_FAILURE",
            "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
            "MARVIS_EVENT_CLIENT_DHCP_STUCK",
            "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
            "MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM",
        },
    },
    "dns": {
        "healthy": {"CLIENT_DNS_OK"},
        "unhealthy": {"MARVIS_DNS_FAILURE"},
    },
    "arp": {
        "healthy": {"CLIENT_GW_ARP_OK"},
        "unhealthy": {
            "CLIENT_GW_ARP_FAILURE",
            "CLIENT_ARP_FAILURE",
            "CLIENT_EXCESSIVE_ARPING_GW",
        },
    },
}

# Canonical feature key ordering — used to guarantee vector consistency across MACs and runs.
FEATURE_KEYS: list[str] = (
    [f"{domain}_healthy_ratio" for domain in DOMAIN_AXES]
    + [f"{domain}_unhealthy_ratio" for domain in DOMAIN_AXES]
    + ["median_inter_event_seconds", "inter_event_cv"]
    + ["rssi_mean", "rssi_std", "rssi_p10", "rssi_trend"]
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


def _rssi_features(mac_events: list[dict]) -> dict[str, float]:
    """
    Extract signal health features from the rssi field across all events.
    RSSI is tracked independently of event type — pure RF health axis.
    Sentinel 0.0 for all features when no RSSI data is present.
    """
    # Collect (timestamp, rssi) pairs where rssi is a real number
    readings = [
        (e.get("timestamp", 0), e["rssi"])
        for e in mac_events
        if isinstance(e.get("rssi"), (int, float)) and e["rssi"] != 0
    ]

    if not readings:
        return {"rssi_mean": 0.0, "rssi_std": 0.0, "rssi_p10": 0.0, "rssi_trend": 0.0}

    readings.sort(key=lambda x: x[0])
    timestamps = np.array([r[0] for r in readings], dtype=float)
    rssi_vals = np.array([r[1] for r in readings], dtype=float)

    mean = float(np.mean(rssi_vals))
    std = float(np.std(rssi_vals)) if len(rssi_vals) > 1 else 0.0
    p10 = float(np.percentile(rssi_vals, 10))

    # Linear trend: slope of rssi vs time normalized to [0,1]
    # Positive = signal improving over the 24hr window, negative = degrading
    if len(timestamps) >= 2 and timestamps[-1] > timestamps[0]:
        t_norm = (timestamps - timestamps[0]) / (timestamps[-1] - timestamps[0])
        slope, _ = np.polyfit(t_norm, rssi_vals, 1)
        trend = float(slope)
    else:
        trend = 0.0

    return {"rssi_mean": mean, "rssi_std": std, "rssi_p10": p10, "rssi_trend": trend}


def build_mac_feature_vector(mac_events: list[dict]) -> dict[str, float]:
    """
    Build the 14-dimensional ML input feature vector for a single MAC.

    Dimensions:
      [0–3]  auth_roam_healthy_ratio, dhcp_healthy_ratio, dns_healthy_ratio, arp_healthy_ratio
      [4–7]  auth_roam_unhealthy_ratio, dhcp_unhealthy_ratio, dns_unhealthy_ratio, arp_unhealthy_ratio
      [8–9]  median_inter_event_seconds, inter_event_cv
      [10–13] rssi_mean, rssi_std, rssi_p10, rssi_trend
    """
    if not mac_events:
        return {k: 0.0 for k in FEATURE_KEYS}

    total = len(mac_events)
    type_counts: Counter = Counter(e.get("type", "") for e in mac_events)

    vec: dict[str, float] = {}

    # Domain health axes — each ratio is normalized to total MAC events (not domain total).
    # This preserves the "absent from domain" signal (both ratios == 0 for inactive domains).
    for domain, sets in DOMAIN_AXES.items():
        healthy_count = sum(type_counts.get(t, 0) for t in sets["healthy"])
        unhealthy_count = sum(type_counts.get(t, 0) for t in sets["unhealthy"])
        vec[f"{domain}_healthy_ratio"] = healthy_count / total
        vec[f"{domain}_unhealthy_ratio"] = unhealthy_count / total

    # Timing features
    timestamps = sorted(e.get("timestamp", 0) for e in mac_events)
    median_gap, cv = _inter_event_stats(timestamps)
    vec["median_inter_event_seconds"] = median_gap
    vec["inter_event_cv"] = cv

    # RSSI / SNR features
    vec.update(_rssi_features(mac_events))

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
        for mac, evts in mac_events.items():
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
        log.info(f"Built features for {len(features)} MACs → {key}")
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

"""
health_scorer.py — Per-family health score computation.

Computes a family-level health score (0.0–1.0) from the event category distribution
of all MACs in a family. Score reflects the ratio of successful vs failed events
across the five failure-capable categories (AUTH, DHCP, DNS, ROAM, ARP).

Score of 1.0 = no failures observed.
Score approaching 0.0 = all interactions are failing.

The score is computed from feature vectors already in Redis — no raw event re-read
is required. Each MAC's vector contains normalized category frequencies, which are
multiplied back by event_count to recover volume-weighted totals per category.

Redis key scheme:
  sasquatch:health:{site_id}:{wlan_key}
  where wlan_key is a sanitized SSID name.
"""

import json
import logging
import os
from collections import defaultdict

import redis.asyncio as aioredis

from .event_collector import sanitize_wlan_key
from .feature_engineer import get_features

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
HEALTH_TTL = 24 * 3600

_SUCCESS_CATS = ("AUTH_SUCCESS", "ROAM_SUCCESS", "DHCP_SUCCESS", "DNS_SUCCESS", "ARP_SUCCESS")
_FAILURE_CATS = ("AUTH_FAILURE", "ROAM_FAILURE", "DHCP_FAILURE", "DNS_FAILURE", "ARP_FAILURE")


def _health_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:health:{site_id}:{sanitize_wlan_key(wlan)}"


def _failure_rate(success: float, failure: float) -> float:
    total = success + failure
    return failure / total if total > 0 else 0.0


def _mac_health_score(vec: dict[str, float]) -> tuple[float, dict[str, float]]:
    """
    Compute health score for a single MAC from its feature vector.

    The feature vector contains normalized category frequencies
    (count / total_events). Health is the fraction of outcome-bearing events
    (success + failure across all categories) that were successes. Neutral
    events (DISASSOC, OTHER, etc.) are excluded from the denominator so they
    don't dilute the signal.

    A device whose DHCP is completely failing has health 0.0 regardless of
    whether its auth or roam behavior is fine.

    Returns (health_score, components_dict).
    components contains per-category failure rates (0.0–1.0) for tooltip display.
    """
    total_success = sum(vec.get(cat, 0.0) for cat in _SUCCESS_CATS)
    total_failure = sum(vec.get(cat, 0.0) for cat in _FAILURE_CATS)
    total = total_success + total_failure

    health_score = max(0.0, 1.0 - (total_failure / total)) if total > 0 else 1.0

    components = {
        "auth": _failure_rate(vec.get("AUTH_SUCCESS", 0.0), vec.get("AUTH_FAILURE", 0.0)),
        "roam": _failure_rate(vec.get("ROAM_SUCCESS", 0.0), vec.get("ROAM_FAILURE", 0.0)),
        "dhcp": _failure_rate(vec.get("DHCP_SUCCESS", 0.0), vec.get("DHCP_FAILURE", 0.0)),
        "dns":  _failure_rate(vec.get("DNS_SUCCESS",  0.0), vec.get("DNS_FAILURE",  0.0)),
        "arp":  _failure_rate(vec.get("ARP_SUCCESS",  0.0), vec.get("ARP_FAILURE",  0.0)),
    }
    return health_score, components


def compute_family_health(features: dict[str, dict]) -> dict[str, dict]:
    """
    Compute per-family health scores from MAC feature records.

    Each MAC gets an equal vote regardless of how many events it generated.
    The family health score is the simple mean of per-MAC health scores.
    This prevents a single high-volume misbehaving device from dragging down
    the family score — a single spammer counts as 1/N, not proportional to
    its event volume.

    Returns:
      {
        family: {
          "health_score": float,       # mean per-MAC score: 0.0 (all failing) → 1.0 (no failures)
          "components": {              # mean per-MAC per-category failure rates (0.0–1.0)
            "auth": float,
            "roam": float,
            "dhcp": float,
            "dns":  float,
            "arp":  float,
          },
          "total_events": int,
          "mac_count": int,
        }
      }
    """
    # Group per-MAC scores by family.
    family_scores: dict[str, list[float]] = defaultdict(list)
    family_components: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: {cat: [] for cat in ("auth", "roam", "dhcp", "dns", "arp")}
    )
    family_total_events: dict[str, int] = defaultdict(int)

    for record in features.values():
        vec = record.get("vector", {})
        family = record.get("device_family", "Unknown")

        score, comps = _mac_health_score(vec)
        family_scores[family].append(score)
        for cat, rate in comps.items():
            family_components[family][cat].append(rate)
        family_total_events[family] += record.get("event_count", 0)

    results: dict[str, dict] = {}
    for family, scores in family_scores.items():
        n = len(scores)
        health_score = round(sum(scores) / n, 4)
        components = {
            cat: round(sum(rates) / n, 4)
            for cat, rates in family_components[family].items()
        }
        results[family] = {
            "health_score": health_score,
            "components": components,
            "total_events": family_total_events[family],
            "mac_count": n,
        }

    return results


async def score_health(site_id: str, wlan: str) -> dict[str, dict]:
    """
    Compute and store family health scores for the given site and WLAN scope.
    Reads feature vectors from Redis — feature_engineer.build_features() must
    have run first.

    Returns the health scores dict {family: health_record}.
    """
    features = await get_features(site_id, wlan)
    if not features:
        log.info(f"Health scorer: no features for site {site_id} wlan={wlan} — skipping")
        return {}

    health = compute_family_health(features)

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        key = _health_redis_key(site_id, wlan)
        await redis_client.set(key, json.dumps(health), ex=HEALTH_TTL)
        log.info(
            f"Health scores stored for {len(health)} families → {key} "
            f"[wlan={wlan}]"
        )
    finally:
        await redis_client.aclose()

    return health


async def get_health(site_id: str, wlan: str) -> dict[str, dict]:
    """Read family health scores from Redis. Returns {} if not yet computed."""
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_health_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return {}
    return json.loads(raw)

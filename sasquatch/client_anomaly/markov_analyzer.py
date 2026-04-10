"""
markov_analyzer.py — Markov Chain analysis for client event chains.

Two independent signals collapse to a single `markov_reason` per MAC:

  "anomaly"  — event-level transition scoring (baseline-relative). Episodes are
               segmented at successful association/authentication/roam boundary
               events; each normal-length episode is scored against the site's
               24hr transition baseline; if enough episodes score below the
               log-probability threshold the MAC is flagged.

  "repeated" — stuck-loop detection (baseline-independent). Counts consecutive
               event-type / category pairs across the MAC's whole stream; if a
               failure-involving pair dominates above a threshold the MAC is
               flagged. Catches devices that contaminate their own baseline.

If both fire, "repeated" wins (more concrete diagnosis).

Baseline transition matrices are built from the last 24hr of site/wlan events,
stored in Redis with a 48hr TTL (MARKOV_BASELINE_TTL), and refreshed by the
daily scheduler job.

Redis key:
  sasquatch:markov_baseline:{site_id}:{wlan_key}   TTL 48hr
"""

import json
import logging
import os
import time as _time
from collections import Counter, defaultdict

import numpy as np
import redis.asyncio as aioredis

from . import config
from .event_collector import sanitize_wlan_key, EVENT_CATEGORIES

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# 48hr TTL so the baseline survives across the daily refresh window with margin.
MARKOV_BASELINE_TTL = 48 * 3600

# ---------------------------------------------------------------------------
# Episode boundary events — any of these resets the episode for a client.
# Covers all successful association, authentication, and roam variants.
# ---------------------------------------------------------------------------
EPISODE_BOUNDARY_EVENTS: frozenset[str] = frozenset({
    # Initial auth / association
    "CLIENT_AUTHENTICATED",
    "CLIENT_AUTH_ASSOCIATION",
    "CLIENT_AUTH_ASSOCIATION_11R",
    "CLIENT_AUTH_ASSOCIATION_OKC",
    # Roam / reassociation (success)
    "CLIENT_AUTH_REASSOCIATION",
    "CLIENT_AUTH_REASSOCIATION_11R",
    "CLIENT_AUTH_REASSOCIATION_OKC",
    "CLIENT_REASSOCIATION",
    "CLIENT_REASSOCIATION_PMKC",
    "CLIENT_ASSOCIATION_PMKC",
})


def _cfg(key: str) -> int | float:
    """Shorthand to read an anomaly-section config value at runtime."""
    return config.get("anomaly", key)


# Non-env-controlled threshold (no GUI counterpart; kept as module constant)
MARKOV_EPISODE_LOG_PROB_THRESHOLD = float(
    os.getenv("MARKOV_EPISODE_LOG_PROB_THRESHOLD", "-4.0")
)

# Event types that can form one end of a stuck-loop transition pair.
# At least one of (A→B) must be in this set before the stuck-loop flag triggers,
# preventing high-frequency healthy patterns (e.g. REASSOCIATION → ARP_OK) from firing.
_STUCK_LOOP_FAILURE_TYPES: frozenset[str] = frozenset({
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_DENIED",
    "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCP_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCPV6_FAILURE",
    "MARVIS_EVENT_CLIENT_DHCP_NAK",
    "MARVIS_EVENT_CLIENT_DHCPV6_NAK",
    "MARVIS_EVENT_CLIENT_DHCP_STUCK",
    "MARVIS_EVENT_CLIENT_DHCPV6_STUCK",
    "MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM",
    "MARVIS_DNS_FAILURE",
    "MARVIS_EVENT_CLIENT_FBT_FAILURE",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_OKC",
    "MARVIS_EVENT_CLIENT_AUTH_FAILURE_11R",
    "MARVIS_EVENT_WLC_FT_KEY_NOT_FOUND",
    "CLIENT_DEASSOCIATION",
    "CLIENT_DEAUTHENTICATION",
    "CLIENT_DEAUTHENTICATED",
    "MARVIS_EVENT_STA_LEAVING",
    "CLIENT_GW_ARP_FAILURE",
    "CLIENT_ARP_FAILURE",
    "CLIENT_EXCESSIVE_ARPING_GW",
})

# Reverse mapping: raw event type → category name, built from EVENT_CATEGORIES.
# Used by stuck-loop detection to aggregate transitions at the category level.
_EVENT_TYPE_TO_CATEGORY: dict[str, str] = {
    event_type: category
    for category, event_types in EVENT_CATEGORIES.items()
    for event_type in event_types
}

# Category-level failure classes for stuck-loop detection.
_STUCK_LOOP_FAILURE_CATEGORIES: frozenset[str] = frozenset({
    "DHCP_FAILURE", "DNS_FAILURE", "AUTH_FAILURE", "ROAM_FAILURE",
    "ARP_FAILURE", "DISASSOC",
})


def _baseline_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:markov_baseline:{site_id}:{sanitize_wlan_key(wlan)}"


async def baseline_exists(site_id: str, wlan: str, redis_client) -> bool:
    """Return True if a Markov baseline is stored in Redis for this site/wlan."""
    return bool(await redis_client.exists(_baseline_key(site_id, wlan)))


# ---------------------------------------------------------------------------
# Core segmentation — single pass, preserves temporal order
# ---------------------------------------------------------------------------

def _segment_ordered(mac_events: list[dict]) -> list[list[dict]]:
    """
    Split a MAC's event stream into temporally ordered episodes.

    Each boundary event (successful auth/association/roam) starts a new episode.
    Events before the first boundary event form an initial pre-boundary episode.
    Episodes are non-empty; events are sorted by timestamp before segmentation.
    """
    if not mac_events:
        return []

    sorted_events = sorted(mac_events, key=lambda e: e.get("timestamp", 0))
    episodes: list[list[dict]] = []
    current: list[dict] = []

    for event in sorted_events:
        if event.get("type") in EPISODE_BOUNDARY_EVENTS:
            if current:
                episodes.append(current)
            current = [event]
        else:
            current.append(event)

    if current:
        episodes.append(current)

    return episodes


# ---------------------------------------------------------------------------
# Transition matrix construction
# ---------------------------------------------------------------------------

def build_transition_counts(
    episodes: list[list[dict]],
    event_type_to_idx: dict[str, int],
    n: int,
) -> np.ndarray:
    """
    Build an NxN raw transition count matrix from a list of episodes.
    counts[i][j] is incremented for each consecutive pair (type_i → type_j).
    Unknown event types (not in event_type_to_idx) are silently skipped.
    Returns float64 array of shape (N, N).
    """
    counts = np.zeros((n, n), dtype=np.float64)
    for episode in episodes:
        for k in range(len(episode) - 1):
            i = event_type_to_idx.get(episode[k].get("type", ""))
            j = event_type_to_idx.get(episode[k + 1].get("type", ""))
            if i is not None and j is not None:
                counts[i, j] += 1.0
    return counts


def laplace_smooth_and_normalize(counts: np.ndarray) -> np.ndarray:
    """
    Apply Laplace (add-1) smoothing and row-normalize to produce a row-stochastic
    probability matrix.  After smoothing every cell is >= 1, so no probability is
    ever zero and log-probabilities are always finite.
    """
    smoothed = counts + 1.0
    row_sums = smoothed.sum(axis=1, keepdims=True)
    # Guard against degenerate rows (shouldn't occur after +1 smoothing)
    row_sums = np.where(row_sums == 0.0, 1.0, row_sums)
    return smoothed / row_sums


# ---------------------------------------------------------------------------
# Episode scoring
# ---------------------------------------------------------------------------

def score_episode(
    episode: list[dict],
    log_prob_matrix: np.ndarray,
    event_type_to_idx: dict[str, int],
) -> float:
    """
    Score an episode as the mean log-probability per valid transition.
    Transitions involving unknown event types are skipped.
    Returns 0.0 if the episode has fewer than 2 events or no valid pairs.
    """
    if len(episode) < 2:
        return 0.0
    values: list[float] = []
    for k in range(len(episode) - 1):
        i = event_type_to_idx.get(episode[k].get("type", ""))
        j = event_type_to_idx.get(episode[k + 1].get("type", ""))
        if i is not None and j is not None:
            values.append(log_prob_matrix[i, j])
    return float(np.mean(values)) if values else 0.0


# ---------------------------------------------------------------------------
# Stuck-loop detection (baseline-independent)
# ---------------------------------------------------------------------------

def detect_stuck_loop(mac_events: list[dict]) -> tuple[bool, str | None, float]:
    """
    Detect if a MAC is stuck in a repetitive failure-involving transition loop.

    Two passes:
      1. Raw event-type pairs: catches tight two-event loops like
         AUTH_FAILURE → DEAUTH → AUTH_FAILURE → DEAUTH.
      2. Category-level pairs: catches loops distributed across subtypes, e.g.
         ROAM_SUCCESS (via multiple reassociation types) → ARP_FAILURE (via
         CLIENT_GW_ARP_FAILURE + CLIENT_ARP_FAILURE). Without this, a family
         whose transitions are spread across 6 roam subtypes × 3 ARP subtypes
         would never have a single raw pair reach the threshold.

    In both passes, the single most common pair must account for >=
    _cfg("markov_stuck_loop_threshold") of all transitions AND at least one side must
    be a failure type/category.

    Returns:
      (is_stuck, dominant_pair_label, dominant_pair_fraction)
      dominant_pair_label is "TYPE_A→TYPE_B" or "CAT_A→CAT_B" when stuck.
    """
    if len(mac_events) < _cfg("markov_stuck_loop_min_events"):
        return False, None, 0.0

    sorted_events = sorted(mac_events, key=lambda e: e.get("timestamp", 0))
    pair_counts: Counter = Counter()
    cat_pair_counts: Counter = Counter()
    for k in range(len(sorted_events) - 1):
        a = sorted_events[k].get("type", "")
        b = sorted_events[k + 1].get("type", "")
        if a and b:
            pair_counts[(a, b)] += 1
            cat_a = _EVENT_TYPE_TO_CATEGORY.get(a, "OTHER")
            cat_b = _EVENT_TYPE_TO_CATEGORY.get(b, "OTHER")
            cat_pair_counts[(cat_a, cat_b)] += 1

    total_pairs = sum(pair_counts.values())
    if total_pairs == 0:
        return False, None, 0.0

    # Pass 1: raw event-type pairs
    (top_a, top_b), top_count = pair_counts.most_common(1)[0]
    top_fraction = top_count / total_pairs

    if (
        top_fraction >= _cfg("markov_stuck_loop_threshold")
        and (top_a in _STUCK_LOOP_FAILURE_TYPES or top_b in _STUCK_LOOP_FAILURE_TYPES)
    ):
        return True, f"{top_a}→{top_b}", top_fraction

    # Pass 2: category-level pairs — aggregate subtypes
    (cat_top_a, cat_top_b), cat_top_count = cat_pair_counts.most_common(1)[0]
    cat_top_fraction = cat_top_count / total_pairs

    if (
        cat_top_fraction >= _cfg("markov_stuck_loop_threshold")
        and (cat_top_a in _STUCK_LOOP_FAILURE_CATEGORIES or cat_top_b in _STUCK_LOOP_FAILURE_CATEGORIES)
    ):
        return True, f"{cat_top_a}→{cat_top_b}", cat_top_fraction

    # Pass 3: failure-dominated transitions — catches multi-step failure cycles
    # (3+ events) where no single pair dominates at the threshold but ALL
    # transitions involve failure categories. Example: AUTH_SUCCESS → AUTH_FAILURE
    # → DISASSOC → AUTH_SUCCESS → ... is a 3-step loop where each pair is ~33%,
    # but 2/3 of pairs involve a failure category. A healthy 3-step cycle like
    # AUTH_SUCCESS → ROAM_SUCCESS → ARP_SUCCESS has 0% failure-involving pairs.
    failure_involving_count = sum(
        count for (ca, cb), count in cat_pair_counts.items()
        if ca in _STUCK_LOOP_FAILURE_CATEGORIES or cb in _STUCK_LOOP_FAILURE_CATEGORIES
    )
    failure_transition_fraction = failure_involving_count / total_pairs
    if failure_transition_fraction >= _cfg("markov_stuck_loop_threshold"):
        # Find the dominant failure pair for the label
        failure_pairs = [
            ((ca, cb), count) for (ca, cb), count in cat_pair_counts.items()
            if ca in _STUCK_LOOP_FAILURE_CATEGORIES or cb in _STUCK_LOOP_FAILURE_CATEGORIES
        ]
        (fp_a, fp_b), _ = max(failure_pairs, key=lambda x: x[1])
        return True, f"{fp_a}→{fp_b}", failure_transition_fraction

    return False, None, max(top_fraction, cat_top_fraction)


# ---------------------------------------------------------------------------
# Per-MAC analysis
# ---------------------------------------------------------------------------

def analyze_mac(
    mac_events: list[dict],
    log_prob_matrix: np.ndarray,
    event_type_to_idx: dict[str, int],
) -> dict:
    """
    Run Markov analysis for a single MAC.

    Two independent signals are computed:

      "anomaly"  — event-level: each normal-length episode is scored against the
                   site transition baseline. If scoreable >= min_scoreable AND the
                   ratio of anomalous episodes (score < MARKOV_EPISODE_LOG_PROB_THRESHOLD)
                   exceeds markov_outlier_episode_ratio, fire.

      "repeated" — stuck-loop: baseline-independent dominance of a failure-involving
                   event/category pair across the MAC's full event stream.

    The MAC is flagged (`is_markov_outlier=True`) if either fires. Priority when
    both fire: "repeated" wins (more concrete diagnosis).

    Returns dict with all Markov anomaly fields; see _empty_markov_result() for keys.
    """
    all_episodes = _segment_ordered(mac_events)
    if not all_episodes:
        return _empty_markov_result()

    total_episodes = len(all_episodes)
    normal_episodes = [
        ep for ep in all_episodes if len(ep) >= _cfg("markov_min_episode_length")
    ]
    normal_count = len(normal_episodes)

    # Event-level episode scoring against the baseline
    episode_scores: list[float] = []
    anomalous_count = 0
    for ep in normal_episodes:
        s = score_episode(ep, log_prob_matrix, event_type_to_idx)
        episode_scores.append(s)
        if s < MARKOV_EPISODE_LOG_PROB_THRESHOLD:
            anomalous_count += 1

    scoreable = normal_count
    episode_anomaly_ratio = (
        anomalous_count / scoreable
        if scoreable >= _cfg("markov_min_scoreable_episodes")
        else 0.0
    )
    event_level_anomalous = (
        scoreable >= _cfg("markov_min_scoreable_episodes")
        and episode_anomaly_ratio >= _cfg("markov_outlier_episode_ratio")
    )

    # Stuck-loop detection: baseline-independent, catches devices that dominate
    # the transition matrix with their own failure pattern.
    is_stuck, stuck_pair, stuck_fraction = detect_stuck_loop(mac_events)

    # "repeated" takes priority when both fire — it is the more concrete diagnosis.
    if is_stuck:
        markov_reason: str | None = "repeated"
    elif event_level_anomalous:
        markov_reason = "anomaly"
    else:
        markov_reason = None

    is_outlier = markov_reason is not None

    return {
        "markov_total_episodes": total_episodes,
        "markov_normal_episodes": normal_count,
        "markov_scoreable_episodes": scoreable,
        "markov_anomalous_episodes": anomalous_count,
        "markov_episode_anomaly_ratio": round(episode_anomaly_ratio, 4),
        "is_stuck_loop": is_stuck,
        "stuck_loop_pair": stuck_pair,
        "stuck_loop_fraction": round(stuck_fraction, 4),
        "is_markov_outlier": is_outlier,
        "markov_reason": markov_reason,
        "markov_episode_scores": [round(s, 4) for s in episode_scores],
    }


def _empty_markov_result() -> dict:
    return {
        "markov_total_episodes": 0,
        "markov_normal_episodes": 0,
        "markov_scoreable_episodes": 0,
        "markov_anomalous_episodes": 0,
        "markov_episode_anomaly_ratio": 0.0,
        "is_stuck_loop": False,
        "stuck_loop_pair": None,
        "stuck_loop_fraction": 0.0,
        "is_markov_outlier": False,
        "markov_reason": None,
        "markov_episode_scores": [],
    }


# ---------------------------------------------------------------------------
# Baseline build and load
# ---------------------------------------------------------------------------

async def build_and_store_baseline(
    site_id: str,
    wlan: str,
    event_type_index: list[str],
) -> dict:
    """
    Build the 24hr Markov transition baseline for a site/wlan combination and store
    in Redis under sasquatch:markov_baseline:{site_id}:{wlan_key} (TTL 48hr).

    Uses the last 24 hours of events from SQLite.
    Returns a summary dict {macs, events, normal_episodes}.
    """
    from .event_collector import get_events

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        cutoff_24h = _time.time() - 24 * 3600
        events_24h = await get_events(
            site_id=site_id, wlan=wlan if wlan else None, since=cutoff_24h
        )

        if not events_24h:
            log.info(
                f"[markov baseline] No events in last 24hr for site={site_id} wlan={wlan}"
            )
            return {"macs": 0, "events": 0, "normal_episodes": 0}

        # Group by MAC
        mac_events: dict[str, list[dict]] = defaultdict(list)
        for evt in events_24h:
            mac = (evt.get("mac") or "").replace(":", "").lower()
            if mac:
                mac_events[mac].append(evt)

        n = len(event_type_index)
        event_type_to_idx = {t: i for i, t in enumerate(event_type_index)}

        all_normal_episodes: list[list[dict]] = []
        for mac_evts in mac_events.values():
            for ep in _segment_ordered(mac_evts):
                if len(ep) >= _cfg("markov_min_episode_length"):
                    all_normal_episodes.append(ep)

        event_counts = build_transition_counts(
            all_normal_episodes, event_type_to_idx, n
        )

        baseline = {
            "transition_counts": event_counts.tolist(),
            "event_type_index": event_type_index,
            "computed_at": _time.time(),
            "mac_count": len(mac_events),
            "normal_episode_count": len(all_normal_episodes),
            "site_id": site_id,
            "wlan": wlan,
        }

        key = _baseline_key(site_id, wlan)
        await redis_client.set(key, json.dumps(baseline), ex=MARKOV_BASELINE_TTL)
        log.info(
            "[markov baseline] Built baseline for site=%s wlan=%s: "
            "%d MACs, %d normal episodes → %s",
            site_id, wlan, len(mac_events), len(all_normal_episodes), key,
        )
        return {
            "macs": len(mac_events),
            "events": len(events_24h),
            "normal_episodes": len(all_normal_episodes),
        }
    finally:
        await redis_client.aclose()


async def load_baseline(
    site_id: str,
    wlan: str,
    redis_client,
) -> tuple[np.ndarray, list[str]] | None:
    """
    Load the event-level baseline matrix from Redis.
    Returns (log_prob_matrix, event_type_index) or None if absent.

    Older baselines stored an `episode_transition_counts` field that has been
    removed; it is silently ignored if present so existing keys keep loading.
    """
    key = _baseline_key(site_id, wlan)
    raw = await redis_client.get(key)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        event_type_index: list[str] = data["event_type_index"]
        counts = np.array(data["transition_counts"], dtype=np.float64)
        log_prob_matrix = np.log(laplace_smooth_and_normalize(counts))
        return log_prob_matrix, event_type_index
    except Exception as exc:
        log.warning(
            "[markov baseline] Failed to deserialize baseline for site=%s wlan=%s: %s",
            site_id, wlan, exc,
        )
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_markov_analysis(
    site_id: str,
    wlan: str,
    mac_raw_events: dict[str, list[dict]],
    family_groups: dict[str, list[str]],
    redis_client,
    event_type_index: list[str],
) -> dict:
    """
    Run full Markov Chain analysis for all MACs in a site/wlan scope.

    If no baseline exists in Redis (first deployment), Markov scoring is skipped:
    all MACs receive is_markov_outlier=False.  The daily baseline job will populate
    the baseline within 24 hours for use in subsequent detection cycles.

    Returns:
      {mac: markov_record, ..., "__family_markov__": {family: family_markov_record}}

    family_markov_record fields:
      is_family_markov_outlier, markov_family_reason,
      markov_family_anomaly_ratio, markov_evaluatable_count,
      markov_family_anomalous_count
    """
    baseline = await load_baseline(site_id, wlan, redis_client)

    if baseline is None:
        log.info(
            "[markov] No baseline for site=%s wlan=%s — skipping Markov scoring "
            "(run markov_baseline_job to populate)",
            site_id, wlan,
        )
        empty = {mac: _empty_markov_result() for mac in mac_raw_events}
        empty["__family_markov__"] = {
            family: {
                "is_family_markov_outlier": False,
                "markov_family_reason": None,
                "markov_family_anomaly_ratio": 0.0,
                "markov_evaluatable_count": 0,
                "markov_family_anomalous_count": 0,
            }
            for family in family_groups
        }
        return empty

    log_prob_matrix, baseline_event_type_index = baseline
    # Use the baseline's event type index for consistency with the stored counts
    event_type_to_idx = {t: i for i, t in enumerate(baseline_event_type_index)}

    # Analyze each MAC
    mac_results: dict[str, dict] = {}
    for mac, mac_evts in mac_raw_events.items():
        mac_results[mac] = analyze_mac(mac_evts, log_prob_matrix, event_type_to_idx)

    # Family-level Markov rollup. Evaluatable = MACs with enough scoreable
    # episodes OR a stuck-loop signal. Stuck-loop devices often have zero
    # proper episodes (they never associate cleanly), so without the union
    # they would never contribute to the family ratio.
    family_markov: dict[str, dict] = {}
    min_scoreable = _cfg("markov_min_scoreable_episodes")
    family_ratio_threshold = _cfg("markov_family_outlier_ratio")
    for family, family_macs in family_groups.items():
        evaluatable = [
            m for m in family_macs
            if m in mac_results and (
                mac_results[m]["markov_scoreable_episodes"] >= min_scoreable
                or mac_results[m]["is_stuck_loop"]
            )
        ]

        if not evaluatable:
            family_markov[family] = {
                "is_family_markov_outlier": False,
                "markov_family_reason": None,
                "markov_family_anomaly_ratio": 0.0,
                "markov_evaluatable_count": 0,
                "markov_family_anomalous_count": 0,
            }
            continue

        anomalous_macs = [
            m for m in evaluatable if mac_results[m]["is_markov_outlier"]
        ]
        ratio = len(anomalous_macs) / len(evaluatable)
        is_family_outlier = ratio >= family_ratio_threshold

        # Pick the family reason from the dominant per-MAC reason among the
        # flagged MACs. Tie → "repeated" (matches per-MAC priority).
        family_reason: str | None = None
        if is_family_outlier and anomalous_macs:
            repeated = sum(
                1 for m in anomalous_macs
                if mac_results[m].get("markov_reason") == "repeated"
            )
            anomaly = sum(
                1 for m in anomalous_macs
                if mac_results[m].get("markov_reason") == "anomaly"
            )
            family_reason = "repeated" if repeated >= anomaly else "anomaly"

        family_markov[family] = {
            "is_family_markov_outlier": is_family_outlier,
            "markov_family_reason": family_reason,
            "markov_family_anomaly_ratio": round(ratio, 4),
            "markov_evaluatable_count": len(evaluatable),
            "markov_family_anomalous_count": len(anomalous_macs),
        }
        if is_family_outlier:
            log.info(
                "[markov] Family [%s] flagged (%s): %d/%d MACs (%.0f%%) "
                "[site=%s wlan=%s]",
                family, family_reason, len(anomalous_macs), len(evaluatable),
                ratio * 100, site_id, wlan,
            )

    mac_results["__family_markov__"] = family_markov
    return mac_results

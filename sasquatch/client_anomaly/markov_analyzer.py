"""
markov_analyzer.py — Two-layer Markov Chain episode analysis for client event chains.

Layer 1 — Event-level transition matrix:
  Built from all consecutive event-type pairs within normal-length episodes.
  Scored per episode; episodes below a log-probability threshold are flagged.

Layer 2 — Episode-type state machine:
  States: "short" (< MARKOV_MIN_EPISODE_LENGTH events) and "normal".
  Tracks whether a client is stuck in a repeated-short-episode loop (e.g., repeatedly
  connecting and failing DHCP before the session gets long enough to appear normal).

Episodes are segmented by successful association/authentication/roam boundary events.
Short episodes are tracked separately — they represent connection attempts that never
completed a full connectivity chain.

Baseline transition matrices are built from the last 24hr of site/wlan events, stored
in Redis with a 48hr TTL (MARKOV_BASELINE_TTL), and refreshed by the daily scheduler job.

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

from .event_collector import sanitize_wlan_key, MIST_CLIENT_EVENT_TYPES

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

# ---------------------------------------------------------------------------
# Tunables — all configurable via environment variables
# ---------------------------------------------------------------------------

# Episodes shorter than this go into the short-episode state machine.
MARKOV_MIN_EPISODE_LENGTH = int(os.getenv("MARKOV_MIN_EPISODE_LENGTH", "3"))

# Mean log-probability threshold per transition below which an event-level episode
# is flagged anomalous.  More negative = stricter.  Default: -4.0 means the geometric
# mean per-transition probability is below e^-4 ≈ 0.018.
MARKOV_EPISODE_LOG_PROB_THRESHOLD = float(
    os.getenv("MARKOV_EPISODE_LOG_PROB_THRESHOLD", "-4.0")
)

# Fraction of a MAC's scoreable normal episodes that must be anomalous to flag the MAC.
MARKOV_OUTLIER_EPISODE_RATIO = float(os.getenv("MARKOV_OUTLIER_EPISODE_RATIO", "0.5"))

# Fraction of a family's evaluatable MACs that must be Markov-outliers to flag the family.
MARKOV_FAMILY_OUTLIER_RATIO = float(os.getenv("MARKOV_FAMILY_OUTLIER_RATIO", "0.5"))

# Minimum number of short episodes before the repeated-short-episode flag can trigger.
MARKOV_SHORT_EPISODE_MIN_COUNT = int(os.getenv("MARKOV_SHORT_EPISODE_MIN_COUNT", "3"))

# Fraction of total episodes that must be short to trigger the repeated-short-episode flag.
MARKOV_SHORT_EPISODE_RATIO_THRESHOLD = float(
    os.getenv("MARKOV_SHORT_EPISODE_RATIO_THRESHOLD", "0.5")
)

# Episode-type sequence: mean log-prob per transition threshold for the Layer 2 sequence.
MARKOV_EPISODE_SEQ_LOG_PROB_THRESHOLD = float(
    os.getenv("MARKOV_EPISODE_SEQ_LOG_PROB_THRESHOLD", "-2.0")
)

# Minimum scoreable normal episodes required before event-level ratio is computed.
# MACs with fewer than this are evaluated only via short-episode and sequence rules.
MARKOV_MIN_SCOREABLE_EPISODES = int(os.getenv("MARKOV_MIN_SCOREABLE_EPISODES", "2"))

# ---------------------------------------------------------------------------
# Episode-level state constants
# ---------------------------------------------------------------------------
_EP_SHORT = 0   # episode shorter than MARKOV_MIN_EPISODE_LENGTH
_EP_NORMAL = 1  # episode at or above MARKOV_MIN_EPISODE_LENGTH
_N_EP_STATES = 2


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


def segment_episodes(
    mac_events: list[dict],
) -> tuple[list[list[dict]], list[list[dict]]]:
    """
    Returns (normal_episodes, short_episodes) for a MAC's event stream.
    Normal: len >= MARKOV_MIN_EPISODE_LENGTH. Short: len < MARKOV_MIN_EPISODE_LENGTH.
    Temporal order is NOT preserved in either list — use _segment_ordered for that.
    """
    all_eps = _segment_ordered(mac_events)
    normal = [ep for ep in all_eps if len(ep) >= MARKOV_MIN_EPISODE_LENGTH]
    short = [ep for ep in all_eps if len(ep) < MARKOV_MIN_EPISODE_LENGTH]
    return normal, short


# ---------------------------------------------------------------------------
# Short episode classification
# ---------------------------------------------------------------------------

def classify_short_episode(episode: list[dict]) -> str:
    """
    Classify a short episode by its dominant failure pattern.
    Used for diagnostic labelling and short-episode pattern tracking only —
    not fed into the Markov transition matrices.
    """
    types = {e.get("type", "") for e in episode}
    has_auth_fail = bool(types & {
        "MARVIS_EVENT_CLIENT_AUTH_FAILURE",
        "MARVIS_EVENT_CLIENT_AUTH_DENIED",
        "MARVIS_EVENT_CLIENT_MAC_AUTH_FAILURE",
        "MARVIS_EVENT_SAE_AUTH_FAILURE",
        "SA_QUERY_TIMEOUT",
    })
    has_dhcp_fail = bool(types & {
        "MARVIS_EVENT_CLIENT_DHCP_NAK",
        "MARVIS_EVENT_CLIENT_DHCP_FAILURE",
        "MARVIS_EVENT_CLIENT_DHCP_STUCK",
        "MARVIS_EVENT_CLIENT_FAILED_DHCP_INFORM",
    })
    has_dhcp_ok = bool(types & {"CLIENT_IP_ASSIGNED", "CLIENT_IPV6_ASSIGNED"})
    has_arp_fail = bool(types & {
        "CLIENT_GW_ARP_FAILURE",
        "CLIENT_ARP_FAILURE",
        "CLIENT_EXCESSIVE_ARPING_GW",
    })
    has_dns_fail = bool(types & {"MARVIS_DNS_FAILURE"})
    has_auth_ok = bool(types & {
        "CLIENT_AUTHENTICATED",
        "CLIENT_AUTH_ASSOCIATION",
        "CLIENT_AUTH_ASSOCIATION_11R",
        "CLIENT_AUTH_ASSOCIATION_OKC",
    })

    if has_auth_fail:
        return "auth_fail"
    if has_auth_ok and has_dhcp_fail and not has_dhcp_ok:
        return "dhcp_fail"
    if has_auth_ok and has_arp_fail:
        return "arp_fail"
    if has_auth_ok and has_dns_fail:
        return "dns_fail"
    if has_auth_ok and not has_dhcp_ok:
        return "auth_no_dhcp"
    return "incomplete"


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


def build_episode_level_transition_counts(
    episode_type_sequences: list[list[int]],
) -> np.ndarray:
    """
    Build a 2x2 transition count matrix over episode-level states (0=short, 1=normal).
    Returns float64 array of shape (2, 2).
    """
    counts = np.zeros((_N_EP_STATES, _N_EP_STATES), dtype=np.float64)
    for seq in episode_type_sequences:
        for k in range(len(seq) - 1):
            counts[seq[k], seq[k + 1]] += 1.0
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


def score_episode_sequence(
    episode_type_seq: list[int],
    episode_log_prob_matrix: np.ndarray,
) -> float:
    """
    Score a sequence of episode types as mean log-probability per transition.
    Returns 0.0 if fewer than 2 episodes.
    """
    if len(episode_type_seq) < 2:
        return 0.0
    values = [
        episode_log_prob_matrix[episode_type_seq[k], episode_type_seq[k + 1]]
        for k in range(len(episode_type_seq) - 1)
    ]
    return float(np.mean(values)) if values else 0.0


# ---------------------------------------------------------------------------
# Per-MAC analysis
# ---------------------------------------------------------------------------

def analyze_mac(
    mac_events: list[dict],
    log_prob_matrix: np.ndarray,
    event_type_to_idx: dict[str, int],
    episode_log_prob_matrix: np.ndarray,
) -> dict:
    """
    Run full two-layer Markov analysis for a single MAC.

    Layer 1: Score each normal-length episode against the event-level log_prob_matrix.
    Layer 2: Score the MAC's sequence of episode types (short/normal) against the
             episode-level log_prob_matrix.

    Returns dict with all Markov anomaly fields; see _empty_markov_result() for keys.

    Outlier conditions (any one triggers is_markov_outlier=True):
      1. event_level: scoreable >= MARKOV_MIN_SCOREABLE_EPISODES AND
         anomalous episodes / scoreable >= MARKOV_OUTLIER_EPISODE_RATIO
      2. episode_sequence: episode-type sequence score < MARKOV_EPISODE_SEQ_LOG_PROB_THRESHOLD
      3. repeated_short: short episodes >= MARKOV_SHORT_EPISODE_MIN_COUNT AND
         short_ratio >= MARKOV_SHORT_EPISODE_RATIO_THRESHOLD
    """
    all_episodes = _segment_ordered(mac_events)
    if not all_episodes:
        return _empty_markov_result()

    total_episodes = len(all_episodes)

    # Partition into normal / short and build the episode-type sequence in order
    normal_episodes: list[list[dict]] = []
    short_episodes: list[list[dict]] = []
    episode_type_seq: list[int] = []

    for ep in all_episodes:
        if len(ep) >= MARKOV_MIN_EPISODE_LENGTH:
            normal_episodes.append(ep)
            episode_type_seq.append(_EP_NORMAL)
        else:
            short_episodes.append(ep)
            episode_type_seq.append(_EP_SHORT)

    short_count = len(short_episodes)
    normal_count = len(normal_episodes)
    short_ratio = short_count / total_episodes

    # Short-episode diagnostics
    short_patterns = [classify_short_episode(ep) for ep in short_episodes]
    dominant_short_pattern: str | None = (
        Counter(short_patterns).most_common(1)[0][0] if short_patterns else None
    )
    has_repeated_short = (
        short_count >= MARKOV_SHORT_EPISODE_MIN_COUNT
        and short_ratio >= MARKOV_SHORT_EPISODE_RATIO_THRESHOLD
    )

    # Layer 1: event-level episode scoring
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
        if scoreable >= MARKOV_MIN_SCOREABLE_EPISODES
        else 0.0
    )

    # Layer 2: episode-type sequence scoring
    ep_seq_score = score_episode_sequence(episode_type_seq, episode_log_prob_matrix)
    ep_seq_anomalous = (
        len(episode_type_seq) >= 2
        and ep_seq_score < MARKOV_EPISODE_SEQ_LOG_PROB_THRESHOLD
    )

    # Aggregate outlier determination
    event_level_anomalous = (
        scoreable >= MARKOV_MIN_SCOREABLE_EPISODES
        and episode_anomaly_ratio >= MARKOV_OUTLIER_EPISODE_RATIO
    )
    is_outlier = event_level_anomalous or ep_seq_anomalous or has_repeated_short

    return {
        "markov_total_episodes": total_episodes,
        "markov_normal_episodes": normal_count,
        "markov_short_episodes": short_count,
        "markov_short_episode_ratio": round(short_ratio, 4),
        "markov_scoreable_episodes": scoreable,
        "markov_anomalous_episodes": anomalous_count,
        "markov_episode_anomaly_ratio": round(episode_anomaly_ratio, 4),
        "markov_episode_seq_score": round(ep_seq_score, 4),
        "has_repeated_short_episodes": has_repeated_short,
        "short_episode_dominant_pattern": dominant_short_pattern,
        "is_markov_outlier": is_outlier,
        "markov_episode_scores": [round(s, 4) for s in episode_scores],
    }


def _empty_markov_result() -> dict:
    return {
        "markov_total_episodes": 0,
        "markov_normal_episodes": 0,
        "markov_short_episodes": 0,
        "markov_short_episode_ratio": 0.0,
        "markov_scoreable_episodes": 0,
        "markov_anomalous_episodes": 0,
        "markov_episode_anomaly_ratio": 0.0,
        "markov_episode_seq_score": 0.0,
        "has_repeated_short_episodes": False,
        "short_episode_dominant_pattern": None,
        "is_markov_outlier": False,
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

    Uses the last 24 hours of events from the site's Redis sorted set.
    Returns a summary dict {macs, events, normal_episodes}.
    """
    from .event_collector import _load_events_from_site_sets

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        cutoff_24h = _time.time() - 24 * 3600
        all_events = await _load_events_from_site_sets(
            redis_client, site_id=site_id, wlan=wlan if wlan else None
        )
        events_24h = [e for e in all_events if e.get("timestamp", 0) >= cutoff_24h]

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
        all_ep_type_seqs: list[list[int]] = []

        for mac_evts in mac_events.values():
            ordered = _segment_ordered(mac_evts)
            seq: list[int] = []
            for ep in ordered:
                if len(ep) >= MARKOV_MIN_EPISODE_LENGTH:
                    all_normal_episodes.append(ep)
                    seq.append(_EP_NORMAL)
                else:
                    seq.append(_EP_SHORT)
            if len(seq) >= 2:
                all_ep_type_seqs.append(seq)

        event_counts = build_transition_counts(
            all_normal_episodes, event_type_to_idx, n
        )
        episode_counts = build_episode_level_transition_counts(all_ep_type_seqs)

        baseline = {
            "transition_counts": event_counts.tolist(),
            "episode_transition_counts": episode_counts.tolist(),
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
) -> tuple[np.ndarray, np.ndarray, list[str]] | None:
    """
    Load baseline matrices from Redis.
    Returns (log_prob_matrix, episode_log_prob_matrix, event_type_index) or None if absent.
    """
    key = _baseline_key(site_id, wlan)
    raw = await redis_client.get(key)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        event_type_index: list[str] = data["event_type_index"]
        counts = np.array(data["transition_counts"], dtype=np.float64)
        ep_counts = np.array(data["episode_transition_counts"], dtype=np.float64)
        log_prob_matrix = np.log(laplace_smooth_and_normalize(counts))
        episode_log_prob_matrix = np.log(laplace_smooth_and_normalize(ep_counts))
        return log_prob_matrix, episode_log_prob_matrix, event_type_index
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
      is_family_markov_outlier, markov_family_anomaly_ratio,
      markov_evaluatable_count, markov_family_anomalous_count
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
                "markov_family_anomaly_ratio": 0.0,
                "markov_evaluatable_count": 0,
                "markov_family_anomalous_count": 0,
            }
            for family in family_groups
        }
        return empty

    log_prob_matrix, episode_log_prob_matrix, baseline_event_type_index = baseline
    # Use the baseline's event type index for consistency with the stored counts
    event_type_to_idx = {t: i for i, t in enumerate(baseline_event_type_index)}

    # Analyze each MAC
    mac_results: dict[str, dict] = {}
    for mac, mac_evts in mac_raw_events.items():
        mac_results[mac] = analyze_mac(
            mac_evts, log_prob_matrix, event_type_to_idx, episode_log_prob_matrix
        )

    # Family-level Markov rollup
    # Evaluatable = MACs with enough scoreable episodes OR enough short episodes to judge
    family_markov: dict[str, dict] = {}
    for family, family_macs in family_groups.items():
        scoreable_macs = [
            m for m in family_macs
            if m in mac_results
            and mac_results[m]["markov_scoreable_episodes"] >= MARKOV_MIN_SCOREABLE_EPISODES
        ]
        short_flagged_macs = [
            m for m in family_macs
            if m in mac_results and mac_results[m]["has_repeated_short_episodes"]
        ]
        # Union so short-episode-only MACs aren't excluded from the family ratio
        evaluatable = list({*scoreable_macs, *short_flagged_macs})

        if not evaluatable:
            family_markov[family] = {
                "is_family_markov_outlier": False,
                "markov_family_anomaly_ratio": 0.0,
                "markov_evaluatable_count": 0,
                "markov_family_anomalous_count": 0,
            }
            continue

        anomalous_macs = [
            m for m in evaluatable
            if m in mac_results and mac_results[m]["is_markov_outlier"]
        ]
        ratio = len(anomalous_macs) / len(evaluatable)
        is_family_outlier = ratio >= MARKOV_FAMILY_OUTLIER_RATIO

        family_markov[family] = {
            "is_family_markov_outlier": is_family_outlier,
            "markov_family_anomaly_ratio": round(ratio, 4),
            "markov_evaluatable_count": len(evaluatable),
            "markov_family_anomalous_count": len(anomalous_macs),
        }
        if is_family_outlier:
            log.info(
                "[markov] Family [%s] flagged: %d/%d MACs anomalous (%.0f%%) "
                "[site=%s wlan=%s]",
                family, len(anomalous_macs), len(evaluatable),
                ratio * 100, site_id, wlan,
            )

    mac_results["__family_markov__"] = family_markov
    return mac_results

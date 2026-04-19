"""
anomaly_detector.py — multi-stage anomaly detection pipeline.

Stage 1: DBSCAN across all MACs in the WLAN scope. MACs that land in noise (label=-1)
         indicate anomalous behavior. DBSCAN results set dbscan_label, is_dbscan_outlier,
         and dbscan_family_noise_ratio on each MAC record.

         Family-level outlier detection (is_family_outlier) is determined by a separate
         cosine-distance step: one dual-representation row (median ⊕ max) is computed
         per device family, and each family's cosine distance from a healthy-reference
         centroid is measured. Families whose distance exceeds
         ANOMALY_CENTROID_DIST_THRESHOLD are flagged. Requires at least 2 qualifying
         families (≥2 MACs each) — below that the step is skipped and no families are
         flagged at the family level.

Stage 2: Isolation Forest within each device family. Identifies specific endpoint MACs
         whose behavior is anomalous relative to their family peer group. IF is used
         ONLY for intra-family outlier detection — it is no longer used at the
         inter-family centroid level.

Stage 4: Markov Chain episode analysis (see markov_analyzer.py).
         Two-layer analysis: event-level transition scoring within episodes, plus an
         episode-type state machine tracking short (failed) vs normal episode sequences.
         Requires a pre-built 24hr baseline (sasquatch:markov_baseline:{site_id}:{wlan_key})
         populated by the daily markov_baseline_job. Skipped silently on first run until
         the baseline is available.

Finding rollup: aggregate per-family outlier ratios → findings list.

Anomaly labels on findings:
  is_family_outlier       — cosine distance from healthy-reference centroid
  is_family_dbscan_outlier — DBSCAN family noise ratio above threshold
  is_family_markov_outlier — Markov Chain family anomaly

Redis key scheme:
  sasquatch:anomalies:{site_id}:{wlan_key}
  sasquatch:findings:{site_id}:{wlan_key}
  where wlan_key is a sanitized SSID name.
"""

import json
import logging
import os
from collections import Counter, defaultdict

import numpy as np
import redis.asyncio as aioredis
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.metrics.pairwise import cosine_distances
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

from . import config
from . import db as _db
from .event_collector import get_events, sanitize_wlan_key
from .feature_engineer import (
    SERVICE_ACCOUNT_SUFFIX,
    build_posthoc_features,
    get_features,
    is_sa_record_key,
    is_service_account_family,
    underlying_mac,
)
from .health_scorer import _mac_health_score
from .markov_analyzer import run_markov_analysis

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
ANOMALIES_TTL = 24 * 3600
FINDINGS_TTL = 24 * 3600

# Device families excluded from finding rollup — heterogeneous catch-all buckets
# (Mist returned no fingerprint, OUI lookup also failed). Mixing unrelated devices
# into one "family" produces noisy centroid/IF/Markov signal that is not actionable,
# so they are suppressed across site findings, org findings, and webhook dispatch.
HIDDEN_FAMILIES: frozenset[str] = frozenset({"Unknown", "IoT (Unknown)"})


def _cfg(key: str) -> int | float:
    """Shorthand to read an anomaly-section config value at runtime."""
    return config.get("anomaly", key)


def _random_state() -> int | None:
    """Return the ML random seed, or None when set to -1 (random each run)."""
    val = _cfg("anomaly_random_state")
    return None if val == -1 else int(val)



def _anomalies_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:anomalies:{site_id}:{sanitize_wlan_key(wlan)}"


def _findings_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:findings:{site_id}:{sanitize_wlan_key(wlan)}"


def _org_anomalies_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:org_anomalies:{site_id}:{sanitize_wlan_key(wlan)}"


def _org_findings_redis_key(wlan: str) -> str:
    """Single org-wide findings key — one entry per device family across all sites."""
    return f"sasquatch:org_findings:{sanitize_wlan_key(wlan)}"


def _severity(outlier_ratio: float) -> str:
    if outlier_ratio > 0.6:
        return "significant"
    if outlier_ratio > 0.3:
        return "moderate"
    return "minimal"


def _extract_vector_array(
    feature_records: list[dict], vector_key: str
) -> np.ndarray:
    """Convert list of feature record dicts to a numpy array.

    `vector_key` selects which vector to extract — "event_vector" for IF,
    "category_vector" for DBSCAN. Key ordering is taken from the first
    record; build_features writes both vectors with stable key ordering
    (CATEGORY_FEATURE_KEYS / event_type_index respectively), so all rows
    share the same dimensionality.
    """
    if not feature_records:
        return np.empty((0, 0))
    keys = list(feature_records[0][vector_key].keys())
    return np.array(
        [[r[vector_key].get(k, 0.0) for k in keys] for r in feature_records]
    )


def _run_isolation_forest(
    macs: list[str], feature_records: list[dict]
) -> dict[str, dict]:
    """
    Run Isolation Forest on a group of MACs (same device family).
    Operates on event_vector (~59-dim per-event-type frequencies) so two
    family members failing at distinct event types (e.g. 11r-FBT vs OKC
    auth failure) score as different rather than collapsing into the
    same ROAM_FAILURE bucket the category vector would merge them into.
    Returns per-MAC dict with if_score and is_if_outlier.

    Per-MAC event-count filter: only MACs with event_count >=
    anomaly_min_mac_events (default 10) are scored. The feature pool itself
    runs at the lower feature_min_mac_events threshold (default 3) so that
    Health and Centroid see broader coverage; IF needs the higher floor for
    the per-MAC vector to be statistically meaningful. MACs filtered out get
    null scores — same shape as the existing MIN_PEERS skip path.
    """
    min_events = _cfg("anomaly_min_mac_events")
    eligible_indices = [
        i for i, r in enumerate(feature_records)
        if r.get("event_count", 0) >= min_events
    ]
    eligible_set = set(eligible_indices)
    eligible_macs = [macs[i] for i in eligible_indices]
    eligible_records = [feature_records[i] for i in eligible_indices]

    X = _extract_vector_array(eligible_records, "event_vector")
    if X.shape[0] < _cfg("anomaly_min_peers"):
        return {
            mac: {"if_score": None, "is_if_outlier": False}
            for mac in macs
        }

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(
        contamination=_cfg("anomaly_if_contamination"),
        random_state=_random_state(),
        n_estimators=_cfg("anomaly_if_n_estimators"),
    )
    labels = clf.fit_predict(X_scaled)
    raw_scores = clf.decision_function(X_scaled)

    # Emit scores for the eligible MACs and null entries for the filtered-out
    # MACs so the caller's downstream merge sees a record for every input.
    results: dict[str, dict] = {}
    for i, mac in enumerate(eligible_macs):
        results[mac] = {
            "if_score": float(raw_scores[i]),
            "is_if_outlier": bool(labels[i] == -1),
        }
    for mac in macs:
        if mac not in results:
            results[mac] = {"if_score": None, "is_if_outlier": False}
    return results


def _auto_min_samples(n_clients: int) -> int:
    """
    Auto-tune DBSCAN min_samples from population size.

    min_samples = max(3, int(n_clients * pct))

    `pct` is sourced from anomaly_dbscan_min_samples_pct (integer 1–10),
    mapped to 0.01–0.10 — 3 → 0.03 by default. The floor of 3 keeps the
    detector well-defined on tiny populations.
    """
    pct_int = int(_cfg("anomaly_dbscan_min_samples_pct"))
    pct = max(1, min(10, pct_int)) / 100.0
    return max(3, int(n_clients * pct))


def _auto_eps(X_reduced: np.ndarray, min_samples: int) -> float:
    """
    Pick DBSCAN eps via the k-distance elbow method.

    For each point, take the distance to its k-th nearest neighbor (k = min_samples).
    Sort ascending. The "elbow" — the point of maximum curvature — is the
    classic Ester et al. heuristic for eps. Approximated here by the point of
    maximum perpendicular distance from the line joining the first and last
    points of the sorted curve (the "knee" / triangle method), which is
    parameter-free and robust on monotone curves.
    """
    n = X_reduced.shape[0]
    k = max(2, min(min_samples, n - 1))
    # ball_tree keeps memory O(n log n) on the 5-8 dim PCA-reduced input,
    # vs. brute's O(n²) pairwise matrix that spiked ~800 MB on org-wide runs.
    nn = NearestNeighbors(n_neighbors=k + 1, algorithm="ball_tree").fit(X_reduced)
    dists, _ = nn.kneighbors(X_reduced)
    kth = np.sort(dists[:, k])
    if kth.size < 2 or kth[-1] <= kth[0]:
        return float(kth[-1]) if kth.size else 0.5

    x = np.arange(kth.size, dtype=float)
    y = kth.astype(float)
    x0, y0 = x[0], y[0]
    x1, y1 = x[-1], y[-1]
    denom = float(np.hypot(y1 - y0, x1 - x0)) or 1.0
    perp = np.abs((y1 - y0) * x - (x1 - x0) * y + x1 * y0 - y1 * x0) / denom
    elbow_idx = int(np.argmax(perp))
    return float(kth[elbow_idx])


def _run_dbscan(macs: list[str], feature_records: list[dict]) -> dict[str, dict]:
    """
    Run DBSCAN across all MACs in the WLAN/org scope.

    Operates on category_vector (14-dim semantic buckets + concentration features).
    DBSCAN is a population-wide cluster scan — semantic granularity is the right
    level here: clients should cluster by which kinds of behaviors they exhibit,
    not by which specific event subtypes they happen to fire. Per-event-type
    detail belongs to the per-family IF / centroid passes.

    PCA reduction is applied to keep Euclidean distance well-behaved on the
    sparse 14-dim category vectors. n_components=0.95 typically collapses to
    a handful of components, making Euclidean distance meaningful again.

    Auto-tuning: min_samples is derived from the size of the input population
    (`max(3, int(n_clients * pct))` — `pct` configurable via the GUI, 0.01–0.10),
    and eps is selected by the k-distance elbow method per run. Both adapt to
    site/org population size automatically — small sites get tight clusters,
    large sites get looser ones.

    Returns per-MAC dict with dbscan_label and is_dbscan_outlier.

    Per-MAC event-count filter: only MACs with event_count >=
    anomaly_min_mac_events (default 10) participate. The feature pool runs
    at the lower feature_min_mac_events threshold (default 3) to give
    Health and Centroid broader coverage; DBSCAN needs the higher floor
    for category-vector density to be cluster-meaningful. Filtered-out
    MACs get dbscan_label=None, is_dbscan_outlier=False so the consumer
    side doesn't conflate "not eligible" with "noise outlier".
    """
    if not macs:
        return {}

    min_events = _cfg("anomaly_min_mac_events")
    eligible_indices = [
        i for i, r in enumerate(feature_records)
        if r.get("event_count", 0) >= min_events
    ]
    eligible_macs = [macs[i] for i in eligible_indices]
    eligible_records = [feature_records[i] for i in eligible_indices]

    n_clients = len(eligible_macs)
    if n_clients == 0:
        return {mac: {"dbscan_label": None, "is_dbscan_outlier": False} for mac in macs}

    min_samples = _auto_min_samples(n_clients)
    if n_clients < min_samples:
        results: dict[str, dict] = {
            mac: {"dbscan_label": -1, "is_dbscan_outlier": True} for mac in eligible_macs
        }
        for mac in macs:
            if mac not in results:
                results[mac] = {"dbscan_label": None, "is_dbscan_outlier": False}
        return results

    X = _extract_vector_array(eligible_records, "category_vector")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Reduce dimensionality before DBSCAN. n_components=0.95 keeps enough components
    # to explain 95% of variance. Cap at n_samples - 1 so PCA doesn't fail on small
    # populations.
    max_components = min(X_scaled.shape[0] - 1, X_scaled.shape[1])
    pca = PCA(n_components=min(_cfg("anomaly_dbscan_pca_variance"), max_components), random_state=_random_state())
    X_reduced = pca.fit_transform(X_scaled)

    eps = _auto_eps(X_reduced, min_samples)

    log.info(
        "DBSCAN auto-tune: n_clients=%d → min_samples=%d, eps=%.4f "
        "(PCA %d→%d dims, %.1f%% variance)",
        n_clients,
        min_samples,
        eps,
        X_scaled.shape[1],
        pca.n_components_,
        pca.explained_variance_ratio_.sum() * 100,
    )

    # Match algorithm to _auto_eps's NearestNeighbors — ball_tree avoids the
    # O(n²) pairwise matrix brute would build on the org-wide MAC population.
    db = DBSCAN(eps=eps, min_samples=min_samples, algorithm="ball_tree")
    labels = db.fit_predict(X_reduced)

    results: dict[str, dict] = {}
    for i, mac in enumerate(eligible_macs):
        results[mac] = {
            "dbscan_label": int(labels[i]),
            "is_dbscan_outlier": bool(labels[i] == -1),
        }
    for mac in macs:
        if mac not in results:
            results[mac] = {"dbscan_label": None, "is_dbscan_outlier": False}
    return results


def _top_contributing_features(
    outlier_vecs: list[dict], normal_vecs: list[dict], top_n: int = 5
) -> list[dict]:
    """
    Find features with largest mean difference between outlier and normal groups.
    """
    if not outlier_vecs or not normal_vecs:
        return []

    keys = list(outlier_vecs[0].keys())
    outlier_arr = np.array([[v.get(k, 0.0) for k in keys] for v in outlier_vecs])
    normal_arr = np.array([[v.get(k, 0.0) for k in keys] for v in normal_vecs])

    outlier_means = outlier_arr.mean(axis=0)
    normal_means = normal_arr.mean(axis=0)
    diffs = np.abs(outlier_means - normal_means)

    top_indices = np.argsort(diffs)[::-1][:top_n]
    return [
        {
            "feature": keys[i],
            "outlier_mean": float(outlier_means[i]),
            "baseline_mean": float(normal_means[i]),
        }
        for i in top_indices
    ]


def _classify_probable_pattern(posthoc: dict) -> str:
    """
    Rule-based pattern classification from post-hoc explainer features.
    First match wins — evaluated in priority order.
    """
    pmkid_ratio = (
        posthoc.get("pmkid_failure_count", 0) / max(posthoc.get("event_count", 1), 1)
    )
    gas_ratio = (
        posthoc.get("gas_timeout_count", 0) / max(posthoc.get("event_count", 1), 1)
    )
    top_frac = posthoc.get("top_event_fraction", 0.0)
    dns_dhcp_ratio = posthoc.get("dns_to_dhcp_xid_ratio", 1.0)
    cat_roam_fail = posthoc.get("cat_ratio_roam_failure", 0.0)
    cat_auth_fail = posthoc.get("cat_ratio_auth_failure", 0.0)
    cat_dns_fail = posthoc.get("cat_ratio_dns_failure", 0.0)
    cat_dhcp_fail = posthoc.get("cat_ratio_dhcp_failure", 0.0)
    auth_recovery = posthoc.get("auth_fail_recovery_ratio", 1.0)

    dhcp_burst = posthoc.get("dhcp_max_burst_5min", 0)
    dhcp_gap = posthoc.get("dhcp_median_gap_seconds", -1)
    is_dhcp_storm = dhcp_burst >= 10 and 0 <= dhcp_gap < 600
    if is_dhcp_storm and top_frac > 0.3 and dns_dhcp_ratio < 0.2:
        return "dhcp_discard_loop"
    if pmkid_ratio > 0.1:
        return "pmkid_stale"
    if gas_ratio > 0.1:
        return "gas_anqp_timeout"
    if cat_roam_fail > 0.15:
        return "roam_failure"
    if cat_auth_fail > 0.15 and auth_recovery > 0.5:
        return "auth_failure_recovering"
    if cat_auth_fail > 0.15 and auth_recovery <= 0.5:
        return "auth_failure_terminal"
    if cat_dns_fail > 0.15:
        return "dns_failure"
    if cat_dhcp_fail > 0.15:
        return "dhcp_failure"
    return "behavioral_outlier"



_CENTROID_MIN_QUALIFYING_FAMILIES = 2


def _run_family_centroid_distance(
    family_groups: dict[str, list[str]],
    features: dict[str, dict],
    wlan: str = "?",
    family_health: dict[str, float] | None = None,
) -> dict[str, float]:
    """
    Inter-family cosine-distance anomaly detection — the sole family-level
    (is_family_outlier) signal. Isolation Forest is no longer used at the
    centroid level; it remains in use for intra-family MAC outlier detection
    (see `_run_isolation_forest`).

    For each family with >= 2 MACs, a dual-representation row is built:
      - median vector: element-wise median across all MACs in the family.
        More robust than the mean — a single anomalous MAC doesn't shift it.
        Captures whole-family behavioral shifts.
      - max vector: component-wise maximum across all MACs in the family.
        Captures the behavioral ceiling of the family — what the most extreme
        any member does on each feature dimension.

    The two vectors are concatenated into a single row and L2-normalized so
    cosine distance measures the angle between family behavior profiles (not
    magnitude). StandardScaler is deliberately NOT used here: it zero-means
    each feature across the small set of family rows, pulling the median
    reference toward the zero vector and producing spurious near-unit
    distances for every family.

    family_health: optional dict of {family: mean_health_score}. When provided
    and at least CENTROID_HEALTHY_REF_MIN families are healthy (score >=
    CENTROID_HEALTHY_REF_THRESHOLD), the reference centroid is built from ONLY
    those healthy families. Every family — including unhealthy ones — is then
    measured against this healthy reference. Families that all fail the same
    way (forming their own cluster) are still flagged because their shared
    failure signature points away from the healthy reference, even if none of
    them looks anomalous relative to the others.

    Returns {family_name: cosine_distance} for every qualifying family.
    Values near 0.0 are behaviorally close to the reference.
    Values exceeding CENTROID_DIST_THRESHOLD are flagged as outliers.
    Returns {} if fewer than 2 qualifying families exist (a reference centroid
    and a target family are both required).
    """
    # Operates on event_vector (~59-dim per-event-type frequencies). Category-level
    # centroids would collapse families that fail at different specific event types
    # into the same point — exactly the signal this detector exists to surface.
    # event_vector keys are stable across MACs within a single build (built from
    # the same event_type_index), so the first present record defines key order.
    event_keys: list[str] | None = None
    for fam_macs in family_groups.values():
        for mac in fam_macs:
            rec = features.get(mac)
            if rec and rec.get("event_vector"):
                event_keys = list(rec["event_vector"].keys())
                break
        if event_keys:
            break
    if not event_keys:
        log.info(
            "Centroid distance [%s]: skipped — no event_vector found on any record",
            wlan,
        )
        return {}

    qualifying: list[tuple[str, np.ndarray]] = []
    for family, macs in family_groups.items():
        if len(macs) < 2:
            continue
        vectors = np.array([
            [features[mac]["event_vector"].get(k, 0.0) for k in event_keys]
            for mac in macs
            if mac in features
        ])
        if vectors.shape[0] == 0:
            continue
        median_vec = np.median(vectors, axis=0)
        max_vec = vectors.max(axis=0)
        combined = np.concatenate([median_vec, max_vec])
        qualifying.append((family, combined))

    if len(qualifying) < _CENTROID_MIN_QUALIFYING_FAMILIES:
        log.info(
            "Centroid distance [%s]: skipped — only %d qualifying families (need >= %d)",
            wlan, len(qualifying), _CENTROID_MIN_QUALIFYING_FAMILIES,
        )
        return {}

    family_names = [name for name, _ in qualifying]
    X = np.array([vec for _, vec in qualifying])

    # L2-normalize each row so cosine distance is geometrically meaningful
    # (measures angle between family behavior profiles, not magnitude).
    norms = np.linalg.norm(X, axis=1, keepdims=True)
    norms = np.where(norms == 0, 1.0, norms)
    X_norm = X / norms

    # Build reference from healthy families only (when health data is available and
    # enough healthy families exist). All families are measured against this reference.
    healthy_ref_threshold = _cfg("anomaly_centroid_healthy_ref_threshold")
    healthy_ref_min = _cfg("anomaly_centroid_healthy_ref_min")
    healthy_indices: list[int] = []
    if family_health is not None:
        healthy_indices = [
            i for i, name in enumerate(family_names)
            if family_health.get(name, 1.0) >= healthy_ref_threshold
        ]

    use_healthy_ref = len(healthy_indices) >= healthy_ref_min
    if use_healthy_ref:
        X_ref = X_norm[healthy_indices]
        log.info(
            "Centroid distance [%s]: using healthy-only reference (%d/%d families, health >= %.2f)",
            wlan, len(healthy_indices), len(family_names), healthy_ref_threshold,
        )
    else:
        X_ref = X_norm
        if family_health is not None:
            log.info(
                "Centroid distance [%s]: fell back to all-family reference "
                "(only %d healthy families, need >= %d)",
                wlan, len(healthy_indices), healthy_ref_min,
            )

    # Element-wise median of reference rows, re-normalized to a unit vector.
    reference = np.median(X_ref, axis=0).reshape(1, -1)
    ref_norm = np.linalg.norm(reference)
    if ref_norm > 0:
        reference = reference / ref_norm

    dists = cosine_distances(X_norm, reference).flatten()
    dist_scores = {family_names[i]: float(dists[i]) for i in range(len(family_names))}
    log.info(
        "Centroid distance [%s]: %d families — scores: %s",
        wlan, len(family_names),
        {f: f"{s:.4f}" for f, s in sorted(dist_scores.items(), key=lambda x: -x[1])},
    )
    return dist_scores


def _family_mean_health(
    groups: dict[str, list[str]],
    feature_map: dict[str, dict],
    log_prefix: str,
    wlan: str,
) -> dict[str, float]:
    """Compute per-family mean health from `category_vector` on each member.

    Used before `_run_family_centroid_distance` to feed it the healthy-reference
    pool. Keys in `groups` may be MACs (site scope) or composite keys (org scope)
    — the lookup into `feature_map` uses whatever key the group carries.
    Missing-from-features members are skipped; a family with no members present
    in `feature_map` scores as 1.0 (no evidence of failure).
    """
    health: dict[str, float] = {}
    for family, members in groups.items():
        scores = [
            _mac_health_score(feature_map[m]["category_vector"])[0]
            for m in members
            if m in feature_map
        ]
        health[family] = sum(scores) / len(scores) if scores else 1.0
    log.info(
        "%sFamily health scores [%s]: %s",
        log_prefix, wlan,
        {f: f"{s:.2f}" for f, s in sorted(health.items(), key=lambda x: x[1])},
    )
    return health


async def score(
    site_id: str,
    wlan: str,
    org_family_contexts: dict[str, list[dict]] | None = None,
) -> int:
    """
    Run DBSCAN (WLAN-scoped, family-level detection) + Isolation Forest (per-family,
    endpoint-level detection) on feature vectors for the given site and WLAN scope.

    org_family_contexts: optional dict of {family: [feature_records]} from OTHER sites
      in the org. When a family has fewer than MIN_PEERS devices at this site, these
      records are used to supplement the IF training pool so small-site families are
      not silently skipped. Only the site's own MACs receive anomaly scores.

    Stage 1 — DBSCAN across all MACs in scope:
      Identifies MACs whose behavior is a site-wide outlier regardless of device type.
      Families with >= DBSCAN_FAMILY_NOISE_THRESHOLD fraction of noise MACs are flagged
      as family-level anomalies.

    Stage 2 — Isolation Forest per device family:
      Identifies specific endpoint MACs anomalous within their family peer group.

    Stage 4 — Markov Chain episode analysis (see markov_analyzer.py):
      Two-layer analysis runs against the 24hr baseline. Skipped if no baseline exists.

    Store per-MAC anomaly scores and rolled-up findings in Redis.
    Returns count of MACs scored.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        features = await get_features(site_id, wlan)
        if features is None:
            raise RuntimeError(
                f"No features found for site {site_id} / wlan={wlan}. "
                "Run feature_engineer.build_features() first."
            )
        if not features:
            # build_features wrote a key but every MAC was filtered out (most
            # likely by ANOMALY_MIN_MAC_EVENTS). Logged at WARNING so the gap is
            # visible in routine log scans — silent skips here are how
            # sasquatch:anomalies:{site}:{wlan} diverges from the features key
            # count (see TODO Phase 4 investigation). We cannot distinguish the
            # exact filter inside build_features from here, but we can confirm
            # the dict-is-empty case vs the key-missing case (the latter raises
            # above) and flag it clearly so downstream code falls back to
            # sasquatch:org_anomalies:{site}:{wlan} where applicable.
            log.warning(
                "[score] site=%s wlan=%s: features key exists but dict is empty "
                "(every MAC filtered out by build_features, likely "
                "ANOMALY_MIN_MAC_EVENTS=%d) — skipping per-site score; "
                "sasquatch:anomalies:%s:%s will NOT be written this cycle",
                site_id, wlan,
                config.get("general", "anomaly_min_mac_events"),
                site_id, wlan,
            )
            return 0

        # Load raw events for post-hoc explainer (only used for outliers).
        # Trailing 24h window — see db.DETECTION_WINDOW_SECONDS.
        events = await get_events(
            site_id=site_id,
            wlan=wlan,
            since=_db.get_detection_cutoff(),
        )
        mac_raw_events: dict[str, list[dict]] = defaultdict(list)
        for evt in events:
            mac = (evt.get("mac") or "").replace(":", "").lower()
            if mac:
                mac_raw_events[mac].append(evt)

        # Build family groups (full — includes service-account virtual families
        # whose keys are composite "{mac}#sa" entries pointing at duplicate vectors).
        family_groups: dict[str, list[str]] = defaultdict(list)
        for mac, record in features.items():
            family = record.get("device_family", "Unknown")
            family_groups[family].append(mac)

        # Service-account dual records are exact-vector copies of their primary
        # MAC and share that MAC's raw event stream. They must be EXCLUDED from
        # passes that operate on raw events or vector density:
        #   - Markov analysis (mac_raw_events is keyed by real MAC, not the composite)
        #   - DBSCAN (duplicate vectors would inflate cluster density and pull in
        #     distant points that wouldn't normally cluster)
        # They participate normally in centroid detection, per-family IF, and
        # finding rollup, where each sa family stands as a first-class peer.
        real_macs_only: set[str] = {k for k in features if not is_sa_record_key(k)}
        real_family_groups: dict[str, list[str]] = defaultdict(list)
        for mac in real_macs_only:
            family = features[mac].get("device_family", "Unknown")
            real_family_groups[family].append(mac)

        # --- Stage 4: Markov Chain episode analysis ---
        # Requires a pre-built 24hr baseline; skipped silently if absent.
        # event_type_index is loaded inside run_markov_analysis via the baseline.
        from .event_collector import ensure_event_type_index
        event_type_index = await ensure_event_type_index(redis_client)
        markov_results = await run_markov_analysis(
            site_id=site_id,
            wlan=wlan,
            mac_raw_events=dict(mac_raw_events),
            family_groups=dict(real_family_groups),
            redis_client=redis_client,
            event_type_index=event_type_index,
        )
        markov_family_flags: dict[str, dict] = markov_results.pop("__family_markov__", {})

        # Propagate per-MAC Markov results onto sa records so the merge step
        # below can populate anomaly entries for both keys with consistent flags.
        for key in features:
            if is_sa_record_key(key):
                markov_results[key] = markov_results.get(underlying_mac(key), {})

        # Build per-sa-family Markov rollup from the propagated per-MAC results.
        # This mirrors markov_analyzer's family rollup but operates on sa families
        # (which were filtered out of the call above).
        markov_min_scoreable = _cfg("markov_min_scoreable_episodes")
        markov_family_ratio_threshold = _cfg("markov_family_outlier_ratio")
        for sa_family, sa_macs in family_groups.items():
            if not is_service_account_family(sa_family):
                continue
            evaluatable_recs = []
            anomalous_recs = []
            for k in sa_macs:
                rec = markov_results.get(underlying_mac(k), {})
                if (
                    rec.get("markov_scoreable_episodes", 0) >= markov_min_scoreable
                    or rec.get("is_stuck_loop")
                ):
                    evaluatable_recs.append(rec)
                    if rec.get("is_markov_outlier"):
                        anomalous_recs.append(rec)
            evaluatable = len(evaluatable_recs)
            anomalous = len(anomalous_recs)
            ratio = anomalous / evaluatable if evaluatable else 0.0
            is_outlier = ratio >= markov_family_ratio_threshold
            sa_family_reason: str | None = None
            if is_outlier and anomalous_recs:
                repeated_n = sum(
                    1 for r in anomalous_recs if r.get("markov_reason") == "repeated"
                )
                anomaly_n = sum(
                    1 for r in anomalous_recs if r.get("markov_reason") == "anomaly"
                )
                sa_family_reason = "repeated" if repeated_n >= anomaly_n else "anomaly"
            markov_family_flags[sa_family] = {
                "is_family_markov_outlier": is_outlier,
                "markov_family_reason": sa_family_reason,
                "markov_family_anomaly_ratio": round(ratio, 4),
                "markov_evaluatable_count": evaluatable,
                "markov_family_anomalous_count": anomalous,
            }

        # --- Stage 1: DBSCAN across real MACs in WLAN scope ---
        # All real MACs participate. min_samples + eps are auto-tuned per run
        # from the population size (see _run_dbscan). The redundant
        # min_family_size pre-filter has been removed — small-family
        # suppression is the job of ALARM_MIN_FAMILY_SIZE downstream.
        # sa records are excluded — see real_family_groups comment above.
        dbscan_eligible_macs = list(real_macs_only)
        dbscan_eligible_records = [features[m] for m in dbscan_eligible_macs]
        dbscan_results_eligible = _run_dbscan(dbscan_eligible_macs, dbscan_eligible_records)

        dbscan_results: dict[str, dict] = {**dbscan_results_eligible}

        # Copy each primary MAC's DBSCAN result onto its sa record so the merge
        # step has something to read for sa keys. sa records inherit their
        # device's site-wide cluster membership — they ARE the same physical device.
        for key in features:
            if is_sa_record_key(key):
                primary = underlying_mac(key)
                dbscan_results[key] = dict(
                    dbscan_results.get(
                        primary,
                        {"dbscan_label": None, "is_dbscan_outlier": False},
                    )
                )

        # Compute DBSCAN noise ratio per family (stored on anomaly records and used
        # by the frontend). For sa families, every member is a composite key and
        # never appears in dbscan_results_eligible — fall back to the underlying
        # primary MACs so the family-level signal still reflects DBSCAN cluster
        # behavior.
        family_dbscan_noise_ratio: dict[str, float] = {}
        for family, family_macs in family_groups.items():
            eligible = [m for m in family_macs if m in dbscan_results_eligible]
            if not eligible and is_service_account_family(family):
                primaries = [underlying_mac(m) for m in family_macs]
                primary_eligible = [m for m in primaries if m in dbscan_results_eligible]
                if primary_eligible:
                    noise_count = sum(
                        1 for m in primary_eligible
                        if dbscan_results_eligible[m]["is_dbscan_outlier"]
                    )
                    family_dbscan_noise_ratio[family] = noise_count / len(primary_eligible)
                else:
                    family_dbscan_noise_ratio[family] = 0.0
                continue
            if not eligible:
                family_dbscan_noise_ratio[family] = 0.0
                continue
            noise_count = sum(1 for m in eligible if dbscan_results[m]["is_dbscan_outlier"])
            ratio = noise_count / len(eligible)
            family_dbscan_noise_ratio[family] = ratio

        # --- Family centroid detection: determine which families are anomalous ---
        # Compute per-family mean health so the centroid detection can build a
        # healthy-only reference (families with low health are excluded from the
        # reference population but are still scored against it).
        family_health = _family_mean_health(family_groups, features, "", wlan)

        # Cosine distance from the healthy-reference centroid is the sole
        # family-level (is_family_outlier) signal. IF is no longer used here.
        centroid_dist_scores = _run_family_centroid_distance(
            family_groups, features, wlan, family_health
        )
        flagged_families: set[str] = set()
        dist_threshold = _cfg("anomaly_centroid_dist_threshold")
        for family, dist in centroid_dist_scores.items():
            if dist > dist_threshold:
                flagged_families.add(family)
                log.info("Centroid distance [%s]: family [%s] flagged (dist=%.4f)", wlan, family, dist)

        # --- Stage 2: Isolation Forest per device family ---
        min_peers = _cfg("anomaly_min_peers")
        if_results: dict[str, dict] = {}
        families_with_org_if: set[str] = set()
        for family, family_macs in family_groups.items():
            n = len(family_macs)
            family_records = [features[m] for m in family_macs]

            # Supplement with org-level context when this site's family is too small.
            ctx_records: list[dict] = []
            if n < min_peers and org_family_contexts:
                ctx_records = org_family_contexts.get(family, [])

            combined_count = n + len(ctx_records)
            if combined_count < min_peers:
                if_results.update({mac: {"if_score": None, "is_if_outlier": False} for mac in family_macs})
                log.info(f"IF [{wlan}] [{family}]: skipped (only {n} MACs site-wide, {combined_count} org-wide, need {min_peers})")
                continue

            if ctx_records:
                # Use placeholder MACs for context records so we can discard their scores.
                ctx_macs = [f"__ctx_{i}__" for i in range(len(ctx_records))]
                results = _run_isolation_forest(family_macs + ctx_macs, family_records + ctx_records)
                # Discard scores for context MACs; keep only this site's MACs.
                results = {mac: results[mac] for mac in family_macs}
                families_with_org_if.add(family)
                outliers = sum(1 for r in results.values() if r["is_if_outlier"])
                log.info(f"IF [{wlan}] [{family}]: {outliers}/{n} outliers (org-pooled, +{len(ctx_records)} from other sites)")
            else:
                results = _run_isolation_forest(family_macs, family_records)
                outliers = sum(1 for r in results.values() if r["is_if_outlier"])
                log.info(f"IF [{wlan}] [{family}]: {outliers}/{n} outliers")

            if_results.update(results)

        # --- Merge per-MAC results ---
        # Both primary and sa keys flow through this loop. The two entries share
        # the same DBSCAN/Markov flags (sa records inherit from their primary)
        # but carry independent IF scores and family-level flags, since they were
        # scored in different family contexts.
        anomalies: dict[str, dict] = {}
        for mac in features:
            is_if = if_results[mac]["is_if_outlier"]
            is_db = dbscan_results[mac]["is_dbscan_outlier"]
            family = features[mac].get("device_family", "Unknown")
            is_family = family in flagged_families
            markov_rec = markov_results.get(mac, {})
            is_markov = markov_rec.get("is_markov_outlier", False)
            anomalies[mac] = {
                "if_score": if_results[mac]["if_score"],
                "is_if_outlier": is_if,
                "dbscan_label": dbscan_results[mac]["dbscan_label"],
                "is_dbscan_outlier": is_db,
                "is_family_outlier": is_family,
                "family_centroid_dist_score": centroid_dist_scores.get(family),
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                # Markov Chain fields
                "is_markov_outlier": is_markov,
                "markov_reason": markov_rec.get("markov_reason"),
                "markov_total_episodes": markov_rec.get("markov_total_episodes", 0),
                "markov_scoreable_episodes": markov_rec.get("markov_scoreable_episodes", 0),
                "markov_anomalous_episodes": markov_rec.get("markov_anomalous_episodes", 0),
                "markov_episode_anomaly_ratio": markov_rec.get("markov_episode_anomaly_ratio", 0.0),
                "is_stuck_loop": markov_rec.get("is_stuck_loop", False),
                "stuck_loop_pair": markov_rec.get("stuck_loop_pair"),
                "stuck_loop_fraction": markov_rec.get("stuck_loop_fraction", 0.0),
                "is_outlier": is_if or is_db or is_family or is_markov,
                "device_family": family,
                "event_count": features[mac].get("event_count", 0),
                "random_mac": features[mac].get("random_mac", False),
                "volume_concentration_weight": features[mac].get("volume_concentration_weight", 1.0),
                "last_username": features[mac].get("last_username", ""),
            }
            if is_sa_record_key(mac):
                anomalies[mac]["is_service_account_record"] = True
                anomalies[mac]["primary_mac"] = features[mac].get("primary_mac", underlying_mac(mac))
                anomalies[mac]["primary_device_family"] = features[mac].get("primary_device_family", "")

        # Surface a compact service-account summary on each PRIMARY anomaly entry
        # so the per-MAC drilldown endpoint (which queries by real MAC) can show
        # "this MAC also belongs to {label}.service_account, scored as
        # {is_family_outlier}" without an extra Redis lookup.
        for mac in list(anomalies):
            if is_sa_record_key(mac):
                continue
            sa_key = f"{mac}#sa"
            sa_entry = anomalies.get(sa_key)
            if not sa_entry:
                continue
            anomalies[mac]["service_account"] = {
                "family": features[mac].get("service_account_family", ""),
                "last_username": features[mac].get("last_username", ""),
                "is_family_outlier": sa_entry["is_family_outlier"],
                "is_if_outlier": sa_entry["is_if_outlier"],
                "if_score": sa_entry["if_score"],
                "centroid_dist_score": sa_entry.get("family_centroid_dist_score"),
            }

        key_anomalies = _anomalies_redis_key(site_id, wlan)
        await redis_client.set(key_anomalies, json.dumps(anomalies), ex=ANOMALIES_TTL)
        log.info(f"Stored anomaly scores for {len(anomalies)} MACs → {key_anomalies}")

        # --- Finding rollup per device family ---
        findings: list[dict] = []
        for family, family_macs in family_groups.items():
            if family in HIDDEN_FAMILIES:
                continue
            total = len(family_macs)

            # Org-pooled families borrowed cross-site data to run IF, so require
            # anomaly_min_peers local MACs before surfacing a site-level finding (avoids
            # hallucinated site findings driven by org noise).
            # Site-only families (IF ran locally or was skipped entirely) use the
            # lower anomaly_finding_min_size threshold — even 2 devices flagged by centroid
            # detection is real site signal worth reporting.
            if family in families_with_org_if:
                min_for_finding = min_peers
            else:
                min_for_finding = _cfg("anomaly_finding_min_size")
            if total < min_for_finding:
                continue

            outlier_macs = [m for m in family_macs if anomalies[m]["is_outlier"]]
            outlier_count = len(outlier_macs)
            outlier_ratio = outlier_count / total if total > 0 else 0.0

            # Surface every family with at least one outlier MAC, a Markov family
            # flag, or a centroid (is_family_outlier) flag. The alarm gate
            # (alarm_dbscan_markov_ratio, applied in webhook_dispatcher and the
            # OrgAlerts feed) decides which findings escalate to alarms; finding
            # visibility is intentionally unconditional so operators can browse
            # low-ratio signal in the Findings UI.
            fam_markov = markov_family_flags.get(family, {})
            is_family_markov_outlier = fam_markov.get("is_family_markov_outlier", False)
            markov_family_reason = fam_markov.get("markov_family_reason")
            markov_family_anomaly_ratio = fam_markov.get("markov_family_anomaly_ratio", 0.0)
            markov_evaluatable_count = fam_markov.get("markov_evaluatable_count", 0)
            markov_family_anomalous_count = fam_markov.get("markov_family_anomalous_count", 0)

            if (
                outlier_count == 0
                and not is_family_markov_outlier
                and family not in flagged_families
            ):
                continue

            # DBSCAN-specific rollup (used by Site Overview severity badge)
            dbscan_outlier_macs = [m for m in family_macs if anomalies[m]["is_dbscan_outlier"]]
            dbscan_outlier_count = len(dbscan_outlier_macs)
            dbscan_outlier_ratio = dbscan_outlier_count / total if total > 0 else 0.0

            # IF outlier MACs (used by family drilldown view)
            if_outlier_macs = [m for m in family_macs if anomalies[m]["is_if_outlier"]]

            family_weights = [anomalies[m]["volume_concentration_weight"] for m in family_macs]
            total_weight = sum(family_weights) or 1.0
            outlier_weight_sum = sum(anomalies[m]["volume_concentration_weight"] for m in outlier_macs)
            weighted_outlier_score = outlier_weight_sum / total_weight

            outlier_vecs = [features[m]["category_vector"] for m in outlier_macs]
            normal_macs = [m for m in family_macs if not anomalies[m]["is_outlier"]]
            normal_vecs = [features[m]["category_vector"] for m in normal_macs]

            # For family-wide outliers the entire family is flagged, leaving normal_vecs
            # empty. Fall back to the rest of the site population as the baseline so
            # top_features reflects how this family differs from all other devices.
            if not normal_vecs and outlier_vecs:
                family_mac_set = set(family_macs)
                normal_vecs = [features[m]["category_vector"] for m in features if m not in family_mac_set]

            top_features = _top_contributing_features(outlier_vecs, normal_vecs)

            # Post-hoc pattern classification.
            # For sa families, mac_raw_events is keyed by REAL MAC, so strip
            # the sa suffix from each composite outlier key before looking up events.
            is_family_level_outlier = family in flagged_families
            family_kind = "service_account" if is_service_account_family(family) else "device_family"
            if is_family_level_outlier:
                probable_pattern = "family_behavioral_outlier"
            else:
                probable_pattern = "behavioral_outlier"
                if outlier_macs:
                    combined_events = [
                        evt
                        for mac in outlier_macs
                        for evt in mac_raw_events.get(underlying_mac(mac), [])
                    ]
                    if combined_events:
                        posthoc = build_posthoc_features(combined_events)
                        posthoc["event_count"] = len(combined_events)
                        probable_pattern = _classify_probable_pattern(posthoc)

            # Worst-health MACs: top 3 across all family MACs by health score (ascending).
            # Used by alert cards in the UI and webhook payload to surface the specific
            # devices experiencing the most failures — independent of outlier scoring.
            # The displayed `mac` is always the real MAC, even for sa families.
            mac_health_scores = {
                m: _mac_health_score(features[m]["category_vector"])
                for m in family_macs
            }
            worst_health_macs = sorted(
                [
                    {
                        "mac": underlying_mac(m),
                        "health_score": round(score, 4),
                        "health_components": {
                            k: round(v, 4) for k, v in comps.items() if v > 0
                        },
                    }
                    for m, (score, comps) in mac_health_scores.items()
                ],
                key=lambda x: x["health_score"],
            )[:3]

            # Markov family-level flags — already computed above before the threshold check.

            # DBSCAN family-level flag: families where noise ratio exceeds threshold
            # are considered family-level anomalies.
            dbscan_noise_thresh = _cfg("anomaly_dbscan_family_noise_threshold")
            is_family_dbscan_outlier = (
                family_dbscan_noise_ratio.get(family, 0.0) >= dbscan_noise_thresh
            )

            # DBSCAN-or-Markov per-MAC union — used by the alarm gate
            # (alarm_dbscan_markov_ratio in webhook_dispatcher and the
            # OrgAlerts feed). A single client flagged by both detectors
            # counts once. Centroid (is_family_outlier) is independent of
            # this rollup and remains independently sufficient to alarm.
            dbscan_or_markov_macs = [
                m for m in family_macs
                if anomalies[m]["is_dbscan_outlier"] or anomalies[m]["is_markov_outlier"]
            ]
            dbscan_or_markov_outlier_count = len(dbscan_or_markov_macs)
            dbscan_or_markov_outlier_ratio = (
                dbscan_or_markov_outlier_count / total if total > 0 else 0.0
            )

            # For sa findings, surface the human-readable username label and the
            # set of underlying device families this service-account spans, so the
            # GUI can render "srv_Apple_EP.service_account (15 MacBooks, 3 Windows)".
            sa_label = ""
            sa_member_families: list[str] = []
            if family_kind == "service_account":
                sa_label = family[: -len(SERVICE_ACCOUNT_SUFFIX)]
                sa_member_families = sorted({
                    features[m].get("primary_device_family", "Unknown")
                    for m in family_macs
                })

            finding = {
                "device_family": family,
                "family_kind": family_kind,
                "service_account_label": sa_label,
                "service_account_member_families": sa_member_families,
                "wlan": wlan,
                "severity": _severity(outlier_ratio),
                "outlier_ratio": round(outlier_ratio, 4),
                "weighted_outlier_score": round(weighted_outlier_score, 4),
                "affected_mac_count": outlier_count,
                "total_mac_count": total,
                "is_family_outlier": is_family_level_outlier,
                "is_family_dbscan_outlier": is_family_dbscan_outlier,
                "is_family_markov_outlier": is_family_markov_outlier,
                "markov_family_reason": markov_family_reason,
                "centroid_dist_score": centroid_dist_scores.get(family),
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                "dbscan_severity": _severity(dbscan_outlier_ratio) if dbscan_outlier_count > 0 else None,
                "dbscan_outlier_ratio": round(dbscan_outlier_ratio, 4),
                "dbscan_outlier_count": dbscan_outlier_count,
                "dbscan_or_markov_outlier_count": dbscan_or_markov_outlier_count,
                "dbscan_or_markov_outlier_ratio": round(dbscan_or_markov_outlier_ratio, 4),
                "if_outlier_macs": [underlying_mac(m) for m in if_outlier_macs],
                "if_outlier_count": len(if_outlier_macs),
                "markov_family_anomaly_ratio": round(markov_family_anomaly_ratio, 4),
                "markov_evaluatable_count": markov_evaluatable_count,
                "markov_family_anomalous_count": markov_family_anomalous_count,
                "example_macs": [
                    underlying_mac(m) for m in sorted(
                        outlier_macs,
                        key=lambda m: anomalies[m]["volume_concentration_weight"],
                        reverse=True,
                    )[:5]
                ],
                "worst_health_macs": worst_health_macs,
                "top_features": top_features,
                "probable_pattern": probable_pattern,
            }
            findings.append(finding)
            log.info(
                f"Finding [{wlan}] [{family}] ({family_kind}): {outlier_count}/{total} outliers "
                f"({outlier_ratio:.1%}) → {finding['severity']} / {probable_pattern}"
            )

        severity_order = {"significant": 0, "moderate": 1, "minimal": 2}
        findings.sort(
            key=lambda f: (severity_order.get(f["severity"], 3), -f["weighted_outlier_score"])
        )

        key_findings = _findings_redis_key(site_id, wlan)
        await redis_client.set(key_findings, json.dumps(findings), ex=FINDINGS_TTL)
        log.info(f"Stored {len(findings)} findings → {key_findings}")

        return len(anomalies)

    finally:
        await redis_client.aclose()


async def score_org_wide(
    all_features_by_site: "dict[str, dict[str, dict]]",
    wlan: str,
) -> "dict[str, int]":
    """
    Run DBSCAN, Family Centroid IF, Isolation Forest, and rule-based thresholds across
    the org-wide pooled MAC population for the given WLAN scope.

    Each MAC is scored relative to all other MACs across all sites rather than just its
    own site's peers. Families that are too small at a single site can still get a
    meaningful IF score when peers from other sites are included.

    all_features_by_site: {site_id: {mac: feature_record}} — pre-loaded feature data.
      Sites with no features for this WLAN should be excluded by the caller.

    Stores results per-site under:
      sasquatch:org_anomalies:{site_id}:{wlan_key}
      sasquatch:org_findings:{site_id}:{wlan_key}

    Returns {site_id: macs_scored}.
    """
    # Build flat composite-key structures: composite_key = "{site_id}:{mac}".
    # Composite keys prevent collisions if the same MAC appears at multiple sites
    # (e.g. randomized MACs reused across SSIDs at different locations).
    composite_macs: list[str] = []
    composite_to_site: dict[str, str] = {}
    composite_to_mac: dict[str, str] = {}
    composite_features: dict[str, dict] = {}

    for site_id, site_features in all_features_by_site.items():
        for mac, record in site_features.items():
            key = f"{site_id}:{mac}"
            composite_macs.append(key)
            composite_to_site[key] = site_id
            composite_to_mac[key] = mac
            composite_features[key] = record

    if not composite_macs:
        log.info(f"[org score] wlan={wlan}: no MACs across any site — skipping")
        return {}

    log.info(
        f"[org score] wlan={wlan}: {len(composite_macs)} MACs across "
        f"{len(all_features_by_site)} sites"
    )

    # Build org-wide family groups (keyed by composite MAC).
    # `org_family_groups` is the FULL set including service-account virtual
    # families whose composite keys carry the "#sa" suffix and point at
    # duplicate per-MAC vectors. `real_org_family_groups` excludes those sa
    # keys for passes that operate on raw events or vector density (DBSCAN
    # would inflate cluster density on identical vectors).
    org_family_groups: dict[str, list[str]] = defaultdict(list)
    for key in composite_macs:
        family = composite_features[key].get("device_family", "Unknown")
        org_family_groups[family].append(key)

    real_composite_macs: set[str] = {k for k in composite_macs if not is_sa_record_key(k)}
    real_org_family_groups: dict[str, list[str]] = defaultdict(list)
    for key in real_composite_macs:
        family = composite_features[key].get("device_family", "Unknown")
        real_org_family_groups[family].append(key)

    # --- Stage 1: DBSCAN across all real org MACs ---
    # All real composite MACs participate. min_samples + eps are auto-tuned per
    # run from the population size (see _run_dbscan). The redundant
    # min_family_size pre-filter has been removed — small-family suppression
    # is the job of ALARM_MIN_FAMILY_SIZE downstream.
    # sa composite keys are filtered out — see real_org_family_groups comment.
    dbscan_eligible_keys = list(real_composite_macs)
    dbscan_results_eligible = _run_dbscan(
        dbscan_eligible_keys,
        [composite_features[k] for k in dbscan_eligible_keys],
    )

    dbscan_results: dict[str, dict] = {**dbscan_results_eligible}

    # Copy each primary composite MAC's DBSCAN result onto its sa composite
    # key so the merge step has a consistent value to read for sa entries.
    # The sa record represents the same physical device — it inherits its
    # primary's site-wide cluster membership.
    for key in composite_macs:
        if not is_sa_record_key(key):
            continue
        primary_ck = key[: -len("#sa")]
        dbscan_results[key] = dict(
            dbscan_results.get(
                primary_ck,
                {"dbscan_label": None, "is_dbscan_outlier": False},
            )
        )

    # DBSCAN noise ratio per family (stored on anomaly records).
    # For sa families every member is a composite sa key that never appears
    # in dbscan_results_eligible — fall back to the underlying primary
    # composite keys so the family-level signal still reflects DBSCAN
    # cluster behavior.
    family_dbscan_noise_ratio: dict[str, float] = {}
    for family, family_keys in org_family_groups.items():
        eligible = [k for k in family_keys if k in dbscan_results_eligible]
        if not eligible and is_service_account_family(family):
            primaries = [k[: -len("#sa")] for k in family_keys if is_sa_record_key(k)]
            primary_eligible = [p for p in primaries if p in dbscan_results_eligible]
            if primary_eligible:
                noise_count = sum(
                    1 for p in primary_eligible
                    if dbscan_results_eligible[p]["is_dbscan_outlier"]
                )
                family_dbscan_noise_ratio[family] = noise_count / len(primary_eligible)
            else:
                family_dbscan_noise_ratio[family] = 0.0
            continue
        if not eligible:
            family_dbscan_noise_ratio[family] = 0.0
            continue
        noise_count = sum(1 for k in eligible if dbscan_results[k]["is_dbscan_outlier"])
        family_dbscan_noise_ratio[family] = noise_count / len(eligible)

    # --- Family centroid detection across all org families ---
    # Compute per-family mean health from feature vectors so the centroid detection
    # can build a healthy-only reference. Unhealthy families are still scored against it.
    org_family_health = _family_mean_health(
        org_family_groups, composite_features, "[org] ", wlan
    )

    centroid_dist_scores = _run_family_centroid_distance(
        org_family_groups, composite_features, f"org/{wlan}", org_family_health
    )
    flagged_families: set[str] = set()
    org_dist_threshold = _cfg("anomaly_centroid_dist_threshold")
    for family, dist in centroid_dist_scores.items():
        if dist > org_dist_threshold:
            flagged_families.add(family)
            log.info(
                "[org Centroid distance] wlan=%s: family [%s] flagged (dist=%.4f)",
                wlan, family, dist,
            )

    # --- Stage 2: Isolation Forest per family (org-wide population) ---
    if_results: dict[str, dict] = {}
    for family, family_keys in org_family_groups.items():
        n = len(family_keys)
        results = _run_isolation_forest(family_keys, [composite_features[k] for k in family_keys])
        outliers = sum(1 for r in results.values() if r["is_if_outlier"])
        log.info(f"[org IF] wlan={wlan} [{family}]: {outliers}/{n} outliers")
        if_results.update(results)

    # --- Merge per-composite-key results ---
    # Both primary and sa composite keys flow through this loop. sa entries
    # share their primary's DBSCAN/Markov flags (inherited above) but carry
    # independent IF scores and family-level flags since they were scored in
    # different family contexts.
    org_anomalies_flat: dict[str, dict] = {}
    for key in composite_macs:
        family = composite_features[key].get("device_family", "Unknown")
        org_anomalies_flat[key] = {
            "if_score": if_results[key]["if_score"],
            "is_if_outlier": if_results[key]["is_if_outlier"],
            "dbscan_label": dbscan_results[key]["dbscan_label"],
            "is_dbscan_outlier": dbscan_results[key]["is_dbscan_outlier"],
            "is_family_outlier": family in flagged_families,
            "family_centroid_dist_score": centroid_dist_scores.get(family),
            "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
            # Markov fields populated below from per-site anomaly records
            "is_markov_outlier": False,
            "markov_reason": None,
            "is_outlier": if_results[key]["is_if_outlier"]
                or dbscan_results[key]["is_dbscan_outlier"]
                or (family in flagged_families),
            "device_family": family,
            "event_count": composite_features[key].get("event_count", 0),
            "random_mac": composite_features[key].get("random_mac", False),
            "volume_concentration_weight": composite_features[key].get(
                "volume_concentration_weight", 1.0
            ),
            "last_username": composite_features[key].get("last_username", ""),
        }
        if is_sa_record_key(key):
            org_anomalies_flat[key]["is_service_account_record"] = True
            org_anomalies_flat[key]["primary_mac"] = composite_features[key].get(
                "primary_mac", underlying_mac(composite_to_mac[key])
            )
            org_anomalies_flat[key]["primary_device_family"] = composite_features[key].get(
                "primary_device_family", ""
            )

    # --- Merge per-site Markov anomaly data into org_anomalies_flat ---
    # Per-site anomaly records (sasquatch:anomalies:{site_id}:{wlan_key}) contain
    # is_markov_outlier if the focused detection cycle has run for that site.
    # If the records are absent or stale, is_markov_outlier stays False.
    # Family-level Markov flags are recomputed below from the merged MAC-level results.
    _org_markov_redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        for site_id_m, site_features_m in all_features_by_site.items():
            site_anoms_raw = await _org_markov_redis.get(
                _anomalies_redis_key(site_id_m, wlan)
            )
            if not site_anoms_raw:
                continue
            try:
                site_anoms: dict[str, dict] = json.loads(site_anoms_raw)
            except (json.JSONDecodeError, TypeError) as exc:
                log.warning(
                    "[org-markov-merge] Failed to parse anomalies for site=%s wlan=%s: %s",
                    site_id_m, wlan, exc,
                )
                continue
            for mac_m, rec in site_anoms.items():
                ck = f"{site_id_m}:{mac_m}"
                if ck in org_anomalies_flat and rec.get("is_markov_outlier"):
                    org_anomalies_flat[ck]["is_markov_outlier"] = True
                    org_anomalies_flat[ck]["markov_reason"] = rec.get("markov_reason")
                    # Copy all Markov detail fields so org anomaly records
                    # carry the same data as per-site records. Without this,
                    # the MacDrilldown and OrgFamilyDrilldown show empty
                    # Markov detail when falling back to org anomalies.
                    for mk in (
                        "markov_total_episodes",
                        "markov_scoreable_episodes",
                        "markov_anomalous_episodes",
                        "markov_episode_anomaly_ratio",
                        "is_stuck_loop",
                        "stuck_loop_pair",
                        "stuck_loop_fraction",
                    ):
                        if mk in rec:
                            org_anomalies_flat[ck][mk] = rec[mk]
                    # Markov flagged → composite is_outlier is True by definition.
                    org_anomalies_flat[ck]["is_outlier"] = True
    finally:
        await _org_markov_redis.aclose()

    # Org-wide family Markov rollup — derived from merged MAC-level is_markov_outlier.
    # The dominant per-MAC markov_reason among the flagged MACs sets the family reason
    # ("repeated" wins ties to match per-MAC priority).
    org_family_markov_flags: dict[str, bool] = {}
    org_family_markov_ratio: dict[str, float] = {}
    org_family_markov_reason: dict[str, str | None] = {}
    for family, family_cks in org_family_groups.items():
        total_cks = len(family_cks)
        if total_cks == 0:
            org_family_markov_flags[family] = False
            org_family_markov_ratio[family] = 0.0
            org_family_markov_reason[family] = None
            continue
        markov_outlier_cks = [k for k in family_cks if org_anomalies_flat[k].get("is_markov_outlier")]
        ratio = len(markov_outlier_cks) / total_cks
        is_outlier = ratio >= _cfg("markov_family_outlier_ratio")
        org_family_markov_flags[family] = is_outlier
        org_family_markov_ratio[family] = ratio
        if is_outlier and markov_outlier_cks:
            repeated_n = sum(
                1 for k in markov_outlier_cks
                if org_anomalies_flat[k].get("markov_reason") == "repeated"
            )
            anomaly_n = sum(
                1 for k in markov_outlier_cks
                if org_anomalies_flat[k].get("markov_reason") == "anomaly"
            )
            org_family_markov_reason[family] = (
                "repeated" if repeated_n >= anomaly_n else "anomaly"
            )
        else:
            org_family_markov_reason[family] = None

    # Surface a compact service-account summary on each PRIMARY org anomaly
    # entry so the per-MAC drilldown endpoint (which queries by real MAC at
    # a given site) can show "this MAC also belongs to {label}.service_account,
    # scored as {is_family_outlier}" without an extra Redis lookup.
    for ck in list(org_anomalies_flat):
        if is_sa_record_key(ck):
            continue
        sa_ck = f"{ck}#sa"
        sa_entry = org_anomalies_flat.get(sa_ck)
        if not sa_entry:
            continue
        org_anomalies_flat[ck]["service_account"] = {
            "family": composite_features[ck].get("service_account_family", ""),
            "last_username": composite_features[ck].get("last_username", ""),
            "is_family_outlier": sa_entry["is_family_outlier"],
            "is_if_outlier": sa_entry["is_if_outlier"],
            "if_score": sa_entry["if_score"],
            "centroid_dist_score": sa_entry.get("family_centroid_dist_score"),
        }

    # Raw events cache for post-hoc explainer — loaded once per site on demand
    raw_events_cache: dict[str, dict[str, list[dict]]] = {}

    async def _load_site_events(sid: str) -> "dict[str, list[dict]]":
        if sid not in raw_events_cache:
            # Trailing 24h window — see db.DETECTION_WINDOW_SECONDS.
            evts = await get_events(
                site_id=sid,
                wlan=wlan,
                since=_db.get_detection_cutoff(),
            )
            mac_raw: dict[str, list[dict]] = defaultdict(list)
            for evt in evts:
                m = (evt.get("mac") or "").replace(":", "").lower()
                if m:
                    mac_raw[m].append(evt)
            raw_events_cache[sid] = mac_raw
        return raw_events_cache[sid]

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    site_macs_scored: dict[str, int] = {}

    try:
        # --- Store per-site org anomaly scores (needed for MAC drilldown) ---
        for site_id, site_features in all_features_by_site.items():
            if not site_features:
                site_macs_scored[site_id] = 0
                continue
            site_anomalies: dict[str, dict] = {
                mac: org_anomalies_flat[f"{site_id}:{mac}"].copy()
                for mac in site_features
            }
            key_anomalies = _org_anomalies_redis_key(site_id, wlan)
            await redis_client.set(key_anomalies, json.dumps(site_anomalies), ex=ANOMALIES_TTL)
            log.info(
                f"[org score] Stored org anomaly scores for {len(site_anomalies)} MACs "
                f"→ {key_anomalies}"
            )
            site_macs_scored[site_id] = len(site_anomalies)

        # --- Org-wide finding rollup: one finding per device family across ALL sites ---
        # Each finding represents the full org population for that family, not a single site.
        org_findings: list[dict] = []

        for family, family_cks in org_family_groups.items():
            if family in HIDDEN_FAMILIES:
                continue
            total = len(family_cks)
            org_min_for_finding = _cfg("anomaly_min_peers")
            if total < org_min_for_finding:
                continue

            outlier_cks = [k for k in family_cks if org_anomalies_flat[k]["is_outlier"]]
            outlier_count = len(outlier_cks)
            outlier_ratio = outlier_count / total if total > 0 else 0.0

            # Surface every org-level family with at least one signal. The
            # alarm gate (alarm_dbscan_markov_ratio, applied in
            # webhook_dispatcher and the OrgAlerts feed) decides which findings
            # escalate to alarms; finding visibility is intentionally
            # unconditional so operators can browse low-ratio signal.
            org_dbscan_noise_thresh = _cfg("anomaly_dbscan_family_noise_threshold")
            is_family_dbscan_outlier = (
                family_dbscan_noise_ratio.get(family, 0.0) >= org_dbscan_noise_thresh
            )
            is_family_markov_outlier = org_family_markov_flags.get(family, False)

            if (
                outlier_count == 0
                and not is_family_dbscan_outlier
                and not is_family_markov_outlier
            ):
                continue

            # Per-site breakdown for the sites_affected field
            site_breakdown: dict[str, dict] = defaultdict(
                lambda: {"outlier_count": 0, "total_count": 0}
            )
            for ck in family_cks:
                sid = composite_to_site[ck]
                site_breakdown[sid]["total_count"] += 1
                if org_anomalies_flat[ck]["is_outlier"]:
                    site_breakdown[sid]["outlier_count"] += 1
            sites_affected = [
                {"site_id": sid, "outlier_count": v["outlier_count"], "total_count": v["total_count"]}
                for sid, v in site_breakdown.items()
                if v["outlier_count"] > 0
            ]

            dbscan_outlier_cks = [k for k in family_cks if org_anomalies_flat[k]["is_dbscan_outlier"]]
            if_outlier_cks = [k for k in family_cks if org_anomalies_flat[k]["is_if_outlier"]]
            dbscan_outlier_count = len(dbscan_outlier_cks)
            dbscan_outlier_ratio = dbscan_outlier_count / total

            # DBSCAN-or-Markov per-MAC union for the alarm gate
            # (alarm_dbscan_markov_ratio). Centroid (is_family_outlier) remains
            # an independently sufficient alarm trigger and is NOT counted here.
            dbscan_or_markov_cks = [
                k for k in family_cks
                if org_anomalies_flat[k]["is_dbscan_outlier"]
                or org_anomalies_flat[k]["is_markov_outlier"]
            ]
            dbscan_or_markov_outlier_count = len(dbscan_or_markov_cks)
            dbscan_or_markov_outlier_ratio = (
                dbscan_or_markov_outlier_count / total if total > 0 else 0.0
            )

            family_weights = [org_anomalies_flat[k]["volume_concentration_weight"] for k in family_cks]
            total_weight = sum(family_weights) or 1.0
            outlier_weight_sum = sum(
                org_anomalies_flat[k]["volume_concentration_weight"] for k in outlier_cks
            )
            weighted_outlier_score = outlier_weight_sum / total_weight

            # Top features: org-wide outliers vs org-wide normals for this family
            outlier_vecs = [composite_features[k]["category_vector"] for k in outlier_cks]
            normal_cks = [k for k in family_cks if not org_anomalies_flat[k]["is_outlier"]]
            normal_vecs = [composite_features[k]["category_vector"] for k in normal_cks]
            if not normal_vecs and outlier_vecs:
                family_ck_set = set(family_cks)
                normal_vecs = [
                    composite_features[k]["category_vector"]
                    for k in composite_macs
                    if k not in family_ck_set
                ]
            top_features = _top_contributing_features(outlier_vecs, normal_vecs)

            # Example MACs: top 5 by weight, each carrying its site_id so the UI
            # can route MAC drilldown clicks to the correct site.
            # For sa families the composite mac string carries the "#sa" suffix —
            # strip it via underlying_mac so the GUI displays a clean MAC.
            example_cks = sorted(
                outlier_cks,
                key=lambda k: org_anomalies_flat[k]["volume_concentration_weight"],
                reverse=True,
            )[:5]
            example_macs = [
                {
                    "mac": underlying_mac(composite_to_mac[k]),
                    "site_id": composite_to_site[k],
                }
                for k in example_cks
            ]

            # Post-hoc pattern: aggregate raw events from ALL outlier MACs across
            # all sites. mac_raw events are keyed by REAL MAC, so strip the "#sa"
            # suffix from sa composite mac strings before lookup.
            is_family_level_outlier = family in flagged_families
            family_kind = "service_account" if is_service_account_family(family) else "device_family"
            combined_events: list[dict] = []
            if is_family_level_outlier:
                probable_pattern = "family_behavioral_outlier"
                for ck in outlier_cks:
                    site_evts = await _load_site_events(composite_to_site[ck])
                    combined_events.extend(
                        site_evts.get(underlying_mac(composite_to_mac[ck]), [])
                    )
            else:
                probable_pattern = "behavioral_outlier"
                for ck in outlier_cks:
                    site_evts = await _load_site_events(composite_to_site[ck])
                    combined_events.extend(
                        site_evts.get(underlying_mac(composite_to_mac[ck]), [])
                    )
                if combined_events:
                    posthoc = build_posthoc_features(combined_events)
                    posthoc["event_count"] = len(combined_events)
                    probable_pattern = _classify_probable_pattern(posthoc)

            # For sa findings, surface the human-readable username label and
            # the set of underlying device families this service-account spans
            # so the GUI can render "srv_Apple_EP.service_account
            # (15 MacBooks, 3 Windows)".
            sa_label = ""
            sa_member_families: list[str] = []
            if family_kind == "service_account":
                sa_label = family[: -len(SERVICE_ACCOUNT_SUFFIX)]
                sa_member_families = sorted({
                    composite_features[k].get("primary_device_family", "Unknown")
                    for k in family_cks
                })

            # Worst-health MACs: top 3 across all family members (org-wide) by
            # ascending health score. Each entry carries its own site_id so the
            # webhook TSHOOT enrichment step (and downstream consumers) can
            # target the right Mist site. For sa families the composite mac
            # string carries the "#sa" suffix — strip it via underlying_mac so
            # the displayed mac is always the real one.
            ck_health_scores = {
                ck: _mac_health_score(composite_features[ck]["category_vector"])
                for ck in family_cks
                if ck in composite_features
            }
            worst_health_macs = sorted(
                [
                    {
                        "mac": underlying_mac(composite_to_mac[ck]),
                        "site_id": composite_to_site[ck],
                        "health_score": round(h_score, 4),
                        "health_components": {
                            k: round(v, 4) for k, v in comps.items() if v > 0
                        },
                    }
                    for ck, (h_score, comps) in ck_health_scores.items()
                ],
                key=lambda x: x["health_score"],
            )[:3]

            finding = {
                "device_family": family,
                "family_kind": family_kind,
                "service_account_label": sa_label,
                "service_account_member_families": sa_member_families,
                "wlan": wlan,
                "severity": _severity(outlier_ratio),
                "outlier_ratio": round(outlier_ratio, 4),
                "weighted_outlier_score": round(weighted_outlier_score, 4),
                "affected_mac_count": outlier_count,
                "total_mac_count": total,
                "site_count": len(sites_affected),
                "sites_affected": sites_affected,
                "example_macs": example_macs,
                "worst_health_macs": worst_health_macs,
                "is_family_outlier": is_family_level_outlier,
                "is_family_dbscan_outlier": is_family_dbscan_outlier,
                "is_family_markov_outlier": is_family_markov_outlier,
                "markov_family_reason": org_family_markov_reason.get(family),
                "markov_family_anomaly_ratio": round(org_family_markov_ratio.get(family, 0.0), 4),
                "centroid_dist_score": centroid_dist_scores.get(family),
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                "dbscan_severity": (
                    _severity(dbscan_outlier_ratio) if dbscan_outlier_count > 0 else None
                ),
                "dbscan_outlier_ratio": round(dbscan_outlier_ratio, 4),
                "dbscan_outlier_count": dbscan_outlier_count,
                "dbscan_or_markov_outlier_count": dbscan_or_markov_outlier_count,
                "dbscan_or_markov_outlier_ratio": round(dbscan_or_markov_outlier_ratio, 4),
                "dbscan_outlier_site_count": len({composite_to_site[k] for k in dbscan_outlier_cks}),
                "if_outlier_count": len(if_outlier_cks),
                "top_features": top_features,
                "probable_pattern": probable_pattern,
                "scope": "org",
            }
            org_findings.append(finding)
            log.info(
                f"[org finding] wlan={wlan} [{family}] ({family_kind}): "
                f"{outlier_count}/{total} outliers ({outlier_ratio:.1%}) across "
                f"{len(sites_affected)} sites → {finding['severity']} / {probable_pattern}"
            )

        # Attach volume-weighted org health_score to each finding before storing.
        # Read per-site health from Redis and compute a mac_count-weighted average
        # so that larger sites contribute proportionally to the org health signal.
        org_site_ids = list(all_features_by_site.keys())
        if org_site_ids and org_findings:
            pipe = redis_client.pipeline()
            for _sid in org_site_ids:
                pipe.get(f"sasquatch:health:{_sid}:{sanitize_wlan_key(wlan)}")
            health_raws = await pipe.execute()
            site_health_map: dict[str, dict] = {}
            for _sid, _raw in zip(org_site_ids, health_raws):
                if _raw:
                    try:
                        site_health_map[_sid] = json.loads(_raw)
                    except Exception:
                        pass
            from .health_scorer import (
                SERVICES as _HSCORE_SERVICES,
                FAMILY_SERVICE_ALARM_THRESHOLD as _HSCORE_FAMILY_SVC_THRESHOLD,
            )
            for _f in org_findings:
                _family = _f["device_family"]
                _wsum = 0.0
                _wcount = 0
                _comp_wsum: dict[str, float] = {}
                _comp_wcount: dict[str, float] = {}
                # Per-service org rollup: sum active/unhealthy MAC counts across sites
                # so the org-level alarm threshold applies to the full device-family scope.
                _svc_active: dict[str, int] = {svc: 0 for svc in _HSCORE_SERVICES}
                _svc_unhealthy: dict[str, int] = {svc: 0 for svc in _HSCORE_SERVICES}
                _svc_health_wsum: dict[str, float] = {svc: 0.0 for svc in _HSCORE_SERVICES}
                # Org-level device-alarm rollup: sum the per-site MAC counts that
                # tripped at least one service alarm so the percentage gate
                # applies to the full org-wide family population.
                _mac_alarm_count_total = 0
                for _sh in site_health_map.values():
                    _fh = _sh.get(_family)
                    if not _fh:
                        continue
                    _n = _fh.get("mac_count", 1)
                    _wsum += _fh.get("health_score", 1.0) * _n
                    _wcount += _n
                    _mac_alarm_count_total += int(_fh.get("mac_alarm_count", 0) or 0)
                    for _cat, _val in _fh.get("components", {}).items():
                        _comp_wsum[_cat] = _comp_wsum.get(_cat, 0.0) + _val * _n
                        _comp_wcount[_cat] = _comp_wcount.get(_cat, 0.0) + _n
                    _site_svc_counts = _fh.get("service_alarm_counts", {}) or {}
                    _site_svc_health = _fh.get("service_health", {}) or {}
                    for _svc in _HSCORE_SERVICES:
                        _info = _site_svc_counts.get(_svc) or {}
                        _a = int(_info.get("active", 0))
                        _u = int(_info.get("unhealthy", 0))
                        _svc_active[_svc] += _a
                        _svc_unhealthy[_svc] += _u
                        _sh_val = _site_svc_health.get(_svc)
                        if _sh_val is not None and _a > 0:
                            _svc_health_wsum[_svc] += float(_sh_val) * _a
                if _wcount > 0:
                    _f["health_score"] = round(_wsum / _wcount, 4)
                    _f["health_components"] = {
                        _cat: round(_comp_wsum[_cat] / _comp_wcount[_cat], 4)
                        for _cat in _comp_wsum
                    }
                else:
                    _f["health_score"] = 1.0
                    _f["health_components"] = {}

                _service_health: dict[str, float | None] = {}
                _service_alarm_counts: dict[str, dict[str, int]] = {}
                _service_alarms: list[str] = []
                for _svc in _HSCORE_SERVICES:
                    _a = _svc_active[_svc]
                    _u = _svc_unhealthy[_svc]
                    _service_alarm_counts[_svc] = {"active": _a, "unhealthy": _u}
                    if _a > 0:
                        _service_health[_svc] = round(_svc_health_wsum[_svc] / _a, 4)
                        if (_u / _a) > _HSCORE_FAMILY_SVC_THRESHOLD:
                            _service_alarms.append(_svc)
                    else:
                        _service_health[_svc] = None
                _f["service_health"] = _service_health
                _f["service_alarm_counts"] = _service_alarm_counts
                _f["service_alarms"] = _service_alarms
                _f["mac_alarm_count"] = _mac_alarm_count_total
                _total_macs = int(_f.get("total_mac_count", 0) or 0)
                _f["mac_alarm_ratio"] = (
                    round(_mac_alarm_count_total / _total_macs, 4)
                    if _total_macs > 0 else 0.0
                )

        severity_order = {"significant": 0, "moderate": 1, "minimal": 2}
        org_findings.sort(
            key=lambda f: (severity_order.get(f["severity"], 3), -f["weighted_outlier_score"])
        )

        key_findings = _org_findings_redis_key(wlan)
        await redis_client.set(key_findings, json.dumps(org_findings), ex=FINDINGS_TTL)
        log.info(f"[org score] Stored {len(org_findings)} org-wide findings → {key_findings}")

    finally:
        await redis_client.aclose()

    return site_macs_scored


async def get_anomalies(site_id: str, wlan: str) -> dict[str, dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_anomalies_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return {}
    return json.loads(raw)


async def get_findings(site_id: str, wlan: str) -> list[dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_findings_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return []
    return json.loads(raw)


async def get_org_findings(wlan: str) -> list[dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_org_findings_redis_key(wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return []
    return json.loads(raw)

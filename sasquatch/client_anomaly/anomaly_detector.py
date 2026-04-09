"""
anomaly_detector.py — three-stage anomaly detection pipeline.

Stage 1: DBSCAN across all MACs in the WLAN scope. MACs that land in noise (label=-1)
         indicate anomalous behavior. DBSCAN results set dbscan_label, is_dbscan_outlier,
         and dbscan_family_noise_ratio on each MAC record.

         Family-level outlier detection (is_family_outlier) is determined by a separate
         family centroid Isolation Forest step: one mean feature vector is computed per
         device family, IF is run across all family centroids, and families whose centroid
         is an outlier among other families are flagged. Requires at least
         CENTROID_IF_MIN_FAMILIES (default 3) qualifying families (≥2 MACs each).

Stage 2: Isolation Forest within each device family. Identifies specific endpoint MACs
         whose behavior is anomalous relative to their family peer group.

Stage 3: Rule-based absolute threshold detection. Runs on every MAC regardless of
         family size or peer availability. Catches pathological behavior that is
         anomalous in absolute terms — e.g. a client whose events are 70% auth failures
         — which peer-comparison methods miss when the family is too small to score.

Stage 4: Markov Chain episode analysis (see markov_analyzer.py).
         Two-layer analysis: event-level transition scoring within episodes, plus an
         episode-type state machine tracking short (failed) vs normal episode sequences.
         Requires a pre-built 24hr baseline (sasquatch:markov_baseline:{site_id}:{wlan_key})
         populated by the daily markov_baseline_job. Skipped silently on first run until
         the baseline is available.

Finding rollup: aggregate per-family outlier ratios → findings list.

Anomaly labels on findings:
  is_family_outlier       — centroid IF/distance (IF Stage)
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
from sklearn.preprocessing import StandardScaler

from . import config
from .event_collector import get_events, sanitize_wlan_key
from .feature_engineer import (
    FEATURE_KEYS,
    build_posthoc_features,
    get_features,
)
from .health_scorer import _mac_health_score
from .markov_analyzer import run_markov_analysis

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
ANOMALIES_TTL = 24 * 3600
FINDINGS_TTL = 24 * 3600


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


def _extract_vector_array(feature_records: list[dict]) -> np.ndarray:
    """Convert list of feature record dicts to a numpy array."""
    if not feature_records:
        return np.empty((0, 0))
    keys = list(feature_records[0]["vector"].keys())
    return np.array([[r["vector"].get(k, 0.0) for k in keys] for r in feature_records])


def _run_isolation_forest(
    macs: list[str], feature_records: list[dict]
) -> dict[str, dict]:
    """
    Run Isolation Forest on a group of MACs (same device family).
    Returns per-MAC dict with if_score and is_if_outlier.
    """
    X = _extract_vector_array(feature_records)
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

    results = {}
    for i, mac in enumerate(macs):
        results[mac] = {
            "if_score": float(raw_scores[i]),
            "is_if_outlier": bool(labels[i] == -1),
        }
    return results


def _run_dbscan(macs: list[str], feature_records: list[dict]) -> dict[str, dict]:
    """
    Run DBSCAN across all MACs in the WLAN scope.
    PCA reduction is applied before DBSCAN to mitigate the curse of dimensionality:
    Euclidean distance degrades in 61-dimensional space (all points tend toward the
    same inter-point distance), and the sparse frequency vectors make this worse.
    PCA is not applied before Isolation Forest — IF splits on one random feature at
    a time and handles high-dimensional sparse vectors without distance degradation.
    Returns per-MAC dict with dbscan_label and is_dbscan_outlier.
    """
    X = _extract_vector_array(feature_records)
    if X.shape[0] < _cfg("anomaly_dbscan_min_samples"):
        return {
            mac: {"dbscan_label": -1, "is_dbscan_outlier": True}
            for mac in macs
        }

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Reduce dimensionality before DBSCAN. n_components=0.95 keeps enough components
    # to explain 95% of variance. For sparse 61-dim frequency vectors this typically
    # collapses to 8–15 components, making Euclidean distance meaningful again.
    # Cap at n_samples - 1 so PCA doesn't fail on small populations.
    max_components = min(X_scaled.shape[0] - 1, X_scaled.shape[1])
    pca = PCA(n_components=min(_cfg("anomaly_dbscan_pca_variance"), max_components), random_state=_random_state())
    X_reduced = pca.fit_transform(X_scaled)
    log.info(
        "DBSCAN PCA: %d MACs, %d→%d dims (%.1f%% variance explained)",
        X_scaled.shape[0],
        X_scaled.shape[1],
        pca.n_components_,
        pca.explained_variance_ratio_.sum() * 100,
    )

    db = DBSCAN(eps=_cfg("anomaly_dbscan_eps"), min_samples=_cfg("anomaly_dbscan_min_samples"))
    labels = db.fit_predict(X_reduced)

    return {
        mac: {
            "dbscan_label": int(labels[i]),
            "is_dbscan_outlier": bool(labels[i] == -1),
        }
        for i, mac in enumerate(macs)
    }


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



def _run_family_centroid_if(
    family_groups: dict[str, list[str]],
    features: dict[str, dict],
    family_health: dict[str, float] | None = None,
) -> dict[str, float]:
    """
    Family centroid Isolation Forest.

    For each family with >= 2 MACs, build a dual-representation row:
      - median vector: element-wise median across all MACs in the family.
        More robust than the mean — a single anomalous MAC doesn't shift it.
        Captures whole-family behavioral shifts.
      - max vector: component-wise maximum across all MACs in the family.
        Captures the behavioral ceiling of the family — what the most extreme
        any member does on each feature dimension.

    The two vectors are concatenated into a single row so the IF model can
    jointly reason about both the family's central tendency and its internal
    spread. This prevents the mean-centroid averaging problem: a family with
    one healthy and one anomalous MAC no longer collapses to a midpoint —
    the max vector preserves the anomalous MAC's signal on the dimensions
    where it is extreme.

    family_health: optional dict of {family: mean_health_score}. When provided
    and at least CENTROID_HEALTHY_REF_MIN families are healthy (score >=
    CENTROID_HEALTHY_REF_THRESHOLD), the IF model is fitted on healthy families
    only. All families — including unhealthy ones — are then scored against that
    healthy model via decision_function. Families that fail together form their
    own cluster that the healthy-fitted model has never seen, so they score as
    anomalous even when they are internally consistent with each other.

    Returns {family_name: if_score} for every qualifying family.
    Negative scores indicate the row is an outlier among family rows.
    Returns {} if fewer than CENTROID_IF_MIN_FAMILIES families qualify.
    """
    qualifying: list[tuple[str, np.ndarray]] = []
    for family, macs in family_groups.items():
        if len(macs) < 2:
            continue
        vectors = np.array([
            [features[mac]["vector"].get(k, 0.0) for k in FEATURE_KEYS]
            for mac in macs
            if mac in features
        ])
        if vectors.shape[0] == 0:
            continue
        median_vec = np.median(vectors, axis=0)
        max_vec = vectors.max(axis=0)
        combined = np.concatenate([median_vec, max_vec])
        qualifying.append((family, combined))

    centroid_min = _cfg("anomaly_centroid_if_min_families")
    if len(qualifying) < centroid_min:
        log.info(
            f"Centroid IF: skipped — only {len(qualifying)} qualifying "
            f"families (need >= {centroid_min})"
        )
        return {}

    family_names = [name for name, _ in qualifying]
    X = np.array([vec for _, vec in qualifying])

    # Determine whether to use healthy-only reference for fitting.
    healthy_ref_threshold = _cfg("anomaly_centroid_healthy_ref_threshold")
    healthy_ref_min = _cfg("anomaly_centroid_healthy_ref_min")
    healthy_indices: list[int] = []
    if family_health is not None:
        healthy_indices = [
            i for i, name in enumerate(family_names)
            if family_health.get(name, 1.0) >= healthy_ref_threshold
        ]

    use_healthy_ref = len(healthy_indices) >= healthy_ref_min
    centroid_contamination = _cfg("anomaly_centroid_if_contamination")
    rs = _random_state()
    n_est = _cfg("anomaly_if_n_estimators")
    if use_healthy_ref:
        X_healthy = X[healthy_indices]
        scaler = StandardScaler()
        scaler.fit(X_healthy)
        X_scaled = scaler.transform(X)
        X_healthy_scaled = scaler.transform(X_healthy)
        clf = IsolationForest(
            contamination=centroid_contamination,
            random_state=rs,
            n_estimators=n_est,
        )
        clf.fit(X_healthy_scaled)
        log.info(
            "Centroid IF: using healthy-only reference (%d/%d families, health >= %.2f)",
            len(healthy_indices), len(family_names), healthy_ref_threshold,
        )
    else:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        clf = IsolationForest(
            contamination=centroid_contamination,
            random_state=rs,
            n_estimators=n_est,
        )
        clf.fit(X_scaled)
        if family_health is not None:
            log.info(
                "Centroid IF: fell back to all-family reference "
                "(only %d healthy families, need >= %d)",
                len(healthy_indices), healthy_ref_min,
            )

    raw_scores = clf.decision_function(X_scaled)

    return {family_names[i]: float(raw_scores[i]) for i in range(len(family_names))}


def _run_family_centroid_distance(
    family_groups: dict[str, list[str]],
    features: dict[str, dict],
    family_health: dict[str, float] | None = None,
) -> dict[str, float]:
    """
    Cosine-distance fallback for inter-family centroid anomaly detection.

    Used when CENTROID_IF_MIN_FAMILIES <= N <= CENTROID_DIST_MAX_FAMILIES qualifying
    families. IsolationForest is statistically weak at small N (5–8 rows); a
    distance-based approach gives more interpretable and stable results.

    Builds the same dual-representation rows as _run_family_centroid_if (element-wise
    median + max of per-MAC vectors, concatenated). After L2-normalization, computes
    the element-wise median of family rows as the population reference point. Each
    family's cosine distance from that reference is returned.

    The median (not mean) is used as the reference to resist the masking effect:
    if one family is genuinely anomalous its centroid row would pull a mean reference
    toward itself, artificially reducing its apparent distance. The median is resistant
    to this shift.

    family_health: optional dict of {family: mean_health_score}. When provided and at
    least CENTROID_HEALTHY_REF_MIN families are healthy (score >= CENTROID_HEALTHY_REF_THRESHOLD),
    the reference centroid is built from ONLY those healthy families. Every family —
    including unhealthy ones — is then measured against this healthy reference. This
    means families that all fail the same way (forming their own cluster) are still
    flagged because their shared failure signature points away from the healthy reference,
    even if none of them looks anomalous relative to the others.

    Returns {family_name: cosine_distance} for every qualifying family.
    Values near 0.0 are behaviorally close to the reference.
    Values approaching or exceeding CENTROID_DIST_THRESHOLD are flagged as outliers.
    Returns {} if fewer than CENTROID_IF_MIN_FAMILIES families qualify.
    """
    qualifying: list[tuple[str, np.ndarray]] = []
    for family, macs in family_groups.items():
        if len(macs) < 2:
            continue
        vectors = np.array([
            [features[mac]["vector"].get(k, 0.0) for k in FEATURE_KEYS]
            for mac in macs
            if mac in features
        ])
        if vectors.shape[0] == 0:
            continue
        median_vec = np.median(vectors, axis=0)
        max_vec = vectors.max(axis=0)
        combined = np.concatenate([median_vec, max_vec])
        qualifying.append((family, combined))

    centroid_min = _cfg("anomaly_centroid_if_min_families")
    if len(qualifying) < centroid_min:
        log.info(
            "Centroid distance: skipped — only %d qualifying families (need >= %d)",
            len(qualifying), centroid_min,
        )
        return {}

    family_names = [name for name, _ in qualifying]
    X = np.array([vec for _, vec in qualifying])

    # L2-normalize each row so cosine distance is geometrically meaningful
    # (measures angle between family behavior profiles, not magnitude).
    # Do NOT apply StandardScaler here: StandardScaler makes each feature zero-mean
    # across the small set of family rows, so the median reference becomes ≈ the zero
    # vector — cosine distance from a near-zero vector is undefined and produces
    # distances near 1.0 for everything, causing mass false-positive flagging.
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
            "Centroid distance: using healthy-only reference (%d/%d families, health >= %.2f)",
            len(healthy_indices), len(family_names), healthy_ref_threshold,
        )
    else:
        X_ref = X_norm
        if family_health is not None:
            log.info(
                "Centroid distance: fell back to all-family reference "
                "(only %d healthy families, need >= %d)",
                len(healthy_indices), healthy_ref_min,
            )

    # Element-wise median of reference rows, re-normalized to a unit vector.
    reference = np.median(X_ref, axis=0).reshape(1, -1)
    ref_norm = np.linalg.norm(reference)
    if ref_norm > 0:
        reference = reference / ref_norm

    dists = cosine_distances(X_norm, reference).flatten()
    return {family_names[i]: float(dists[i]) for i in range(len(family_names))}


def _dispatch_centroid_detection(
    family_groups: dict[str, list[str]],
    features: dict[str, dict],
    wlan: str = "?",
    family_health: dict[str, float] | None = None,
) -> tuple[dict[str, float], dict[str, float], str]:
    """
    Select and run the appropriate inter-family centroid anomaly check based on N:
      - N < CENTROID_IF_MIN_FAMILIES: skip entirely
      - CENTROID_IF_MIN_FAMILIES <= N <= CENTROID_DIST_MAX_FAMILIES: cosine distance
      - N > CENTROID_DIST_MAX_FAMILIES: Isolation Forest

    family_health: optional per-family mean health scores passed through to the
    sub-functions so they can build a healthy-only reference centroid. See
    _run_family_centroid_distance and _run_family_centroid_if for details.

    Returns (centroid_if_scores, centroid_dist_scores, method).
    Exactly one score dict will be non-empty, or both empty if skipped.
    method is one of "if", "distance", or "skipped".
    """
    n_qualifying = sum(1 for macs in family_groups.values() if len(macs) >= 2)

    centroid_min = _cfg("anomaly_centroid_if_min_families")
    if n_qualifying < centroid_min:
        log.info(
            "Centroid detection [%s]: skipped — %d qualifying families (need >= %d)",
            wlan, n_qualifying, centroid_min,
        )
        return {}, {}, "skipped"

    if n_qualifying <= _cfg("anomaly_centroid_dist_max_families"):
        dist_scores = _run_family_centroid_distance(family_groups, features, family_health)
        log.info(
            "Centroid detection [%s]: distance method (%d families) — scores: %s",
            wlan, n_qualifying,
            {f: f"{s:.4f}" for f, s in sorted(dist_scores.items(), key=lambda x: -x[1])},
        )
        return {}, dist_scores, "distance"

    if_scores = _run_family_centroid_if(family_groups, features, family_health)
    log.info(
        "Centroid detection [%s]: IF method (%d families) — scores: %s",
        wlan, n_qualifying,
        {f: f"{s:.4f}" for f, s in sorted(if_scores.items(), key=lambda x: x[1])},
    )
    return if_scores, {}, "if"


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
            log.info(
                f"No qualifying MACs for site {site_id} / wlan={wlan} "
                f"(all below MIN_MAC_EVENTS threshold) — skipping score"
            )
            return 0

        # Load raw events for post-hoc explainer (only used for outliers)
        events = await get_events(
            site_id=site_id,
            wlan=wlan,
        )
        mac_raw_events: dict[str, list[dict]] = defaultdict(list)
        for evt in events:
            mac = (evt.get("mac") or "").replace(":", "").lower()
            if mac:
                mac_raw_events[mac].append(evt)

        # Build family groups
        family_groups: dict[str, list[str]] = defaultdict(list)
        for mac, record in features.items():
            family = record.get("device_family", "Unknown")
            family_groups[family].append(mac)

        # --- Stage 4: Markov Chain episode analysis ---
        # Requires a pre-built 24hr baseline; skipped silently if absent.
        # event_type_index is loaded inside run_markov_analysis via the baseline.
        from .event_collector import ensure_event_type_index
        event_type_index = await ensure_event_type_index(redis_client)
        markov_results = await run_markov_analysis(
            site_id=site_id,
            wlan=wlan,
            mac_raw_events=dict(mac_raw_events),
            family_groups=dict(family_groups),
            redis_client=redis_client,
            event_type_index=event_type_index,
        )
        markov_family_flags: dict[str, dict] = markov_results.pop("__family_markov__", {})

        # --- Stage 1: DBSCAN across all MACs in WLAN scope ---
        # Only include MACs from families large enough to contribute meaningful signal.
        dbscan_eligible_macs = [
            mac for mac in features
            if len(family_groups.get(features[mac].get("device_family", "Unknown"), [])) >= _cfg("anomaly_dbscan_min_family_size")
        ]
        excluded_from_dbscan = set(features.keys()) - set(dbscan_eligible_macs)

        dbscan_eligible_records = [features[m] for m in dbscan_eligible_macs]
        dbscan_results_eligible = _run_dbscan(dbscan_eligible_macs, dbscan_eligible_records)

        dbscan_results: dict[str, dict] = {**dbscan_results_eligible}
        for mac in excluded_from_dbscan:
            dbscan_results[mac] = {"dbscan_label": None, "is_dbscan_outlier": False}

        if excluded_from_dbscan:
            excluded_families = {features[m].get("device_family", "Unknown") for m in excluded_from_dbscan}
            log.info(
                f"DBSCAN [{wlan}]: excluded {len(excluded_from_dbscan)} MACs from "
                f"{len(excluded_families)} small families: {excluded_families}"
            )

        # Compute DBSCAN noise ratio per family (stored on anomaly records and used
        # by the frontend). No longer used to populate flagged_families.
        family_dbscan_noise_ratio: dict[str, float] = {}
        for family, family_macs in family_groups.items():
            eligible = [m for m in family_macs if m in dbscan_results_eligible]
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
        family_health: dict[str, float] = {}
        for _fam, _macs in family_groups.items():
            _scores = [_mac_health_score(features[m]["vector"])[0] for m in _macs if m in features]
            family_health[_fam] = sum(_scores) / len(_scores) if _scores else 1.0
        log.info(
            "Family health scores [%s]: %s",
            wlan,
            {f: f"{s:.2f}" for f, s in sorted(family_health.items(), key=lambda x: x[1])},
        )

        # Dispatches to cosine-distance (small N) or IF (large N) based on how many
        # qualifying families are present. See _dispatch_centroid_detection for thresholds.
        centroid_if_scores, centroid_dist_scores, centroid_method = (
            _dispatch_centroid_detection(family_groups, features, wlan, family_health)
        )
        flagged_families: set[str] = set()
        for family, if_score in centroid_if_scores.items():
            if if_score < 0:
                flagged_families.add(family)
                log.info("Centroid IF [%s]: family [%s] flagged (score=%.4f)", wlan, family, if_score)
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
                "family_centroid_if_score": centroid_if_scores.get(family),
                "family_centroid_dist_score": centroid_dist_scores.get(family),
                "centroid_detection_method": centroid_method,
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                # Markov Chain fields
                "is_markov_outlier": is_markov,
                "markov_total_episodes": markov_rec.get("markov_total_episodes", 0),
                "markov_scoreable_episodes": markov_rec.get("markov_scoreable_episodes", 0),
                "markov_anomalous_episodes": markov_rec.get("markov_anomalous_episodes", 0),
                "markov_episode_anomaly_ratio": markov_rec.get("markov_episode_anomaly_ratio", 0.0),
                "markov_short_episodes": markov_rec.get("markov_short_episodes", 0),
                "markov_short_episode_ratio": markov_rec.get("markov_short_episode_ratio", 0.0),
                "has_repeated_short_episodes": markov_rec.get("has_repeated_short_episodes", False),
                "short_episode_dominant_pattern": markov_rec.get("short_episode_dominant_pattern"),
                "markov_episode_seq_score": markov_rec.get("markov_episode_seq_score", 0.0),
                "is_stuck_loop": markov_rec.get("is_stuck_loop", False),
                "stuck_loop_pair": markov_rec.get("stuck_loop_pair"),
                "stuck_loop_fraction": markov_rec.get("stuck_loop_fraction", 0.0),
                "is_outlier": is_if or is_db or is_family or is_markov,
                "device_family": family,
                "event_count": features[mac].get("event_count", 0),
                "random_mac": features[mac].get("random_mac", False),
                "volume_concentration_weight": features[mac].get("volume_concentration_weight", 1.0),
            }

        key_anomalies = _anomalies_redis_key(site_id, wlan)
        await redis_client.set(key_anomalies, json.dumps(anomalies), ex=ANOMALIES_TTL)
        log.info(f"Stored anomaly scores for {len(anomalies)} MACs → {key_anomalies}")

        # --- Finding rollup per device family ---
        findings: list[dict] = []
        for family, family_macs in family_groups.items():
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

            # Evaluate Markov family flag here so it can bypass the finding threshold.
            # A family where enough MACs have anomalous episode patterns warrants a
            # finding even if the combined IF/DBSCAN/Markov MAC-level outlier ratio
            # is below the finding threshold.
            fam_markov = markov_family_flags.get(family, {})
            is_family_markov_outlier = fam_markov.get("is_family_markov_outlier", False)
            markov_family_anomaly_ratio = fam_markov.get("markov_family_anomaly_ratio", 0.0)
            markov_evaluatable_count = fam_markov.get("markov_evaluatable_count", 0)
            markov_family_anomalous_count = fam_markov.get("markov_family_anomalous_count", 0)

            finding_threshold = _cfg("anomaly_finding_threshold")
            if outlier_ratio < finding_threshold and not is_family_markov_outlier:
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

            outlier_vecs = [features[m]["vector"] for m in outlier_macs]
            normal_macs = [m for m in family_macs if not anomalies[m]["is_outlier"]]
            normal_vecs = [features[m]["vector"] for m in normal_macs]

            # For family-wide outliers the entire family is flagged, leaving normal_vecs
            # empty. Fall back to the rest of the site population as the baseline so
            # top_features reflects how this family differs from all other devices.
            if not normal_vecs and outlier_vecs:
                family_mac_set = set(family_macs)
                normal_vecs = [features[m]["vector"] for m in features if m not in family_mac_set]

            top_features = _top_contributing_features(outlier_vecs, normal_vecs)

            # Post-hoc pattern classification
            is_family_level_outlier = family in flagged_families
            if is_family_level_outlier:
                probable_pattern = "family_behavioral_outlier"
            else:
                probable_pattern = "behavioral_outlier"
                if outlier_macs:
                    combined_events = [
                        evt
                        for mac in outlier_macs
                        for evt in mac_raw_events.get(mac, [])
                    ]
                    if combined_events:
                        posthoc = build_posthoc_features(combined_events)
                        posthoc["event_count"] = len(combined_events)
                        probable_pattern = _classify_probable_pattern(posthoc)

            # Worst-health MACs: top 3 across all family MACs by health score (ascending).
            # Used by alert cards in the UI and webhook payload to surface the specific
            # devices experiencing the most failures — independent of outlier scoring.
            mac_health_scores = {
                m: _mac_health_score(features[m]["vector"])
                for m in family_macs
            }
            worst_health_macs = sorted(
                [
                    {
                        "mac": m,
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

            finding = {
                "device_family": family,
                "wlan": wlan,
                "severity": _severity(outlier_ratio),
                "outlier_ratio": round(outlier_ratio, 4),
                "weighted_outlier_score": round(weighted_outlier_score, 4),
                "affected_mac_count": outlier_count,
                "total_mac_count": total,
                "is_family_outlier": is_family_level_outlier,
                "is_family_dbscan_outlier": is_family_dbscan_outlier,
                "is_family_markov_outlier": is_family_markov_outlier,
                "centroid_if_score": centroid_if_scores.get(family),
                "centroid_dist_score": centroid_dist_scores.get(family),
                "centroid_detection_method": centroid_method,
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                "dbscan_severity": _severity(dbscan_outlier_ratio) if dbscan_outlier_count > 0 else None,
                "dbscan_outlier_ratio": round(dbscan_outlier_ratio, 4),
                "dbscan_outlier_count": dbscan_outlier_count,
                "if_outlier_macs": if_outlier_macs,
                "if_outlier_count": len(if_outlier_macs),
                "markov_family_anomaly_ratio": round(markov_family_anomaly_ratio, 4),
                "markov_evaluatable_count": markov_evaluatable_count,
                "markov_family_anomalous_count": markov_family_anomalous_count,
                "example_macs": sorted(
                    outlier_macs,
                    key=lambda m: anomalies[m]["volume_concentration_weight"],
                    reverse=True,
                )[:5],
                "worst_health_macs": worst_health_macs,
                "top_features": top_features,
                "probable_pattern": probable_pattern,
            }
            findings.append(finding)
            log.info(
                f"Finding [{wlan}] [{family}]: {outlier_count}/{total} outliers "
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

    # Build org-wide family groups (keyed by composite MAC)
    org_family_groups: dict[str, list[str]] = defaultdict(list)
    for key in composite_macs:
        family = composite_features[key].get("device_family", "Unknown")
        org_family_groups[family].append(key)

    # --- Stage 1: DBSCAN across all org MACs ---
    dbscan_eligible_keys = [
        k for k in composite_macs
        if len(org_family_groups.get(
            composite_features[k].get("device_family", "Unknown"), []
        )) >= _cfg("anomaly_dbscan_min_family_size")
    ]
    excluded_from_dbscan = set(composite_macs) - set(dbscan_eligible_keys)

    dbscan_results_eligible = _run_dbscan(
        dbscan_eligible_keys,
        [composite_features[k] for k in dbscan_eligible_keys],
    )

    dbscan_results: dict[str, dict] = {**dbscan_results_eligible}
    for key in excluded_from_dbscan:
        dbscan_results[key] = {"dbscan_label": None, "is_dbscan_outlier": False}

    if excluded_from_dbscan:
        excluded_families = {
            composite_features[k].get("device_family", "Unknown")
            for k in excluded_from_dbscan
        }
        log.info(
            f"[org DBSCAN] wlan={wlan}: excluded {len(excluded_from_dbscan)} MACs "
            f"from {len(excluded_families)} small families: {excluded_families}"
        )

    # DBSCAN noise ratio per family (stored on anomaly records)
    family_dbscan_noise_ratio: dict[str, float] = {}
    for family, family_keys in org_family_groups.items():
        eligible = [k for k in family_keys if k in dbscan_results_eligible]
        if not eligible:
            family_dbscan_noise_ratio[family] = 0.0
            continue
        noise_count = sum(1 for k in eligible if dbscan_results[k]["is_dbscan_outlier"])
        family_dbscan_noise_ratio[family] = noise_count / len(eligible)

    # --- Family centroid detection across all org families ---
    # Compute per-family mean health from feature vectors so the centroid detection
    # can build a healthy-only reference. Unhealthy families are still scored against it.
    org_family_health: dict[str, float] = {}
    for _fam, _cks in org_family_groups.items():
        _scores = [
            _mac_health_score(composite_features[k]["vector"])[0]
            for k in _cks
            if k in composite_features
        ]
        org_family_health[_fam] = sum(_scores) / len(_scores) if _scores else 1.0
    log.info(
        "[org] Family health scores [%s]: %s",
        wlan,
        {f: f"{s:.2f}" for f, s in sorted(org_family_health.items(), key=lambda x: x[1])},
    )

    centroid_if_scores, centroid_dist_scores, centroid_method = (
        _dispatch_centroid_detection(org_family_groups, composite_features, f"org/{wlan}", org_family_health)
    )
    flagged_families: set[str] = set()
    for family, if_score in centroid_if_scores.items():
        if if_score < 0:
            flagged_families.add(family)
            log.info(
                "[org Centroid IF] wlan=%s: family [%s] flagged (score=%.4f)",
                wlan, family, if_score,
            )
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
    org_anomalies_flat: dict[str, dict] = {}
    for key in composite_macs:
        family = composite_features[key].get("device_family", "Unknown")
        org_anomalies_flat[key] = {
            "if_score": if_results[key]["if_score"],
            "is_if_outlier": if_results[key]["is_if_outlier"],
            "dbscan_label": dbscan_results[key]["dbscan_label"],
            "is_dbscan_outlier": dbscan_results[key]["is_dbscan_outlier"],
            "is_family_outlier": family in flagged_families,
            "family_centroid_if_score": centroid_if_scores.get(family),
            "family_centroid_dist_score": centroid_dist_scores.get(family),
            "centroid_detection_method": centroid_method,
            "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
            # Markov fields populated below from per-site anomaly records
            "is_markov_outlier": False,
            "is_outlier": if_results[key]["is_if_outlier"]
                or dbscan_results[key]["is_dbscan_outlier"]
                or (family in flagged_families),
            "device_family": family,
            "event_count": composite_features[key].get("event_count", 0),
            "random_mac": composite_features[key].get("random_mac", False),
            "volume_concentration_weight": composite_features[key].get(
                "volume_concentration_weight", 1.0
            ),
        }

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
            except Exception:
                continue
            for mac_m, rec in site_anoms.items():
                ck = f"{site_id_m}:{mac_m}"
                if ck in org_anomalies_flat and rec.get("is_markov_outlier"):
                    org_anomalies_flat[ck]["is_markov_outlier"] = True
                    # Update composite is_outlier to reflect Markov
                    org_anomalies_flat[ck]["is_outlier"] = (
                        org_anomalies_flat[ck]["is_outlier"] or True
                    )
    finally:
        await _org_markov_redis.aclose()

    # Org-wide family Markov rollup — derived from merged MAC-level is_markov_outlier
    org_family_markov_flags: dict[str, bool] = {}
    org_family_markov_ratio: dict[str, float] = {}
    for family, family_cks in org_family_groups.items():
        # Only count MACs that had any Markov data (is_markov_outlier is explicitly set)
        # As a proxy for "evaluatable", we count all composite keys — if the per-site
        # anomaly record was absent, is_markov_outlier defaulted to False, so this is
        # a conservative estimate.
        total_cks = len(family_cks)
        if total_cks == 0:
            org_family_markov_flags[family] = False
            org_family_markov_ratio[family] = 0.0
            continue
        markov_outlier_cks = [k for k in family_cks if org_anomalies_flat[k].get("is_markov_outlier")]
        ratio = len(markov_outlier_cks) / total_cks
        org_family_markov_flags[family] = ratio >= _cfg("markov_family_outlier_ratio")
        org_family_markov_ratio[family] = ratio

    # Raw events cache for post-hoc explainer — loaded once per site on demand
    raw_events_cache: dict[str, dict[str, list[dict]]] = {}

    async def _load_site_events(sid: str) -> "dict[str, list[dict]]":
        if sid not in raw_events_cache:
            evts = await get_events(
                site_id=sid,
                wlan=wlan,
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
            total = len(family_cks)
            org_min_for_finding = _cfg("anomaly_min_peers")
            if total < org_min_for_finding:
                continue

            outlier_cks = [k for k in family_cks if org_anomalies_flat[k]["is_outlier"]]
            outlier_count = len(outlier_cks)
            outlier_ratio = outlier_count / total if total > 0 else 0.0

            # Evaluate family-level DBSCAN and Markov flags before the threshold gate so
            # they can bypass it — mirrors site-level rollup logic (line ~712).
            org_dbscan_noise_thresh = _cfg("anomaly_dbscan_family_noise_threshold")
            is_family_dbscan_outlier = (
                family_dbscan_noise_ratio.get(family, 0.0) >= org_dbscan_noise_thresh
            )
            is_family_markov_outlier = org_family_markov_flags.get(family, False)

            org_finding_threshold = _cfg("anomaly_finding_threshold")
            if outlier_ratio < org_finding_threshold and not is_family_dbscan_outlier and not is_family_markov_outlier:
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

            family_weights = [org_anomalies_flat[k]["volume_concentration_weight"] for k in family_cks]
            total_weight = sum(family_weights) or 1.0
            outlier_weight_sum = sum(
                org_anomalies_flat[k]["volume_concentration_weight"] for k in outlier_cks
            )
            weighted_outlier_score = outlier_weight_sum / total_weight

            # Top features: org-wide outliers vs org-wide normals for this family
            outlier_vecs = [composite_features[k]["vector"] for k in outlier_cks]
            normal_cks = [k for k in family_cks if not org_anomalies_flat[k]["is_outlier"]]
            normal_vecs = [composite_features[k]["vector"] for k in normal_cks]
            if not normal_vecs and outlier_vecs:
                family_ck_set = set(family_cks)
                normal_vecs = [
                    composite_features[k]["vector"]
                    for k in composite_macs
                    if k not in family_ck_set
                ]
            top_features = _top_contributing_features(outlier_vecs, normal_vecs)

            # Example MACs: top 5 by weight, each carrying its site_id so the UI
            # can route MAC drilldown clicks to the correct site.
            example_cks = sorted(
                outlier_cks,
                key=lambda k: org_anomalies_flat[k]["volume_concentration_weight"],
                reverse=True,
            )[:5]
            example_macs = [
                {"mac": composite_to_mac[k], "site_id": composite_to_site[k]}
                for k in example_cks
            ]

            # Post-hoc pattern: aggregate raw events from ALL outlier MACs across all sites
            is_family_level_outlier = family in flagged_families
            combined_events: list[dict] = []
            if is_family_level_outlier:
                probable_pattern = "family_behavioral_outlier"
                for ck in outlier_cks:
                    site_evts = await _load_site_events(composite_to_site[ck])
                    combined_events.extend(site_evts.get(composite_to_mac[ck], []))
            else:
                probable_pattern = "behavioral_outlier"
                for ck in outlier_cks:
                    site_evts = await _load_site_events(composite_to_site[ck])
                    combined_events.extend(site_evts.get(composite_to_mac[ck], []))
                if combined_events:
                    posthoc = build_posthoc_features(combined_events)
                    posthoc["event_count"] = len(combined_events)
                    probable_pattern = _classify_probable_pattern(posthoc)

            finding = {
                "device_family": family,
                "wlan": wlan,
                "severity": _severity(outlier_ratio),
                "outlier_ratio": round(outlier_ratio, 4),
                "weighted_outlier_score": round(weighted_outlier_score, 4),
                "affected_mac_count": outlier_count,
                "total_mac_count": total,
                "site_count": len(sites_affected),
                "sites_affected": sites_affected,
                "example_macs": example_macs,
                "is_family_outlier": is_family_level_outlier,
                "is_family_dbscan_outlier": is_family_dbscan_outlier,
                "is_family_markov_outlier": is_family_markov_outlier,
                "markov_family_anomaly_ratio": round(org_family_markov_ratio.get(family, 0.0), 4),
                "centroid_if_score": centroid_if_scores.get(family),
                "centroid_dist_score": centroid_dist_scores.get(family),
                "centroid_detection_method": centroid_method,
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                "dbscan_severity": (
                    _severity(dbscan_outlier_ratio) if dbscan_outlier_count > 0 else None
                ),
                "dbscan_outlier_ratio": round(dbscan_outlier_ratio, 4),
                "dbscan_outlier_count": dbscan_outlier_count,
                "dbscan_outlier_site_count": len({composite_to_site[k] for k in dbscan_outlier_cks}),
                "if_outlier_count": len(if_outlier_cks),
                "top_features": top_features,
                "probable_pattern": probable_pattern,
                "scope": "org",
            }
            org_findings.append(finding)
            log.info(
                f"[org finding] wlan={wlan} [{family}]: {outlier_count}/{total} outliers "
                f"({outlier_ratio:.1%}) across {len(sites_affected)} sites "
                f"→ {finding['severity']} / {probable_pattern}"
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
            for _f in org_findings:
                _family = _f["device_family"]
                _wsum = 0.0
                _wcount = 0
                _comp_wsum: dict[str, float] = {}
                _comp_wcount: dict[str, float] = {}
                for _sh in site_health_map.values():
                    _fh = _sh.get(_family)
                    if not _fh:
                        continue
                    _n = _fh.get("mac_count", 1)
                    _wsum += _fh.get("health_score", 1.0) * _n
                    _wcount += _n
                    for _cat, _val in _fh.get("components", {}).items():
                        _comp_wsum[_cat] = _comp_wsum.get(_cat, 0.0) + _val * _n
                        _comp_wcount[_cat] = _comp_wcount.get(_cat, 0.0) + _n
                if _wcount > 0:
                    _f["health_score"] = round(_wsum / _wcount, 4)
                    _f["health_components"] = {
                        _cat: round(_comp_wsum[_cat] / _comp_wcount[_cat], 4)
                        for _cat in _comp_wsum
                    }
                else:
                    _f["health_score"] = 1.0
                    _f["health_components"] = {}

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

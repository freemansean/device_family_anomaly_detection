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

Finding rollup: aggregate per-family outlier ratios → findings list.

Redis key scheme:
  sasquatch:anomalies:{site_id}:{wlan_key}
  sasquatch:findings:{site_id}:{wlan_key}
  where wlan_key = "__all__" or sanitized SSID name.
"""

import json
import logging
import os
from collections import Counter, defaultdict

import numpy as np
import redis.asyncio as aioredis
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .event_collector import get_events, sanitize_wlan_key
from .feature_engineer import (
    FEATURE_KEYS,
    build_posthoc_features,
    get_features,
)

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
ANOMALIES_TTL = 24 * 3600
FINDINGS_TTL = 24 * 3600

MIN_PEERS = int(os.getenv("ANOMALY_MIN_PEERS", "5"))
IF_CONTAMINATION = float(os.getenv("ANOMALY_IF_CONTAMINATION", "0.1"))
DBSCAN_EPS = float(os.getenv("ANOMALY_DBSCAN_EPS", "0.5"))
DBSCAN_MIN_SAMPLES = int(os.getenv("ANOMALY_DBSCAN_MIN_SAMPLES", "5"))
DBSCAN_MIN_FAMILY_SIZE = int(os.getenv("ANOMALY_DBSCAN_MIN_FAMILY_SIZE", "5"))
# Fraction of a family's MACs that must be DBSCAN noise to flag the whole family.
DBSCAN_FAMILY_NOISE_THRESHOLD = float(os.getenv("ANOMALY_DBSCAN_FAMILY_NOISE_THRESHOLD", "0.5"))
# Minimum number of qualifying families (≥2 MACs each) required to run centroid IF.
CENTROID_IF_MIN_FAMILIES = int(os.getenv("ANOMALY_CENTROID_IF_MIN_FAMILIES", "3"))
FINDING_THRESHOLD = float(os.getenv("ANOMALY_FINDING_THRESHOLD", "0.3"))



def _anomalies_redis_key(site_id: str, wlan: str = "__all__") -> str:
    return f"sasquatch:anomalies:{site_id}:{sanitize_wlan_key(wlan)}"


def _findings_redis_key(site_id: str, wlan: str = "__all__") -> str:
    return f"sasquatch:findings:{site_id}:{sanitize_wlan_key(wlan)}"


def _org_anomalies_redis_key(site_id: str, wlan: str = "__all__") -> str:
    return f"sasquatch:org_anomalies:{site_id}:{sanitize_wlan_key(wlan)}"


def _org_findings_redis_key(wlan: str = "__all__") -> str:
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
    if X.shape[0] < MIN_PEERS:
        return {
            mac: {"if_score": None, "is_if_outlier": False}
            for mac in macs
        }

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(
        contamination=IF_CONTAMINATION,
        random_state=42,
        n_estimators=100,
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
    Returns per-MAC dict with dbscan_label and is_dbscan_outlier.
    """
    X = _extract_vector_array(feature_records)
    if X.shape[0] < DBSCAN_MIN_SAMPLES:
        return {
            mac: {"dbscan_label": -1, "is_dbscan_outlier": True}
            for mac in macs
        }

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    db = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES)
    labels = db.fit_predict(X_scaled)

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
) -> dict[str, float]:
    """
    Family centroid Isolation Forest.

    For each family with >= 2 MACs, compute a centroid = element-wise mean of
    features[mac]["vector"] across all MACs in that family (using FEATURE_KEYS
    for consistent column ordering). Collect all qualifying centroids into a
    matrix and run StandardScaler + IsolationForest across them.

    Returns {family_name: if_score} for every qualifying family.
    Negative scores indicate the centroid is an outlier among family centroids.
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
        centroid = vectors.mean(axis=0)
        qualifying.append((family, centroid))

    if len(qualifying) < CENTROID_IF_MIN_FAMILIES:
        log.info(
            f"Centroid IF: skipped — only {len(qualifying)} qualifying "
            f"families (need >= {CENTROID_IF_MIN_FAMILIES})"
        )
        return {}

    family_names = [name for name, _ in qualifying]
    X = np.array([vec for _, vec in qualifying])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(
        contamination=IF_CONTAMINATION,
        random_state=42,
        n_estimators=100,
    )
    clf.fit(X_scaled)
    raw_scores = clf.decision_function(X_scaled)

    return {family_names[i]: float(raw_scores[i]) for i in range(len(family_names))}


async def score(
    site_id: str,
    wlan: str = "__all__",
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

    Store per-MAC anomaly scores and rolled-up findings in Redis.
    Returns count of MACs scored.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        features = await get_features(site_id, wlan)
        if not features:
            raise RuntimeError(
                f"No features found for site {site_id} / wlan={wlan}. "
                "Run feature_engineer.build_features() first."
            )

        # Load raw events for post-hoc explainer (only used for outliers)
        events = await get_events(
            site_id=site_id,
            wlan=wlan if wlan != "__all__" else None,
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

        # --- Stage 1: DBSCAN across all MACs in WLAN scope ---
        # Only include MACs from families large enough to contribute meaningful signal.
        dbscan_eligible_macs = [
            mac for mac in features
            if len(family_groups.get(features[mac].get("device_family", "Unknown"), [])) >= DBSCAN_MIN_FAMILY_SIZE
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

        # --- Family centroid IF: determine which families are anomalous ---
        # Compute one mean feature vector per family, run IF across all family
        # centroids, and flag families whose centroid is an outlier among peers.
        centroid_if_scores = _run_family_centroid_if(family_groups, features)
        flagged_families: set[str] = set()
        for family, centroid_score in centroid_if_scores.items():
            if centroid_score < 0:  # negative = outlier in IsolationForest
                flagged_families.add(family)
                log.info(f"Centroid IF [{wlan}]: family [{family}] flagged (score={centroid_score:.4f})")

        # --- Stage 2: Isolation Forest per device family ---
        if_results: dict[str, dict] = {}
        families_with_org_if: set[str] = set()
        for family, family_macs in family_groups.items():
            n = len(family_macs)
            family_records = [features[m] for m in family_macs]

            # Supplement with org-level context when this site's family is too small.
            ctx_records: list[dict] = []
            if n < MIN_PEERS and org_family_contexts:
                ctx_records = org_family_contexts.get(family, [])

            combined_count = n + len(ctx_records)
            if combined_count < MIN_PEERS:
                if_results.update({mac: {"if_score": None, "is_if_outlier": False} for mac in family_macs})
                log.info(f"IF [{wlan}] [{family}]: skipped (only {n} MACs site-wide, {combined_count} org-wide, need {MIN_PEERS})")
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
            anomalies[mac] = {
                "if_score": if_results[mac]["if_score"],
                "is_if_outlier": is_if,
                "dbscan_label": dbscan_results[mac]["dbscan_label"],
                "is_dbscan_outlier": is_db,
                "is_family_outlier": is_family,
                "family_centroid_if_score": centroid_if_scores.get(family),
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                "is_outlier": is_if or is_db or is_family,
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

            # Families that ran IF via org pooling require at least 2 to avoid
            # single-device IF noise. All others require MIN_PEERS.
            if family in families_with_org_if:
                min_for_finding = 2
            else:
                min_for_finding = MIN_PEERS
            if total < min_for_finding:
                continue

            outlier_macs = [m for m in family_macs if anomalies[m]["is_outlier"]]
            outlier_count = len(outlier_macs)
            outlier_ratio = outlier_count / total if total > 0 else 0.0

            if outlier_ratio < FINDING_THRESHOLD:
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

            # For __all__ scope, derive the predominant WLAN from outlier MAC events
            predominant_wlan: str | None = None
            if wlan == "__all__" and outlier_macs:
                wlan_counts: Counter = Counter()
                for mac in outlier_macs:
                    for evt in mac_raw_events.get(mac, []):
                        if evt.get("wlan"):
                            wlan_counts[evt["wlan"]] += 1
                if wlan_counts:
                    predominant_wlan = wlan_counts.most_common(1)[0][0]

            finding = {
                "device_family": family,
                "wlan": wlan,
                "predominant_wlan": predominant_wlan,
                "severity": _severity(outlier_ratio),
                "outlier_ratio": round(outlier_ratio, 4),
                "weighted_outlier_score": round(weighted_outlier_score, 4),
                "affected_mac_count": outlier_count,
                "total_mac_count": total,
                "is_family_outlier": is_family_level_outlier,
                "centroid_if_score": centroid_if_scores.get(family),
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                "dbscan_severity": _severity(dbscan_outlier_ratio) if dbscan_outlier_count > 0 else None,
                "dbscan_outlier_ratio": round(dbscan_outlier_ratio, 4),
                "dbscan_outlier_count": dbscan_outlier_count,
                "if_outlier_macs": if_outlier_macs,
                "if_outlier_count": len(if_outlier_macs),
                "example_macs": sorted(
                    outlier_macs,
                    key=lambda m: anomalies[m]["volume_concentration_weight"],
                    reverse=True,
                )[:5],
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
    wlan: str = "__all__",
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
        )) >= DBSCAN_MIN_FAMILY_SIZE
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

    # --- Family Centroid IF across all org families ---
    centroid_if_scores = _run_family_centroid_if(org_family_groups, composite_features)
    flagged_families: set[str] = set()
    for family, centroid_score in centroid_if_scores.items():
        if centroid_score < 0:
            flagged_families.add(family)
            log.info(
                f"[org Centroid IF] wlan={wlan}: family [{family}] flagged "
                f"(score={centroid_score:.4f})"
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
            "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
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

    # Raw events cache for post-hoc explainer — loaded once per site on demand
    raw_events_cache: dict[str, dict[str, list[dict]]] = {}

    async def _load_site_events(sid: str) -> "dict[str, list[dict]]":
        if sid not in raw_events_cache:
            evts = await get_events(
                site_id=sid,
                wlan=wlan if wlan != "__all__" else None,
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
            min_for_finding = MIN_PEERS
            if total < min_for_finding:
                continue

            outlier_cks = [k for k in family_cks if org_anomalies_flat[k]["is_outlier"]]
            outlier_count = len(outlier_cks)
            outlier_ratio = outlier_count / total if total > 0 else 0.0

            if outlier_ratio < FINDING_THRESHOLD:
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
                if wlan == "__all__":
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

            # For __all__ scope, derive the predominant WLAN from outlier MAC events
            predominant_wlan: str | None = None
            if wlan == "__all__" and combined_events:
                wlan_counts: Counter = Counter(
                    evt["wlan"] for evt in combined_events if evt.get("wlan")
                )
                if wlan_counts:
                    predominant_wlan = wlan_counts.most_common(1)[0][0]

            finding = {
                "device_family": family,
                "wlan": wlan,
                "predominant_wlan": predominant_wlan,
                "severity": _severity(outlier_ratio),
                "outlier_ratio": round(outlier_ratio, 4),
                "weighted_outlier_score": round(weighted_outlier_score, 4),
                "affected_mac_count": outlier_count,
                "total_mac_count": total,
                "site_count": len(sites_affected),
                "sites_affected": sites_affected,
                "example_macs": example_macs,
                "is_family_outlier": is_family_level_outlier,
                "centroid_if_score": centroid_if_scores.get(family),
                "dbscan_family_noise_ratio": round(family_dbscan_noise_ratio.get(family, 0.0), 4),
                "dbscan_severity": (
                    _severity(dbscan_outlier_ratio) if dbscan_outlier_count > 0 else None
                ),
                "dbscan_outlier_ratio": round(dbscan_outlier_ratio, 4),
                "dbscan_outlier_count": dbscan_outlier_count,
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


async def get_anomalies(site_id: str, wlan: str = "__all__") -> dict[str, dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_anomalies_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return {}
    return json.loads(raw)


async def get_findings(site_id: str, wlan: str = "__all__") -> list[dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_findings_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return []
    return json.loads(raw)


async def get_org_findings(wlan: str = "__all__") -> list[dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_org_findings_redis_key(wlan))
    finally:
        await redis_client.aclose()
    if not raw:
        return []
    return json.loads(raw)

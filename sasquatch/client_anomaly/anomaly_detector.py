"""
anomaly_detector.py — Isolation Forest (per device family) + DBSCAN (site-wide) scoring.

Stage 1: Isolation Forest scores each MAC within its device family peer group.
Stage 2: DBSCAN finds site-wide behavioral outliers regardless of device type.
Finding rollup: aggregate per-family outlier ratios → findings list.
"""

import json
import logging
import os
from collections import defaultdict

import numpy as np
import redis.asyncio as aioredis
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .feature_engineer import build_posthoc_features, get_features

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
ANOMALIES_TTL = 24 * 3600
FINDINGS_TTL = 24 * 3600

MIN_PEERS = int(os.getenv("ANOMALY_MIN_PEERS", "5"))
IF_CONTAMINATION = float(os.getenv("ANOMALY_IF_CONTAMINATION", "0.1"))
DBSCAN_EPS = float(os.getenv("ANOMALY_DBSCAN_EPS", "0.5"))
DBSCAN_MIN_SAMPLES = int(os.getenv("ANOMALY_DBSCAN_MIN_SAMPLES", "5"))
FINDING_THRESHOLD = float(os.getenv("ANOMALY_FINDING_THRESHOLD", "0.3"))


def _severity(outlier_ratio: float) -> str:
    if outlier_ratio > 0.6:
        return "CRITICAL"
    if outlier_ratio > 0.3:
        return "WARNING"
    return "INFO"


def _extract_vector_array(feature_records: list[dict]) -> np.ndarray:
    """
    Convert list of feature record dicts to a numpy array.
    Each record has a 'vector' dict with consistent keys.
    """
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
    labels = clf.fit_predict(X_scaled)           # -1 = outlier, 1 = normal
    raw_scores = clf.decision_function(X_scaled)  # continuous score (higher = more normal)

    results = {}
    for i, mac in enumerate(macs):
        results[mac] = {
            "if_score": float(raw_scores[i]),
            "is_if_outlier": bool(labels[i] == -1),
        }
    return results


def _run_dbscan(macs: list[str], feature_records: list[dict]) -> dict[str, dict]:
    """
    Run DBSCAN across all MACs (site-wide).
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

    # DHCP discard loop requires a temporal burst, not just a high ratio.
    # A client renewing every 8 hours passes the ratio test but has burst=1 and a
    # large median gap — that is normal lease behaviour, not a storm.
    # Require: 3+ CLIENT_IP_ASSIGNED in any 5-minute window AND median gap < 10 minutes.
    dhcp_burst = posthoc.get("dhcp_max_burst_5min", 0)
    dhcp_gap = posthoc.get("dhcp_median_gap_seconds", -1)
    is_dhcp_storm = dhcp_burst >= 3 and 0 <= dhcp_gap < 600
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


async def score(site_id: str) -> int:
    """
    Run Isolation Forest + DBSCAN on feature vectors.
    Store per-MAC anomaly scores and rolled-up findings in Redis.
    Returns count of MACs scored.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        features = await get_features(site_id)
        if not features:
            raise RuntimeError(
                f"No features found for site {site_id}. "
                "Run feature_engineer.build_features() first."
            )

        # Load raw events for post-hoc explainer (only loaded for outliers later)
        raw_events_json = await redis_client.get(f"sasquatch:events:{site_id}")
        all_events: list[dict] = json.loads(raw_events_json) if raw_events_json else []

        # Group events by MAC for post-hoc use
        mac_raw_events: dict[str, list[dict]] = defaultdict(list)
        for evt in all_events:
            mac = (evt.get("mac") or "").replace(":", "").lower()
            if mac:
                mac_raw_events[mac].append(evt)

        # --- Stage 1: Isolation Forest per device family ---
        family_groups: dict[str, list[str]] = defaultdict(list)
        for mac, record in features.items():
            family = record.get("device_family", "Unknown")
            family_groups[family].append(mac)

        if_results: dict[str, dict] = {}
        for family, family_macs in family_groups.items():
            family_records = [features[m] for m in family_macs]
            results = _run_isolation_forest(family_macs, family_records)
            if_results.update(results)
            n = len(family_macs)
            if n >= MIN_PEERS:
                outliers = sum(1 for r in results.values() if r["is_if_outlier"])
                log.info(f"IF [{family}]: {outliers}/{n} outliers")
            else:
                log.info(f"IF [{family}]: skipped (only {n} MACs, need {MIN_PEERS})")

        # --- Stage 2: DBSCAN site-wide ---
        all_macs = list(features.keys())
        all_records = [features[m] for m in all_macs]
        dbscan_results = _run_dbscan(all_macs, all_records)

        # --- Merge per-MAC results ---
        anomalies: dict[str, dict] = {}
        for mac in all_macs:
            is_if = if_results[mac]["is_if_outlier"]
            is_db = dbscan_results[mac]["is_dbscan_outlier"]
            anomalies[mac] = {
                "if_score": if_results[mac]["if_score"],
                "is_if_outlier": is_if,
                "dbscan_label": dbscan_results[mac]["dbscan_label"],
                "is_dbscan_outlier": is_db,
                "is_outlier": is_if or is_db,
                "device_family": features[mac].get("device_family", "Unknown"),
                "event_count": features[mac].get("event_count", 0),
                "random_mac": features[mac].get("random_mac", False),
            }

        key_anomalies = f"sasquatch:anomalies:{site_id}"
        await redis_client.set(key_anomalies, json.dumps(anomalies), ex=ANOMALIES_TTL)
        log.info(f"Stored anomaly scores for {len(anomalies)} MACs → {key_anomalies}")

        # --- Finding rollup per device family ---
        findings: list[dict] = []
        for family, family_macs in family_groups.items():
            total = len(family_macs)
            outlier_macs = [m for m in family_macs if anomalies[m]["is_outlier"]]
            outlier_count = len(outlier_macs)
            outlier_ratio = outlier_count / total if total > 0 else 0.0

            if outlier_ratio < 0.1:
                continue  # Below INFO threshold

            # Identify top contributing features vs baseline
            outlier_vecs = [features[m]["vector"] for m in outlier_macs]
            normal_macs = [m for m in family_macs if not anomalies[m]["is_outlier"]]
            normal_vecs = [features[m]["vector"] for m in normal_macs]
            top_features = _top_contributing_features(outlier_vecs, normal_vecs)

            # Post-hoc pattern classification on example outlier MACs
            probable_pattern = "behavioral_outlier"
            if outlier_macs:
                # Aggregate post-hoc features across outlier MACs for pattern detection
                sample_mac = outlier_macs[0]
                sample_events = mac_raw_events.get(sample_mac, [])
                posthoc = build_posthoc_features(sample_events)
                posthoc["event_count"] = len(sample_events)
                probable_pattern = _classify_probable_pattern(posthoc)

            finding = {
                "device_family": family,
                "severity": _severity(outlier_ratio),
                "outlier_ratio": round(outlier_ratio, 4),
                "affected_mac_count": outlier_count,
                "total_mac_count": total,
                "example_macs": outlier_macs[:5],
                "top_features": top_features,
                "probable_pattern": probable_pattern,
            }
            findings.append(finding)
            log.info(
                f"Finding [{family}]: {outlier_count}/{total} outliers "
                f"({outlier_ratio:.1%}) → {finding['severity']} / {probable_pattern}"
            )

        # Sort findings by severity then outlier_ratio
        severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        findings.sort(
            key=lambda f: (severity_order.get(f["severity"], 3), -f["outlier_ratio"])
        )

        key_findings = f"sasquatch:findings:{site_id}"
        await redis_client.set(key_findings, json.dumps(findings), ex=FINDINGS_TTL)
        log.info(f"Stored {len(findings)} findings → {key_findings}")

        return len(anomalies)

    finally:
        await redis_client.aclose()


async def get_anomalies(site_id: str) -> dict[str, dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(f"sasquatch:anomalies:{site_id}")
    finally:
        await redis_client.aclose()
    if not raw:
        return {}
    return json.loads(raw)


async def get_findings(site_id: str) -> list[dict]:
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(f"sasquatch:findings:{site_id}")
    finally:
        await redis_client.aclose()
    if not raw:
        return []
    return json.loads(raw)

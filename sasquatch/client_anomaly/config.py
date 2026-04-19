"""
config.py — Centralised configuration with hardcoded best-practice defaults.

Resolution order for every setting:
  1. config_overrides.json  (GUI-set values, persisted across restarts)
  2. Environment variable   (operator override via .env or shell)
  3. Hardcoded default      (best-practice value defined here)

No setting in the General Config or Anomaly Config sections needs to be
present in .env — they all have sensible defaults baked in below.
"""

import json
import logging
import os
import pathlib

log = logging.getLogger(__name__)

_CONFIG_FILE = pathlib.Path(__file__).parent / "config_overrides.json"

# ─────────────────────────────────────────────────────────────────────
# Best-practice defaults — the single source of truth for every
# GUI-configurable setting.  Organised by config section.
# ─────────────────────────────────────────────────────────────────────

DEFAULTS = {
    # ── General Config ──────────────────────────────────────────────
    "general": {
        # How often (hours) to run org-wide cross-site detection
        "org_detection_interval_hours": {"default": 1, "env": "ORG_DETECTION_INTERVAL_HOURS", "cast": int},
        # Minimum events for a MAC to enter the per-MAC feature pool at all
        # (feature_engineer skip threshold). Sets the floor for what the
        # inter-family Centroid Detector and per-family Health Score can see —
        # both consume every record in the pool. The IF and DBSCAN detectors
        # apply their own higher threshold below (anomaly_min_mac_events).
        # Lowering this surfaces more low-volume cohorts in Health and
        # Centroid; raising it reduces noise. Default 3 keeps the per-MAC
        # vector statistically meaningful (zero/one-event MACs collapse to
        # extreme corners of the category space).
        "feature_min_mac_events": {"default": 3, "env": "FEATURE_MIN_MAC_EVENTS", "cast": int},
        # Minimum events for a MAC to be evaluated by the per-family
        # Isolation Forest and site-wide DBSCAN passes. Below this floor,
        # per-MAC vectors are too sparse for distance-based scoring to be
        # reliable. Does NOT affect the inter-family Cosine Distance
        # (centroid) detector or the per-family Health Score, which use the
        # broader pool defined by feature_min_mac_events above. Markov has
        # its own internal threshold (markov_stuck_loop_min_events).
        "anomaly_min_mac_events": {"default": 10, "env": "ANOMALY_MIN_MAC_EVENTS", "cast": int},
        # Suppress alarms for device families whose total MAC count is below this
        # threshold. Small families can trip the detector on a single quirky device
        # — raising this floor lets operators quiet that noise without touching the
        # detection pipeline itself. Applies to both webhook dispatch and the
        # OrgAlerts UI feed. Default 10 suppresses families smaller than 10
        # MACs; set to 1 to disable and let every family through.
        "alarm_min_family_size": {"default": 10, "env": "ALARM_MIN_FAMILY_SIZE", "cast": int},
        # Health score threshold for dual-gate alarm generation. Device families
        # with health_score below this value are considered degraded and — if also
        # flagged by any family-level anomaly detector — trigger an alert via the
        # webhook dispatcher and the OrgAlerts UI feed. Lives under General Config
        # (alongside alarm_min_family_size) because it gates alarm generation at
        # both org and site level, not the anomaly detection pipeline itself.
        "anomaly_health_score_threshold": {"default": 0.20, "env": "ANOMALY_HEALTH_SCORE_THRESHOLD", "cast": float},
        # Service-alarm device-percentage threshold for dual-gate alarm
        # generation. A device family is "service-alarming" when at least this
        # fraction of its MACs have individually tripped a service alarm
        # (one or more of auth/roam/dhcp/dns/arp below SERVICE_HEALTH_THRESHOLD).
        # Lives under General Config alongside anomaly_health_score_threshold —
        # both gate webhook dispatch and the org/site alert feeds. Default 0.50
        # requires at least half of the family's MACs to have tripped a per-MAC
        # service alarm before the service-alarm path fires.
        "alarm_service_device_pct": {"default": 0.70, "env": "ALARM_SERVICE_DEVICE_PCT", "cast": float},
        # Combine mode for the two health-side alarm gates
        # (anomaly_health_score_threshold and alarm_service_device_pct).
        # "or"  = fire when either gate trips (preserves prior behavior).
        # "and" = fire only when both gates trip.
        "alarm_health_combine": {"default": "or", "env": "ALARM_HEALTH_COMBINE", "cast": str},
        # Fraction of clients in a device family that must be flagged as
        # anomalous by *either* DBSCAN or Markov before an alarm fires for that
        # family. The union is taken per-MAC: a single client flagged by both
        # detectors counts once. Inter-family centroid detection
        # (is_family_outlier) is independent of this gate and remains
        # independently sufficient to fire an alarm. Applies at both org and
        # site level, gating both webhook dispatch and the OrgAlerts UI feed.
        # Default 0.70 = at least 70% of family clients must be DBSCAN/Markov-
        # flagged before alarming on the rollup signal.
        "alarm_dbscan_markov_ratio": {"default": 0.70, "env": "ALARM_DBSCAN_MARKOV_RATIO", "cast": float},
        # RSSI floor (dBm) below which *failure* events are discarded during
        # enrichment. Clients at the fringe of RF coverage generate auth/roam
        # failure events that reflect poor signal, not device-level behavior —
        # dropping them keeps the feature vectors focused on actionable
        # anomalies. Only applies to auth/roam/association failure event types;
        # successful events and non-auth types (DHCP, DNS, ARP, etc.) pass
        # through regardless of signal strength. Set to a very negative value
        # (e.g. -120) to effectively disable the filter.
        "anomaly_rssi_min_threshold": {"default": -87, "env": "ANOMALY_RSSI_MIN_THRESHOLD", "cast": int},
        # Minimum MACs a manufacturer must have in the WLAN scope before a
        # <mfg>-MFG rollup virtual family is emitted. Each -MFG family
        # aggregates every MAC of that manufacturer regardless of fingerprint
        # depth (bare 1-token rows + all per-fingerprint siblings) and is the
        # only candidate for Centroid analysis. Below this floor no -MFG
        # family is built for that manufacturer and no Centroid pass runs for
        # it that cycle — mirrors the small-cohort skip path used elsewhere
        # in the pipeline. Default 5 aligns with the service-account
        # threshold philosophy: small enough to surface real minority
        # manufacturers, large enough to keep 2-or-3 MAC noise out of the
        # heatmap.
        "mfg_rollup_min_macs": {"default": 5, "env": "MFG_ROLLUP_MIN_MACS", "cast": int},
    },

    # ── Anomaly Config ──────────────────────────────────────────────
    "anomaly": {
        # Isolation Forest contamination (per-family, Stage 2)
        "anomaly_if_contamination": {"default": 0.05, "env": "ANOMALY_IF_CONTAMINATION", "cast": float},
        # Number of IF trees
        "anomaly_if_n_estimators": {"default": 200, "env": "ANOMALY_IF_N_ESTIMATORS", "cast": int},
        # Random seed (-1 for random)
        "anomaly_random_state": {"default": 42, "env": "ANOMALY_RANDOM_STATE", "cast": int},
        # Min MACs per family before IF runs
        "anomaly_min_peers": {"default": 3, "env": "ANOMALY_MIN_PEERS", "cast": int},
        # PCA variance retained for DBSCAN
        "anomaly_dbscan_pca_variance": {"default": 0.95, "env": "ANOMALY_DBSCAN_PCA_VARIANCE", "cast": float},
        # DBSCAN min_samples is auto-tuned per run as max(3, n_clients * pct).
        # `pct` is configured here as an integer 1–10, mapped at runtime to
        # 0.01–0.10. Default 3 → 0.03 (3% of n_clients, floor of 3).
        "anomaly_dbscan_min_samples_pct": {"default": 3, "env": "ANOMALY_DBSCAN_MIN_SAMPLES_PCT", "cast": int},
        # DBSCAN family noise threshold
        "anomaly_dbscan_family_noise_threshold": {"default": 0.5, "env": "ANOMALY_DBSCAN_FAMILY_NOISE_THRESHOLD", "cast": float},
        # Cosine distance threshold for family flagging (Stage 1b)
        "anomaly_centroid_dist_threshold": {"default": 0.35, "env": "ANOMALY_CENTROID_DIST_THRESHOLD", "cast": float},
        # Health threshold for healthy-only centroid reference
        "anomaly_centroid_healthy_ref_threshold": {"default": 0.75, "env": "ANOMALY_CENTROID_HEALTHY_REF_THRESHOLD", "cast": float},
        # Min healthy families for healthy-only reference mode
        "anomaly_centroid_healthy_ref_min": {"default": 2, "env": "ANOMALY_CENTROID_HEALTHY_REF_MIN", "cast": int},
        # Min family size for site-level finding generation
        "anomaly_finding_min_size": {"default": 2, "env": "ANOMALY_FINDING_MIN_SIZE", "cast": int},
        # Markov: fraction of family clients that must be outliers
        "markov_family_outlier_ratio": {"default": 0.5, "env": "MARKOV_FAMILY_OUTLIER_RATIO", "cast": float},
        # Markov: min episode length
        "markov_min_episode_length": {"default": 3, "env": "MARKOV_MIN_EPISODE_LENGTH", "cast": int},
        # Markov: episode anomaly ratio to flag a MAC
        "markov_outlier_episode_ratio": {"default": 0.5, "env": "MARKOV_OUTLIER_EPISODE_RATIO", "cast": float},
        # Markov: min scoreable episodes before analysis runs
        "markov_min_scoreable_episodes": {"default": 2, "env": "MARKOV_MIN_SCOREABLE_EPISODES", "cast": int},
        # Markov: stuck-loop transition dominance threshold
        "markov_stuck_loop_threshold": {"default": 0.4, "env": "MARKOV_STUCK_LOOP_THRESHOLD", "cast": float},
        # Markov: min events before stuck-loop detection runs
        "markov_stuck_loop_min_events": {"default": 20, "env": "MARKOV_STUCK_LOOP_MIN_EVENTS", "cast": int},
    },

    # ── Service Account Visibility ─────────────────────────────────
    "service_account": {
        # Minimum number of distinct client MACs sharing the same normalized
        # username before that username is treated as a service-account family.
        # Set higher to suppress small username clusters; set to 0 to disable
        # service-account family generation entirely.
        "service_account_min_macs": {"default": 50, "env": "SERVICE_ACCOUNT_MIN_MACS", "cast": int},
    },
}


def _load_overrides() -> dict:
    """Load config_overrides.json. Returns empty dict on missing/corrupt file."""
    try:
        return json.loads(_CONFIG_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return {}


def get(section: str, key: str) -> int | float | str:
    """Return the runtime value for a config key.

    Resolution: config_overrides.json → env var → hardcoded default.
    """
    spec = DEFAULTS.get(section, {}).get(key)
    if spec is None:
        raise KeyError(f"Unknown config key: {section}.{key}")

    cast = spec["cast"]

    # 1. GUI override (config_overrides.json)
    overrides = _load_overrides().get(section, {})
    gui_val = overrides.get(key)
    if gui_val is not None:
        try:
            return cast(gui_val)
        except (ValueError, TypeError):
            pass

    # 2. Environment variable
    env_val = os.environ.get(spec["env"])
    if env_val is not None:
        try:
            return cast(env_val)
        except (ValueError, TypeError):
            pass

    # 3. Hardcoded default
    return spec["default"]


def get_section_defaults(section: str) -> dict:
    """Return {key: default_value} for all keys in a section.

    Used by the config GET endpoints to build the base dict before
    applying overrides.
    """
    return {key: spec["default"] for key, spec in DEFAULTS.get(section, {}).items()}


def get_section(section: str) -> dict:
    """Return {key: resolved_value} for all keys in a section.

    Each value goes through the full resolution chain.
    """
    return {key: get(section, key) for key in DEFAULTS.get(section, {})}

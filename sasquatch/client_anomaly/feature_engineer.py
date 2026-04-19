"""
feature_engineer.py — Per-MAC feature vector construction.

DESIGN PRINCIPLE: Volume is not anomaly.
The ML models receive ratio features ONLY — not raw counts.
All features are normalized so that active clients are not penalized for being active.

Each MAC carries TWO feature vectors, routed to different stages:

  event_vector     — ~59-dim normalized per-event-type frequency distribution.
                     Fed to Isolation Forest (per-family intra-family outliers)
                     and the family Centroid cosine-distance detector
                     (inter-family outliers). Granular enough to distinguish,
                     e.g., two iPhones failing at different roam types
                     (FBT vs OKC vs 11r) rather than collapsing them both
                     into one ROAM_FAILURE bucket.

  category_vector  — 14-dim category frequency + 2 concentration features.
                     Fed to DBSCAN (population-wide, after PCA), the health
                     scorer, and the top-contributing-features explainer
                     shown in the UI. Semantic bucket granularity is the
                     right level for clustering and human-readable output.

Post-hoc explainer features are computed separately, only for flagged MACs.

Redis key scheme:
  sasquatch:features:{site_id}:{wlan_key}
  where wlan_key is a sanitized SSID name.
"""

import json
import logging
import math
import os
import statistics  # used by build_posthoc_features
from collections import Counter, defaultdict

import redis.asyncio as aioredis

from .event_collector import (
    EVENT_CATEGORIES,
    ensure_event_type_index,
    get_events,
    sanitize_wlan_key,
)

from . import config
from . import db as _db
from .client_cache import (
    is_bare_one_token_family,
    resolve_manufacturer_from_family,
)

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# Service-account dual-family identifiers.
#
# A MAC that belongs to a qualifying service-account username is emitted into
# the feature dict TWICE: once under its real MAC (primary record, real device
# family like "MacBook"), and once under a composite key built by `sa_record_key`
# with `device_family = "{label}.service_account"`. The two records share the
# same vector but are scored under different family groups so the device-family
# detection passes treat them independently.
#
# Downstream code identifies sa records by:
#   - is_sa_record_key(key)         — composite key form, used in features dict
#   - is_service_account_family(name) — family-name suffix check
#   - underlying_mac(key)            — strip the suffix to recover the real MAC
# ─────────────────────────────────────────────────────────────────────
SERVICE_ACCOUNT_SUFFIX = ".service_account"
_SA_KEY_SUFFIX = "#sa"

# ─────────────────────────────────────────────────────────────────────
# Manufacturer-rollup dual-family identifiers.
#
# Every MAC whose resolved manufacturer meets the mfg_rollup_min_macs
# threshold is emitted into the feature dict an ADDITIONAL time under a
# composite key built by `mfg_record_key`, with device_family set to
# "{mfg}-MFG". The -MFG family is the sole candidate for Centroid
# analysis (per the Phase-3 detector gates); per-fingerprint families
# drop out of Centroid entirely and stay with DBSCAN/IF/Markov.
#
# Shape mirrors the service-account plumbing: composite features-dict
# key suffix `#mfg`, virtual family-name suffix `-MFG`.
# ─────────────────────────────────────────────────────────────────────
MFG_ROLLUP_SUFFIX = "-MFG"
_MFG_KEY_SUFFIX = "#mfg"


def sa_record_key(mac: str) -> str:
    """Composite features-dict key for a MAC's service-account record."""
    return f"{mac}{_SA_KEY_SUFFIX}"


def is_sa_record_key(key: str) -> bool:
    """True if a features-dict key is the service-account variant of a MAC."""
    return key.endswith(_SA_KEY_SUFFIX)


def mfg_record_key(mac: str) -> str:
    """Composite features-dict key for a MAC's manufacturer-rollup record."""
    return f"{mac}{_MFG_KEY_SUFFIX}"


def is_mfg_record_key(key: str) -> bool:
    """True if a features-dict key is the MFG-rollup variant of a MAC."""
    return key.endswith(_MFG_KEY_SUFFIX)


def underlying_mac(key: str) -> str:
    """Strip any virtual-family suffix from a composite key to recover the real MAC."""
    if is_sa_record_key(key):
        return key[: -len(_SA_KEY_SUFFIX)]
    if is_mfg_record_key(key):
        return key[: -len(_MFG_KEY_SUFFIX)]
    return key


def is_service_account_family(name: str | None) -> bool:
    """True if a device-family name is a virtual service-account family."""
    return bool(name) and name.endswith(SERVICE_ACCOUNT_SUFFIX)


def is_mfg_rollup_family(name: str | None) -> bool:
    """True if a device-family name is a virtual <mfg>-MFG rollup family."""
    return bool(name) and name.endswith(MFG_ROLLUP_SUFFIX)


def mfg_rollup_family_name(mfg: str) -> str:
    """Build the virtual-family name for a manufacturer."""
    return f"{mfg}{MFG_ROLLUP_SUFFIX}"

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

# Collaboration events are excluded from the ML feature vector.
# They are application-layer signals (Zoom/Teams calls, CPU spikes) that have no
# bearing on network connectivity behaviour and are absent for most device types,
# which would create spurious anomaly signal against devices that do have them.
_COLLABORATION_EVENT_TYPES: frozenset[str] = frozenset(EVENT_CATEGORIES["COLLABORATION"])

# Event categories used as ML input dimensions — collaboration excluded.
_ML_CATEGORIES: list[str] = [cat for cat in EVENT_CATEGORIES if cat != "COLLABORATION"]

# Failure-class categories — used for failure concentration scoring and feature weighting.
_FAILURE_CATEGORIES: frozenset[str] = frozenset({
    "DHCP_FAILURE", "DNS_FAILURE", "AUTH_FAILURE", "ROAM_FAILURE", "ARP_FAILURE"
})

# Canonical category-vector key ordering — guarantees vector consistency across
# MACs and runs. Category dimensions first (in _ML_CATEGORIES order), then the
# two concentration features. Used by DBSCAN, health scorer, and the top-
# contributing-features explainer.
CATEGORY_FEATURE_KEYS: list[str] = _ML_CATEGORIES + [
    "top_category_fraction",
    "top_failure_category_fraction",
]

# Backwards-compatible alias so any stragglers (and external readers that grep
# the module) still resolve to the category vector's key order. New code should
# reference CATEGORY_FEATURE_KEYS or EVENT_FEATURE_KEYS explicitly.
FEATURE_KEYS = CATEGORY_FEATURE_KEYS


def _features_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:features:{site_id}:{sanitize_wlan_key(wlan)}"


def _family_event_counts_redis_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:family_event_counts:{site_id}:{sanitize_wlan_key(wlan)}"


def build_mac_category_vector(mac_events: list[dict]) -> dict[str, float]:
    """
    Build the semantic category-level feature vector for a single MAC.

    Dimensions:
      [0–N-1]  One frequency per event category (excluding COLLABORATION):
               count of events in that category / total non-collaboration events.
               Zero-filled for categories with no events. Dimensions sum to 1.0.
      [N, N+1] top_category_fraction, top_failure_category_fraction

    Consumers: DBSCAN (post-PCA), health scorer, top-contributing-features explainer.
    """
    if not mac_events:
        return {k: 0.0 for k in CATEGORY_FEATURE_KEYS}

    # Strip collaboration events — they are not network signals and are absent for most
    # device types, so including them would create spurious cross-device anomaly signal.
    ml_events = [e for e in mac_events if e.get("type") not in _COLLABORATION_EVENT_TYPES]
    if not ml_events:
        return {k: 0.0 for k in CATEGORY_FEATURE_KEYS}

    total = len(ml_events)
    type_counts: Counter = Counter(e.get("type", "") for e in ml_events)

    vec: dict[str, float] = {}

    # Per-category normalized frequency.
    for cat in _ML_CATEGORIES:
        cat_count = sum(type_counts.get(t, 0) for t in EVENT_CATEGORIES.get(cat, []))
        vec[cat] = cat_count / total

    # Concentration features — amplify signal for clients stuck in a single-category loop.
    vec["top_category_fraction"] = max(vec[cat] for cat in _ML_CATEGORIES)
    vec["top_failure_category_fraction"] = max(
        (vec[cat] for cat in _FAILURE_CATEGORIES), default=0.0
    )

    return vec


def build_mac_event_vector(
    mac_events: list[dict], event_type_index: list[str]
) -> dict[str, float]:
    """
    Build the per-event-type frequency vector for a single MAC.

    Each dimension is count(event_type) / total_events across all known Mist
    client event types. Zero-filled for types this MAC never produced. Dimensions
    sum to 1.0 over the subset of events whose type is in event_type_index;
    unknown types are excluded from both the numerator and the denominator so
    the vector stays a proper probability distribution even when Mist introduces
    a new type we don't yet track.

    Collaboration events are kept here — at the per-event-type level they are
    just additional dimensions that devices using them can differ on, not
    category-level noise. IF and centroid consumers see the full event surface.

    Consumers: Isolation Forest (intra-family), Centroid cosine-distance (inter-family).
    """
    keys = list(event_type_index)
    if not mac_events or not keys:
        return {k: 0.0 for k in keys}

    known = set(keys)
    type_counts: Counter = Counter(
        e.get("type", "") for e in mac_events if e.get("type") in known
    )
    total = sum(type_counts.values())
    if total == 0:
        return {k: 0.0 for k in keys}

    return {k: type_counts.get(k, 0) / total for k in keys}


# Legacy name — some callers still reference it. Resolves to the category
# vector (the historical behavior). New detection-path code should call
# build_mac_category_vector or build_mac_event_vector directly.
def build_mac_feature_vector(mac_events: list[dict]) -> dict[str, float]:
    return build_mac_category_vector(mac_events)


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

    # DHCP burst detection
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
        dhcp_median_gap_seconds = -1

    dns_ok_count = type_counts.get("CLIENT_DNS_OK", 0)
    dns_to_dhcp_xid_ratio = (
        dns_ok_count / dhcp_unique_xid_count if dhcp_unique_xid_count > 0 else 0.0
    )

    roam_failure_types_seen = {
        e.get("type") for e in mac_events if e.get("type") in ROAM_FAILURE_TYPES
    }

    if type_counts:
        top_event_type, top_count = type_counts.most_common(1)[0]
        top_event_fraction = top_count / total
    else:
        top_event_type = ""
        top_event_fraction = 0.0

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


async def build_features(
    site_id: str,
    wlan: str,
    *,
    qualifying_mfgs: set[str] | None = None,
) -> int:
    """
    Read events from the global Redis sorted set (filtered by site and WLAN),
    build per-MAC feature vectors, store in Redis.

    Returns count of MACs processed.

    ``qualifying_mfgs``: optional pre-computed set of manufacturers that met
    the mfg_rollup_min_macs threshold org-wide on this WLAN. When provided,
    the -MFG rollup emission uses this set instead of computing per-site
    counts — a manufacturer spread thin across many sites (e.g. Amazon,
    3 MACs × 30 sites) will then still emit <mfg>-MFG records at every site
    that sees the mfg, and the org-wide Centroid pass sees the full cohort.
    When None (manual API trigger, test, one-off), the function falls back
    to per-site counting for backwards compatibility.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        # Detection considers the trailing 24h only — see db.DETECTION_WINDOW_SECONDS.
        # Storage retention is a longer 7-day window for drilldowns / forensics.
        events = await get_events(
            site_id=site_id, wlan=wlan, since=_db.get_detection_cutoff(),
        )
        if not events:
            raise RuntimeError(
                f"No events found for site {site_id} / wlan={wlan}. "
                "Run event_collector.collect() first."
            )

        # Load the canonical event-type ordering once per build so every MAC's
        # event_vector lines up dimension-for-dimension. Cached in Redis with a
        # 7-day TTL by ensure_event_type_index — first build after a Redis flush
        # pays one HTTP call, every subsequent build is a single GET.
        event_type_index = await ensure_event_type_index(redis_client)

        # Group events by MAC up-front — every downstream pass uses this map.
        mac_events: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            mac = (event.get("mac") or "").replace(":", "").lower()
            if mac:
                mac_events[mac].append(event)

        # ── Service-account family lookup (org-wide, evaluated once per build) ──
        # Pulls normalized usernames that ≥ N distinct client rows share across
        # the entire org. Each qualifying entry maps to a display label that
        # becomes the virtual family name "{label}.service_account". Empty when
        # SERVICE_ACCOUNT_MIN_MACS is 0 or when no clusters cross the threshold.
        sa_min = config.get("service_account", "service_account_min_macs")
        sa_lookup: dict[str, dict] = {}
        org_id = os.getenv("MIST_ORG_ID", "")
        if sa_min > 0 and org_id:
            try:
                sa_lookup = await _db.get_service_account_usernames(org_id, int(sa_min))
            except Exception:
                log.exception(
                    "service-account lookup failed; skipping virtual family emission"
                )
                sa_lookup = {}

        # Per-MAC pre-pass: compute majority-vote last_username and resolve the
        # service-account virtual family. Done before the family-event-counts
        # aggregator below so events for sa-bound MACs get binned into BOTH
        # their primary family and the virtual sa family in one walk.
        mac_to_username: dict[str, str] = {}
        mac_to_sa_family: dict[str, str] = {}
        for mac, evts in mac_events.items():
            uname_counts: dict[str, int] = {}
            for e in evts:
                u = (e.get("last_username") or "").strip()
                if u:
                    uname_counts[u] = uname_counts.get(u, 0) + 1
            if not uname_counts:
                continue
            last_username = max(uname_counts, key=uname_counts.__getitem__)
            mac_to_username[mac] = last_username
            if not sa_lookup:
                continue
            uname_norm = _db.normalize_username(last_username)
            sa_entry = sa_lookup.get(uname_norm) if uname_norm else None
            if sa_entry:
                mac_to_sa_family[mac] = f"{sa_entry['label']}{SERVICE_ACCOUNT_SUFFIX}"

        # ── Manufacturer-rollup family resolution (per MAC, threshold-gated) ──
        # Resolve each MAC's manufacturer via majority vote over its enriched
        # events. Then count MACs per manufacturer and keep only those meeting
        # the mfg_rollup_min_macs floor. Bare-1-token families back-resolve
        # through the family name (iOS 17 → Apple, iPhone → Apple, …) via the
        # strict whitelist in client_cache.resolve_manufacturer — anything we
        # can't attribute with confidence stays unresolved and emits no -MFG.
        mfg_rollup_min = config.get("general", "mfg_rollup_min_macs")
        mac_to_mfg: dict[str, str] = {}
        for mac, evts in mac_events.items():
            mfg_votes: dict[str, int] = {}
            for e in evts:
                fam = e.get("device_family") or ""
                mfg_raw = e.get("device_manufacturer") or ""
                resolved = resolve_manufacturer_from_family(fam, mfg_raw)
                if resolved:
                    mfg_votes[resolved] = mfg_votes.get(resolved, 0) + 1
            if mfg_votes:
                mac_to_mfg[mac] = max(mfg_votes, key=mfg_votes.__getitem__)
        # Threshold source: caller-supplied org-wide qualifying set (Phase 2
        # pre-pass in scheduler) OR, when absent, per-site count from this
        # call's own MAC population.
        if qualifying_mfgs is None:
            mfg_mac_counts: Counter[str] = Counter(mac_to_mfg.values())
            qualifying_mfgs_set: set[str] = {
                m for m, cnt in mfg_mac_counts.items() if cnt >= int(mfg_rollup_min)
            }
        else:
            qualifying_mfgs_set = set(qualifying_mfgs)

        # Pre-compute per-family event category counts for the org/family-insights
        # endpoint so it can aggregate across sites without loading raw events per
        # request. Each event contributes to its primary device family and — when
        # the MAC belongs to a qualifying service-account cluster — also to the
        # virtual sa family, so the heatmap surfaces sa families as first-class rows.
        _fam_cat: dict[str, Counter] = defaultdict(Counter)
        _fam_macs: dict[str, set] = defaultdict(set)
        for _evt in events:
            _fam = _evt.get("device_family", "Unknown")
            _cat = _evt.get("event_category", "OTHER")
            _fam_cat[_fam][_cat] += 1
            _mac = (_evt.get("mac") or "").replace(":", "").lower()
            if _mac:
                _fam_macs[_fam].add(_mac)
                _sa_fam = mac_to_sa_family.get(_mac)
                if _sa_fam:
                    _fam_cat[_sa_fam][_cat] += 1
                    _fam_macs[_sa_fam].add(_mac)
                _mfg = mac_to_mfg.get(_mac)
                if _mfg and _mfg in qualifying_mfgs_set:
                    _mfg_fam = mfg_rollup_family_name(_mfg)
                    _fam_cat[_mfg_fam][_cat] += 1
                    _fam_macs[_mfg_fam].add(_mac)
        family_counts = {
            fam: {
                "total_events": sum(cats.values()),
                "mac_count": len(_fam_macs[fam]),
                "categories": dict(cats),
            }
            for fam, cats in _fam_cat.items()
        }
        await redis_client.set(
            _family_event_counts_redis_key(site_id, wlan),
            json.dumps(family_counts),
            ex=FEATURES_TTL,
        )

        # Build feature vectors for each MAC. Each record carries TWO vectors:
        #   category_vector — semantic buckets, fed to DBSCAN/health/explainer
        #   event_vector    — per-event-type frequencies, fed to IF/Centroid
        features: dict[str, dict] = {}
        skipped = 0
        sa_emitted = 0
        mfg_emitted = 0
        # Use the lower feature-pool threshold here (default 3). The Health
        # scorer and inter-family Centroid detector both consume the full
        # pool; IF and DBSCAN apply their higher anomaly_min_mac_events
        # filter at consumption time inside _run_isolation_forest /
        # _run_dbscan. The event_count field on each emitted record carries
        # the raw count so consumers can filter without re-counting.
        min_mac_events = config.get("general", "feature_min_mac_events")
        for mac, evts in mac_events.items():
            if len(evts) < min_mac_events:
                skipped += 1
                continue
            cat_vec = build_mac_category_vector(evts)
            event_vec = build_mac_event_vector(evts, event_type_index)
            # Majority-vote device_family across all events for this MAC.
            # Any non-Unknown label beats Unknown — handles MACs whose events span
            # a cache refresh boundary (early events labeled Unknown, later ones correct).
            family_counts_local: dict[str, int] = {}
            for e in evts:
                f = e.get("device_family") or "Unknown"
                family_counts_local[f] = family_counts_local.get(f, 0) + 1
            non_unknown = {f: c for f, c in family_counts_local.items() if not f.startswith("Unknown")}
            if non_unknown:
                device_family = max(non_unknown, key=non_unknown.__getitem__)
            else:
                device_family = max(family_counts_local, key=family_counts_local.__getitem__)

            last_username = mac_to_username.get(mac, "")
            sa_family_name = mac_to_sa_family.get(mac, "")
            resolved_mfg = mac_to_mfg.get(mac, "")
            bare_one_token = is_bare_one_token_family(device_family)

            volume_concentration_weight = math.log1p(len(evts)) * cat_vec["top_category_fraction"]
            features[mac] = {
                # `vector` retained as alias for category_vector so any reader
                # that grew up on the single-vector schema keeps working until
                # it migrates. New code reads category_vector / event_vector
                # explicitly.
                "vector": cat_vec,
                "category_vector": cat_vec,
                "event_vector": event_vec,
                "device_family": device_family,
                "event_count": len(evts),
                "random_mac": evts[0].get("random_mac", False) if evts else False,
                "volume_concentration_weight": volume_concentration_weight,
                "last_username": last_username,
                "service_account_family": sa_family_name,
                # True when device_family is a single-token coverage artifact
                # (e.g. bare "Intel Corporate" for MACs Mist never fully
                # fingerprinted). Consumed by the family-level rollup in
                # anomaly_detector.score / score_org_wide to drop these MACs
                # from family outlier-ratio calculations — the MAC still
                # participates in DBSCAN/IF/Markov as a data point and keeps
                # its per-MAC flags, but the "family" (which is a junk drawer)
                # does not earn a detector badge of its own.
                "is_bare_one_token": bare_one_token,
                # Resolved manufacturer for this MAC. Blank when nothing
                # resolves (Mist placeholder mfg + no OS/device token match).
                # Used downstream for -MFG rollup membership.
                "resolved_manufacturer": resolved_mfg,
            }

            # ── Dual-family emission ──
            # Same vectors under a composite key with device_family overridden to
            # the virtual service-account label. The two records share weight,
            # event count, and random_mac flag — they are the SAME device viewed
            # under two grouping schemes. anomaly_detector groups by device_family,
            # so the sa record naturally lands in its own family bucket and is
            # scored independently of its physical-device-family peers.
            if sa_family_name:
                features[sa_record_key(mac)] = {
                    "vector": dict(cat_vec),
                    "category_vector": dict(cat_vec),
                    "event_vector": dict(event_vec),
                    "device_family": sa_family_name,
                    "event_count": len(evts),
                    "random_mac": evts[0].get("random_mac", False) if evts else False,
                    "volume_concentration_weight": volume_concentration_weight,
                    "last_username": last_username,
                    "primary_device_family": device_family,
                    "primary_mac": mac,
                    "is_service_account_record": True,
                }
                sa_emitted += 1

            # ── Manufacturer-rollup emission ──
            # Every MAC whose resolved manufacturer meets the threshold is
            # emitted into the features dict an additional time under a
            # composite `#mfg` key with device_family = "{mfg}-MFG". The MFG
            # record is the sole Centroid candidate for that manufacturer
            # (Phase 3 gate in anomaly_detector); bare-1-token and per-
            # fingerprint primary records drop out of Centroid. The MFG record
            # itself does NOT participate in DBSCAN/IF/Markov — those still
            # run on primary per-fingerprint records only.
            if resolved_mfg and resolved_mfg in qualifying_mfgs_set:
                mfg_family_name = mfg_rollup_family_name(resolved_mfg)
                features[mfg_record_key(mac)] = {
                    "vector": dict(cat_vec),
                    "category_vector": dict(cat_vec),
                    "event_vector": dict(event_vec),
                    "device_family": mfg_family_name,
                    "event_count": len(evts),
                    "random_mac": evts[0].get("random_mac", False) if evts else False,
                    "volume_concentration_weight": volume_concentration_weight,
                    "last_username": last_username,
                    "primary_device_family": device_family,
                    "primary_mac": mac,
                    "is_mfg_rollup_record": True,
                    "resolved_manufacturer": resolved_mfg,
                }
                mfg_emitted += 1

        key = _features_redis_key(site_id, wlan)
        await redis_client.set(key, json.dumps(features), ex=FEATURES_TTL)
        log.info(
            f"Built features for {len(features)} records "
            f"({sa_emitted} service-account dual records, "
            f"{mfg_emitted} mfg-rollup dual records, "
            f"{len(qualifying_mfgs_set)} qualifying mfgs ≥ {mfg_rollup_min}) → {key} "
            f"(category_vector={len(CATEGORY_FEATURE_KEYS)}d, "
            f"event_vector={len(event_type_index)}d) "
            f"({skipped} skipped with < {min_mac_events} events) [wlan={wlan}]"
        )
        return len(features)

    finally:
        await redis_client.aclose()


async def get_features(site_id: str, wlan: str) -> dict[str, dict] | None:
    """Return the features dict for the given site/wlan, or None if the key doesn't exist.

    Returns {} (empty dict) when build_features ran but no MACs met the event threshold.
    Returns None when build_features has never been run (key missing from Redis).
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get(_features_redis_key(site_id, wlan))
    finally:
        await redis_client.aclose()
    if raw is None:
        return None
    return json.loads(raw)

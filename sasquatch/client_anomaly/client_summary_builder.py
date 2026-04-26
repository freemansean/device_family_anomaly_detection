"""
client_summary_builder.py -- materialise the per-(mac, site, wlan) summary
table read by the Device Family Drilldown and Device Family Search endpoints.

Architecture: the drilldown endpoints used to scan the full 7-day events
table in Python and aggregate on the fly, which was O(n) in the event count
(easily millions per retention window). This module pre-aggregates during
the detection pipeline tail (Phase 5) so the drilldowns become an indexed
SQLite SELECT instead.

Rebuild strategy: truncate-and-rebuild per (site_id, wlan). Each detection
cycle:
  1. `delete_client_summaries_for_scope(site, wlan)` drops the previous rows.
  2. `build_scope(site, wlan)` computes fresh rows from events + Redis state.
  3. `upsert_client_summaries(rows)` bulk-inserts the new rows.

The builder reads:
  - Events from SQLite (GROUP BY mac, event_category -- never pulls raw JSON)
  - Anomaly scores from sasquatch:anomalies:{site}:{wlan}, falling back to
    sasquatch:org_anomalies:{site}:{wlan} so MACs scored only org-wide are
    still included (mirrors the fallback in the existing drilldown routes).
  - Health scores from sasquatch:health:{site}:{wlan}
  - Client metadata (device_family, username, etc.) from the SQLite clients
    table via db.get_org_client_cache.
  - Service-account family assignments from db.get_service_account_usernames
    so each MAC's service_account_family column can be populated.

Service accounts are a per-device attribute (column `service_account_family`),
not a separate row — the family-level SA rollup already lives in Redis
(org_findings, family-insights). Each MAC carries at most one
`service_account_family` value, equal to "{username_label}.service_account"
when the username has >= SERVICE_ACCOUNT_MIN_MACS peers, else NULL.
"""

from __future__ import annotations

import json
import logging
import time
from collections import Counter, defaultdict
from typing import Optional

from . import config
from . import db
from .client_cache import resolve_manufacturer_from_family
from .event_collector import _EVENT_TYPE_TO_CATEGORY  # event_type -> category
from .feature_engineer import SERVICE_ACCOUNT_SUFFIX
from .health_scorer import _health_redis_key

log = logging.getLogger(__name__)


# Category key -> column name in the client_summary table. Category keys
# match those in event_collector.EVENT_CATEGORIES. Any unmapped category is
# accumulated under `other`.
_CATEGORY_TO_COL: dict[str, str] = {
    "DHCP_SUCCESS": "dhcp_success",
    "DHCP_FAILURE": "dhcp_failure",
    "DNS_SUCCESS": "dns_success",
    "DNS_FAILURE": "dns_failure",
    "AUTH_SUCCESS": "auth_success",
    "AUTH_FAILURE": "auth_failure",
    "ROAM_SUCCESS": "roam_success",
    "ROAM_FAILURE": "roam_failure",
    "DISASSOC_AP": "disassoc_ap",
    "DISASSOC_CLIENT": "disassoc_client",
    "ARP_SUCCESS": "arp_success",
    "ARP_FAILURE": "arp_failure",
    "CAPTIVE_PORTAL": "captive_portal",
    "SECURITY": "security",
    "COLLABORATION": "collaboration",
    "OTHER": "other",
}


def _anomalies_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:anomalies:{site_id}:{wlan}"


def _org_anomalies_key(site_id: str, wlan: str) -> str:
    return f"sasquatch:org_anomalies:{site_id}:{wlan}"


async def _load_anomalies(redis_client, site_id: str, wlan: str) -> dict:
    """
    Load per-MAC anomaly scores for a (site, wlan). Prefers the per-site key
    (richer, written by score()) and falls back to org_anomalies for MACs that
    were only scored against the org-wide pool (see drilldown route comments).
    """
    raw = await redis_client.get(_anomalies_key(site_id, wlan))
    if raw:
        return json.loads(raw)
    org_raw = await redis_client.get(_org_anomalies_key(site_id, wlan))
    if org_raw:
        return json.loads(org_raw)
    return {}


async def _load_health(redis_client, site_id: str, wlan: str) -> dict:
    raw = await redis_client.get(_health_redis_key(site_id, wlan))
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


async def _load_event_aggregates(
    site_id: str, wlan: str,
) -> dict[str, dict]:
    """
    GROUP BY mac, event_category on the events table for a (site, wlan).
    Returns: mac -> {"total": int, "cats": Counter, "first_seen": float,
                     "last_seen": float, "device_family": str | None}

    This is the single expensive read but it hits idx_events_wlan and never
    touches raw_json -- just the denormalized columns.

    Retained for callers that need a single-scope aggregate (tests, ad-hoc
    queries). The rebuild path uses ``_load_event_aggregates_all`` which
    does one org-wide groupby and partitions the result.

    Scoped to the detection window (24h). client_summary backs the family
    drilldown / MAC-prefix search UI, which sits alongside anomaly records
    that are themselves 24h-scoped. A wider window would surface MACs the
    detector never saw this cycle.
    """
    conn = await db.get_connection()
    cutoff = db.get_detection_cutoff()

    rows = await conn.execute_fetchall(
        """SELECT mac, event_type, event_category, device_family,
                  MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts,
                  COUNT(*) AS cnt
           FROM events
           WHERE site_id = ? AND wlan = ? AND timestamp >= ?
           GROUP BY mac, event_type, event_category, device_family""",
        (site_id, wlan, cutoff),
    )

    by_mac: dict[str, dict] = {}
    for mac, event_type, event_category, device_family, first_ts, last_ts, cnt in rows:
        entry = by_mac.setdefault(mac, {
            "total": 0,
            "cats": Counter(),
            "first_seen": first_ts,
            "last_seen": last_ts,
            "device_family": device_family,
        })
        # Trust event_category when present, fall back to the canonical map.
        cat = event_category or _EVENT_TYPE_TO_CATEGORY.get(event_type, "OTHER")
        entry["cats"][cat] += int(cnt)
        entry["total"] += int(cnt)
        if first_ts is not None and (entry["first_seen"] is None or first_ts < entry["first_seen"]):
            entry["first_seen"] = first_ts
        if last_ts is not None and (entry["last_seen"] is None or last_ts > entry["last_seen"]):
            entry["last_seen"] = last_ts
        # Prefer a concrete family name over Unknown/NULL.
        if device_family and entry["device_family"] in (None, "", "Unknown"):
            entry["device_family"] = device_family
    return by_mac


async def _load_event_aggregates_all(
    keep_scopes: set[tuple[str, str]],
) -> dict[tuple[str, str], dict[str, dict]]:
    """
    Single-pass org-wide groupby, partitioned by (site_id, wlan).

    Replaces the 1,182-scope sequential pattern of ``_load_event_aggregates``
    with one index-scan over the retention window. SQLite aggregates in C;
    Python only walks the result once. At ~5M events / 1k scopes this cuts
    rebuild from hours to seconds.

    Scopes not present in ``keep_scopes`` are discarded (the caller has
    already decided which WLANs the pipeline scored). Empty scopes simply
    don't appear in the result.

    Scoped to the detection window (24h) so the rebuilt summary table only
    contains MACs that were active in the same window the detector scored
    against. See _load_event_aggregates for the rationale.
    """
    conn = await db.get_connection()
    cutoff = db.get_detection_cutoff()

    rows = await conn.execute_fetchall(
        """SELECT site_id, wlan, mac, event_type, event_category, device_family,
                  MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts,
                  COUNT(*) AS cnt
           FROM events
           WHERE timestamp >= ?
           GROUP BY site_id, wlan, mac, event_type, event_category, device_family""",
        (cutoff,),
    )

    by_scope: dict[tuple[str, str], dict[str, dict]] = {}
    for (site_id, wlan, mac, event_type, event_category, device_family,
         first_ts, last_ts, cnt) in rows:
        scope = (site_id, wlan or "")
        if scope not in keep_scopes:
            continue
        scope_map = by_scope.setdefault(scope, {})
        entry = scope_map.setdefault(mac, {
            "total": 0,
            "cats": Counter(),
            "first_seen": first_ts,
            "last_seen": last_ts,
            "device_family": device_family,
        })
        cat = event_category or _EVENT_TYPE_TO_CATEGORY.get(event_type, "OTHER")
        entry["cats"][cat] += int(cnt)
        entry["total"] += int(cnt)
        if first_ts is not None and (entry["first_seen"] is None or first_ts < entry["first_seen"]):
            entry["first_seen"] = first_ts
        if last_ts is not None and (entry["last_seen"] is None or last_ts > entry["last_seen"]):
            entry["last_seen"] = last_ts
        if device_family and entry["device_family"] in (None, "", "Unknown"):
            entry["device_family"] = device_family
    return by_scope


# Per-MAC service health is recomputed from the stored category counts
# rather than read from health_scorer output, because health_scorer only
# persists family-level rollups (mac_alarm_count etc.), not the per-MAC
# tripped set. This keeps the column self-consistent with the other counts
# in the same row.
_SERVICE_HEALTH_THRESHOLD = 0.5  # matches health_scorer.SERVICE_HEALTH_THRESHOLD


def _mac_service_alarm_from_cats(cats: Counter) -> bool:
    """True if any (success, failure) pair tips below the per-MAC threshold."""
    pairs = (
        ("AUTH_SUCCESS", "AUTH_FAILURE"),
        ("ROAM_SUCCESS", "ROAM_FAILURE"),
        ("DHCP_SUCCESS", "DHCP_FAILURE"),
        ("DNS_SUCCESS", "DNS_FAILURE"),
        ("ARP_SUCCESS", "ARP_FAILURE"),
    )
    for ok, fail in pairs:
        s = cats.get(ok, 0)
        f = cats.get(fail, 0)
        if s + f == 0:
            continue
        if s / (s + f) < _SERVICE_HEALTH_THRESHOLD:
            return True
    return False


async def build_scope(
    redis_client,
    site_id: str,
    wlan: str,
    *,
    org_id: str,
    org_client_cache: dict,
    sa_lookup: dict[str, dict],
) -> list[dict]:
    """
    Compute summary rows for a single (site_id, wlan) scope.

    ``org_client_cache`` and ``sa_lookup`` are passed in so the caller (the
    pipeline loop) can load them once and reuse across every scope, rather
    than re-querying SQLite per WLAN.

    Returns a list of row dicts ready for ``db.upsert_client_summaries``.
    Returns an empty list if the scope has no events; the caller is expected
    to have already truncated the scope before calling.
    """
    event_agg = await _load_event_aggregates(site_id, wlan)
    if not event_agg:
        return []

    anomalies = await _load_anomalies(redis_client, site_id, wlan)
    health = await _load_health(redis_client, site_id, wlan)

    now = time.time()
    rows: list[dict] = []

    for mac, agg in event_agg.items():
        # Prefer client-cache family (daily refresh is authoritative); fall
        # back to whatever the events table recorded at ingestion.
        client_meta = org_client_cache.get(mac, {})
        device_family = (
            client_meta.get("family")
            or agg.get("device_family")
            or "Unknown"
        )
        last_username_norm = client_meta.get("last_username_norm", "") or ""
        sa_entry = sa_lookup.get(last_username_norm) if last_username_norm else None
        sa_family = (
            f"{sa_entry['label']}{SERVICE_ACCOUNT_SUFFIX}" if sa_entry else None
        )

        anom = anomalies.get(mac) or {}
        health_entry = health.get(device_family) or {}
        health_score = health_entry.get("health_score")

        cats = agg["cats"]
        row = {
            "mac": mac,
            "site_id": site_id,
            "wlan": wlan,
            "org_id": org_id,
            "device_family": device_family,
            "device_model": client_meta.get("model", ""),
            "device_manufacturer": client_meta.get("manufacturer", ""),
            "device_os": client_meta.get("os", ""),
            # Detection-normalized manufacturer used by the <mfg>-MFG rollup
            # drilldown filter. Runs the same resolver feature_engineer uses
            # so the filter key matches the virtual-family membership.
            "resolved_manufacturer": resolve_manufacturer_from_family(
                device_family or "", client_meta.get("manufacturer", "")
            ),
            "last_username": client_meta.get("last_username", ""),
            "service_account_family": sa_family,
            "random_mac": bool(client_meta.get("random_mac", False) or anom.get("random_mac", False)),
            "health_score": health_score,
            "if_score": anom.get("if_score"),
            "centroid_dist_score": anom.get("centroid_dist_score"),
            "dbscan_label": anom.get("dbscan_label"),
            "is_if_outlier": bool(anom.get("is_if_outlier", False)),
            "is_dbscan_outlier": bool(anom.get("is_dbscan_outlier", False)),
            "is_family_outlier": bool(anom.get("is_family_outlier", False)),
            "is_markov_outlier": bool(anom.get("is_markov_outlier", False)),
            "markov_reason": anom.get("markov_reason"),
            "service_alarm": _mac_service_alarm_from_cats(cats),
            "total_events": agg["total"],
            "first_seen": agg["first_seen"],
            "last_seen": agg["last_seen"],
            "built_at": now,
        }
        # Fill category columns from the Counter; defaults stay at 0.
        for cat_key, col_name in _CATEGORY_TO_COL.items():
            row[col_name] = int(cats.get(cat_key, 0))
        rows.append(row)

    return rows


async def _load_redis_state_bulk(
    redis_client,
    scopes: list[tuple[str, str]],
) -> tuple[dict[tuple[str, str], dict], dict[tuple[str, str], dict]]:
    """
    Pipeline-fetch anomaly + health JSON for every scope in one round-trip
    instead of 3 * N sequential GETs. Returns (anomalies_by_scope,
    health_by_scope), each keyed by (site_id, wlan).

    Anomaly fallback mirrors ``_load_anomalies``: prefer per-site, fall back
    to org_anomalies for MACs scored only against the org-wide pool.
    """
    if not scopes:
        return {}, {}

    pipe = redis_client.pipeline()
    for site_id, wlan in scopes:
        pipe.get(_anomalies_key(site_id, wlan))
        pipe.get(_org_anomalies_key(site_id, wlan))
        pipe.get(_health_redis_key(site_id, wlan))
    results = await pipe.execute()

    anomalies: dict[tuple[str, str], dict] = {}
    health: dict[tuple[str, str], dict] = {}
    for idx, scope in enumerate(scopes):
        base = idx * 3
        per_site_raw = results[base]
        org_raw = results[base + 1]
        health_raw = results[base + 2]
        raw = per_site_raw or org_raw
        if raw:
            try:
                anomalies[scope] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                anomalies[scope] = {}
        if health_raw:
            try:
                health[scope] = json.loads(health_raw)
            except (json.JSONDecodeError, TypeError):
                health[scope] = {}
    return anomalies, health


async def rebuild_summary_table(
    redis_client,
    site_wlan_pairs: list[tuple[str, str]],
    *,
    org_id: str,
) -> dict:
    """
    Top-level entry point called from the detection pipeline tail. One
    org-wide events groupby, one bulk Redis pipeline for anomaly + health,
    one bulk DELETE covering every scope, one bulk INSERT.

    Previously this ran 3+ sequential queries per scope (DELETE, SELECT
    GROUP BY, INSERT) plus 3 Redis GETs per scope. At 197 sites * 6 WLANs
    that was ~7k Redis calls + 1,182 groupby scans — the pathological
    case that hung the detection pipeline for hours on a multi-million-
    event retention window.

    Returns a summary dict suitable for log output.
    """
    org_client_cache = await db.get_org_client_cache(org_id) or {}
    sa_min = int(config.get("service_account", "service_account_min_macs") or 0)
    sa_lookup: dict[str, dict] = {}
    if sa_min > 0:
        try:
            sa_lookup = await db.get_service_account_usernames(org_id, sa_min)
        except Exception:
            log.exception("[summary builder] get_service_account_usernames failed")

    keep_scopes = {(s, w) for s, w in site_wlan_pairs}

    # One org-wide groupby, partitioned in Python.
    try:
        agg_by_scope = await _load_event_aggregates_all(keep_scopes)
    except Exception:
        log.exception("[summary builder] org-wide aggregate query failed")
        return {
            "scopes_built": 0,
            "scopes_failed": len(site_wlan_pairs),
            "rows_total": 0,
            "stale_rows_swept": 0,
        }

    # Bulk-fetch all anomaly + health JSON in one Redis pipeline.
    try:
        anomalies_by_scope, health_by_scope = await _load_redis_state_bulk(
            redis_client, site_wlan_pairs,
        )
    except Exception:
        log.exception("[summary builder] bulk Redis state fetch failed")
        anomalies_by_scope, health_by_scope = {}, {}

    # Build every row in memory. At org scale this is ~tens of thousands of
    # small dicts — well under the cost of the SQL we just saved.
    now = time.time()
    all_rows: list[dict] = []
    scopes_built = 0
    for scope in site_wlan_pairs:
        site_id, wlan = scope
        event_agg = agg_by_scope.get(scope)
        if not event_agg:
            scopes_built += 1
            continue
        anomalies = anomalies_by_scope.get(scope, {})
        health = health_by_scope.get(scope, {})
        for mac, agg in event_agg.items():
            client_meta = org_client_cache.get(mac, {})
            device_family = (
                client_meta.get("family")
                or agg.get("device_family")
                or "Unknown"
            )
            last_username_norm = client_meta.get("last_username_norm", "") or ""
            sa_entry = sa_lookup.get(last_username_norm) if last_username_norm else None
            sa_family = (
                f"{sa_entry['label']}{SERVICE_ACCOUNT_SUFFIX}" if sa_entry else None
            )

            anom = anomalies.get(mac) or {}
            health_entry = health.get(device_family) or {}
            health_score = health_entry.get("health_score")

            cats = agg["cats"]
            row = {
                "mac": mac,
                "site_id": site_id,
                "wlan": wlan,
                "org_id": org_id,
                "device_family": device_family,
                "device_model": client_meta.get("model", ""),
                "device_manufacturer": client_meta.get("manufacturer", ""),
                "device_os": client_meta.get("os", ""),
                "resolved_manufacturer": resolve_manufacturer_from_family(
                    device_family or "", client_meta.get("manufacturer", "")
                ),
                "last_username": client_meta.get("last_username", ""),
                "service_account_family": sa_family,
                "random_mac": bool(client_meta.get("random_mac", False) or anom.get("random_mac", False)),
                "health_score": health_score,
                "if_score": anom.get("if_score"),
                "centroid_dist_score": anom.get("centroid_dist_score"),
                "dbscan_label": anom.get("dbscan_label"),
                "is_if_outlier": bool(anom.get("is_if_outlier", False)),
                "is_dbscan_outlier": bool(anom.get("is_dbscan_outlier", False)),
                "is_family_outlier": bool(anom.get("is_family_outlier", False)),
                "is_markov_outlier": bool(anom.get("is_markov_outlier", False)),
                "markov_reason": anom.get("markov_reason"),
                "service_alarm": _mac_service_alarm_from_cats(cats),
                "total_events": agg["total"],
                "first_seen": agg["first_seen"],
                "last_seen": agg["last_seen"],
                "built_at": now,
            }
            for cat_key, col_name in _CATEGORY_TO_COL.items():
                row[col_name] = int(cats.get(cat_key, 0))
            all_rows.append(row)
        scopes_built += 1

    # Single truncate-and-rebuild for the whole table. The sweep call below
    # collapses to this when no rows survive filtering, but doing the DELETE
    # up front keeps the semantics identical to the old per-scope truncate.
    try:
        conn = await db.get_connection()
        await conn.execute("DELETE FROM client_summary")
        await conn.commit()
    except Exception:
        log.exception("[summary builder] truncate failed")
        return {
            "scopes_built": 0,
            "scopes_failed": len(site_wlan_pairs),
            "rows_total": 0,
            "stale_rows_swept": 0,
        }

    rows_total = 0
    if all_rows:
        try:
            rows_total = await db.upsert_client_summaries(all_rows)
        except Exception:
            log.exception("[summary builder] bulk insert failed")
            return {
                "scopes_built": 0,
                "scopes_failed": len(site_wlan_pairs),
                "rows_total": 0,
                "stale_rows_swept": 0,
            }

    # Stale-scope sweep is a no-op after a full truncate, but keep the call
    # so the return shape is unchanged and a future refactor that drops the
    # truncate still gets the sweep.
    try:
        swept = await db.delete_client_summaries_not_in(list(site_wlan_pairs))
    except Exception:
        swept = 0
        log.exception("[summary builder] stale-scope sweep failed")

    return {
        "scopes_built": scopes_built,
        "scopes_failed": 0,
        "rows_total": rows_total,
        "stale_rows_swept": swept,
    }

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
    "DISASSOC": "disassoc",
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
    """
    conn = await db.get_connection()
    cutoff = time.time() - db.EVENTS_RETENTION_SECONDS

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


async def rebuild_summary_table(
    redis_client,
    site_wlan_pairs: list[tuple[str, str]],
    *,
    org_id: str,
) -> dict:
    """
    Top-level entry point called from the detection pipeline tail. Walks
    every (site_id, wlan) scope in ``site_wlan_pairs``, truncates the scope,
    rebuilds it, and sweeps any stale scopes that no longer have events.

    Best-effort per scope: a single scope's failure is logged and the rest
    continue. Returns a summary dict suitable for log output.
    """
    org_client_cache = await db.get_org_client_cache(org_id) or {}
    sa_min = int(config.get("service_account", "service_account_min_macs") or 0)
    sa_lookup: dict[str, dict] = {}
    if sa_min > 0:
        try:
            sa_lookup = await db.get_service_account_usernames(org_id, sa_min)
        except Exception:
            log.exception("[summary builder] get_service_account_usernames failed")

    scopes_built = 0
    scopes_failed = 0
    rows_total = 0
    for site_id, wlan in site_wlan_pairs:
        try:
            await db.delete_client_summaries_for_scope(site_id, wlan)
            rows = await build_scope(
                redis_client, site_id, wlan,
                org_id=org_id,
                org_client_cache=org_client_cache,
                sa_lookup=sa_lookup,
            )
            if rows:
                await db.upsert_client_summaries(rows)
            scopes_built += 1
            rows_total += len(rows)
        except Exception:
            scopes_failed += 1
            log.exception(
                "[summary builder] build failed: site=%s wlan=%s", site_id, wlan,
            )

    # Sweep scopes that no longer exist in the event data.
    try:
        swept = await db.delete_client_summaries_not_in(list(site_wlan_pairs))
    except Exception:
        swept = 0
        log.exception("[summary builder] stale-scope sweep failed")

    return {
        "scopes_built": scopes_built,
        "scopes_failed": scopes_failed,
        "rows_total": rows_total,
        "stale_rows_swept": swept,
    }

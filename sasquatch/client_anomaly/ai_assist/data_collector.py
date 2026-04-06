"""
data_collector.py — Gather device family statistics from Redis for AI Assist prompts.

Supports two scopes:
  "site"  — reads data for a single site_id
  "org"   — aggregates across all org sites (enumerates sites via Mist API)

The returned structure is a list of family stats dicts, each with the shape:

  {
    "name":              str,           # device family name, e.g. "iPhone"
    "total_events":      int,
    "client_count":      int,           # unique MACs observed
    "site_count":        int,           # number of sites this family appeared on
    "if_outlier_count":  int,           # MACs flagged by Isolation Forest
    "worst_severity":    str | None,    # "significant" | "moderate" | "minimal" | None
    "is_family_outlier": bool,          # any site flagged whole family as outlier
    "categories":        {              # event category breakdown
        "<CAT_KEY>": {"count": int, "ratio": float},
        ...
    },
    "findings": [                       # ML-detected patterns for this family
        {
            "probable_pattern": str,
            "severity":         str,
            "mac_count":        int,
            "example_macs":     [str],
        },
        ...
    ],
  }
"""

import json
import logging
import os
from collections import Counter, defaultdict

import httpx
import redis.asyncio as aioredis

from ..event_collector import EVENT_CATEGORIES

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

_SEVERITY_RANK = {"significant": 3, "moderate": 2, "minimal": 1}

ALL_CATEGORIES = list(EVENT_CATEGORIES.keys()) + ["OTHER"]


async def _get_org_site_ids() -> list[str]:
    """Fetch all site IDs from the Mist API for the configured org."""
    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/sites"
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
    return [s["id"] for s in resp.json() if "id" in s]


def _accumulate_site_data(
    site_events: list[dict],
    site_findings: list[dict],
    site_anomalies: dict,
    family_event_counts: dict,   # mutated in-place
    family_total_events: Counter,
    family_macs: dict,
    family_site_count: Counter,
    family_worst_severity: dict,
    family_is_family_outlier: dict,
    family_if_outlier_count: Counter,
    family_findings: dict,
) -> None:
    """
    Merge one site's Redis data into the per-family accumulators.
    All accumulator dicts are mutated in-place.
    """
    seen_families: set[str] = set()

    for event in site_events:
        family = event.get("device_family", "Unknown")
        category = event.get("event_category", "OTHER")
        family_event_counts[family][category] += 1
        family_total_events[family] += 1
        seen_families.add(family)
        mac = (event.get("mac") or "").replace(":", "").lower()
        if mac:
            family_macs[family].add(mac)

    for fam in seen_families:
        family_site_count[fam] += 1

    for finding in site_findings:
        fam = finding.get("device_family")
        if not fam:
            continue
        sev = finding.get("severity")
        if sev and _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(family_worst_severity.get(fam, ""), 0):
            family_worst_severity[fam] = sev
        if finding.get("is_family_outlier"):
            family_is_family_outlier[fam] = True
        if sev in _SEVERITY_RANK:
            # Record per-family finding (deduplicated by pattern)
            pattern = finding.get("probable_pattern", "unknown")
            key = (fam, pattern, sev)
            if key not in family_findings:
                family_findings[key] = {
                    "probable_pattern": pattern,
                    "severity": sev,
                    "mac_count": 0,
                    "example_macs": [],
                }
            family_findings[key]["mac_count"] += len(finding.get("example_macs", []))
            family_findings[key]["example_macs"].extend(finding.get("example_macs", [])[:2])

    for mac, data in site_anomalies.items():
        fam = data.get("device_family")
        if not fam:
            continue
        if data.get("is_if_outlier"):
            family_if_outlier_count[fam] += 1


def _build_family_stats(
    family_event_counts: dict,
    family_total_events: Counter,
    family_macs: dict,
    family_site_count: Counter,
    family_worst_severity: dict,
    family_is_family_outlier: dict,
    family_if_outlier_count: Counter,
    family_findings: dict,
) -> list[dict]:
    """Convert accumulators into the final list of family stats dicts."""
    result = []
    for family, cat_counts in family_event_counts.items():
        total = family_total_events[family]

        # Collect findings for this family, sorted by severity
        findings = [
            v for (fam, _, _), v in family_findings.items() if fam == family
        ]
        findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 0), reverse=True)
        # Deduplicate example MACs
        for f in findings:
            f["example_macs"] = list(dict.fromkeys(f["example_macs"]))[:3]

        result.append({
            "name": family,
            "total_events": total,
            "client_count": len(family_macs.get(family, set())),
            "site_count": family_site_count[family],
            "if_outlier_count": family_if_outlier_count[family],
            "worst_severity": family_worst_severity.get(family),
            "is_family_outlier": family_is_family_outlier.get(family, False),
            "categories": {
                cat: {
                    "count": cat_counts.get(cat, 0),
                    "ratio": round(cat_counts.get(cat, 0) / total, 4) if total > 0 else 0.0,
                }
                for cat in ALL_CATEGORIES
            },
            "findings": findings,
        })

    # Sort families by total event volume descending
    result.sort(key=lambda x: x["total_events"], reverse=True)
    return result


async def gather_family_stats(scope: str, site_id: str | None = None) -> list[dict]:
    """
    Collect and return family stats for the given scope.

    Parameters
    ----------
    scope   : "site" or "org"
    site_id : required when scope == "site"

    Returns a list of family stats dicts (see module docstring).
    Raises ValueError for invalid arguments, RuntimeError for connectivity issues.
    """
    if scope == "site":
        if not site_id:
            raise ValueError("site_id is required for scope='site'")
        site_ids = [site_id]
    elif scope == "org":
        if not MIST_ORG_ID or not MIST_API_TOKEN:
            raise ValueError("MIST_ORG_ID and MIST_API_TOKEN must be set for org scope")
        try:
            site_ids = await _get_org_site_ids()
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Could not fetch org sites from Mist API: {exc}") from exc
    else:
        raise ValueError(f"Invalid scope '{scope}'. Must be 'site' or 'org'.")

    # Per-family accumulators
    family_event_counts: dict[str, Counter] = defaultdict(Counter)
    family_total_events: Counter = Counter()
    family_macs: dict[str, set] = defaultdict(set)
    family_site_count: Counter = Counter()
    family_worst_severity: dict[str, str] = {}
    family_is_family_outlier: dict[str, bool] = defaultdict(bool)
    family_if_outlier_count: Counter = Counter()
    family_findings: dict[tuple, dict] = {}

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        for sid in site_ids:
            events_raw = await redis_client.get(f"sasquatch:events:{sid}")
            findings_raw = await redis_client.get(f"sasquatch:findings:{sid}")
            anomalies_raw = await redis_client.get(f"sasquatch:anomalies:{sid}")

            if not events_raw:
                continue

            site_events: list[dict] = json.loads(events_raw)
            site_findings: list[dict] = json.loads(findings_raw) if findings_raw else []
            site_anomalies: dict = json.loads(anomalies_raw) if anomalies_raw else {}

            _accumulate_site_data(
                site_events, site_findings, site_anomalies,
                family_event_counts, family_total_events, family_macs,
                family_site_count, family_worst_severity, family_is_family_outlier,
                family_if_outlier_count, family_findings,
            )
    finally:
        await redis_client.aclose()

    return _build_family_stats(
        family_event_counts, family_total_events, family_macs, family_site_count,
        family_worst_severity, family_is_family_outlier, family_if_outlier_count,
        family_findings,
    )

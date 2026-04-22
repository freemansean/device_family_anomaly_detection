"""
webhook_dispatcher.py — Evaluate findings against dual alert gate and POST to webhook.

A finding triggers the webhook only when BOTH conditions are true:
  1. The device family carries at least one anomaly label:
       - is_family_outlier (centroid IF/distance) — whole family collectively differs
         from all other families
       - is_family_dbscan_outlier — fraction of DBSCAN noise MACs in the family
         exceeds DBSCAN_FAMILY_NOISE_THRESHOLD (a site-wide clustering anomaly)
       - is_family_markov_outlier — Markov Chain analysis found an anomalous event
         chain pattern in >= MARKOV_FAMILY_OUTLIER_RATIO of the family's clients
  2. The family's health score is below ANOMALY_HEALTH_SCORE_THRESHOLD. This
     confirms that the behavioral anomaly is accompanied by measurable failure
     degradation, not just an unusual-but-healthy traffic pattern.

Single-device anomalies (per-family IF or DBSCAN outliers for one MAC) produce
findings visible in the UI but never trigger the webhook.

Retry logic: 3 attempts with exponential backoff (1s, 2s, 4s).
Never raises — webhook failure does not kill the scheduler job.

Marvis TSHOOT enrichment: each qualifying finding is enriched with results from the
  Mist org-level troubleshoot API, targeting the worst-health MACs in the family. The
  `marvis_tshoot` field on each finding is a list of {mac, tshoot_results} dicts.
  TSHOOT failures never block webhook delivery.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis

from . import config
from .anomaly_detector import HIDDEN_FAMILIES, get_findings, get_org_findings
from .client_cache import get_client_cache
from .health_scorer import get_health

log = logging.getLogger(__name__)

WEBHOOK_URL = os.getenv("ANOMALY_WEBHOOK_URL", "")

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


def get_health_score_threshold() -> float:
    """Read health score threshold via the centralised config module.

    Resolution: config_overrides.json → env var → hardcoded default (0.30).
    Imported by routes.py so the same value is used for API alert filtering.
    Lives under the `general` section because it gates alarm generation at
    both org and site level alongside `alarm_min_family_size`.
    """
    return config.get("general", "anomaly_health_score_threshold")


def get_alarm_service_device_pct() -> float:
    """Read the service-alarm device-percentage threshold.

    A family fires an alarm via the service-alarm path when at least this
    fraction of its MACs have individually tripped a service alarm. Default
    0.50 (at least half of the family must be tripped). Imported by
    routes.py so the same gate is used for API alert filtering.
    """
    return config.get("general", "alarm_service_device_pct")


def get_alarm_health_combine() -> str:
    """Read the combine mode for the two health-side alarm gates.

    "or"  — fire when either the health-score gate OR the service-alarm
            device-pct gate trips (default; preserves prior behavior).
    "and" — fire only when BOTH health-side gates trip.
    Any value other than "and" (case-insensitive) is treated as "or".
    """
    raw = config.get("general", "alarm_health_combine")
    return "and" if str(raw).strip().lower() == "and" else "or"


def health_gate_passes(
    unhealthy_by_score: bool,
    unhealthy_by_service: bool,
    combine: str,
) -> bool:
    """Combine the two health-side gate results per the admin-selected mode."""
    if combine == "and":
        return unhealthy_by_score and unhealthy_by_service
    return unhealthy_by_score or unhealthy_by_service


def get_alarm_dbscan_markov_ratio() -> float:
    """Read the DBSCAN/Markov family-rollup alarm ratio.

    A family fires an alarm via the rollup gate when the fraction of its
    clients flagged by *either* DBSCAN or Markov is at or above this value.
    Inter-family centroid detection (is_family_outlier) is independent of
    this gate and remains independently sufficient to fire an alarm.
    Resolution: config_overrides.json → env var → hardcoded default (0.70).
    Imported by routes.py so the same ratio is used for API alert filtering.
    """
    return config.get("general", "alarm_dbscan_markov_ratio")


def family_passes_dbscan_markov_gate(finding: dict, ratio: float) -> bool:
    """Return True when a finding qualifies for an alarm via the centroid or
    the DBSCAN-or-Markov rollup gate.

    Centroid (is_family_outlier) is independently sufficient. Otherwise the
    per-MAC union of DBSCAN and Markov flags must reach `ratio` of the
    family's total client count.

    HIDDEN_FAMILIES ("Unknown", "IoT (Unknown)") are heterogeneous catch-all
    buckets and never eligible for alarms, regardless of any other signal.
    This is the single alarm chokepoint shared by webhook dispatch and the
    /org/alerts + /org/alerts-full feeds, so exclusion here covers every path.
    """
    if finding.get("device_family") in HIDDEN_FAMILIES:
        return False
    if finding.get("is_family_outlier", False):
        return True
    total = finding.get("total_mac_count", 0) or 0
    if total <= 0:
        return False
    union_count = finding.get("dbscan_or_markov_outlier_count", 0) or 0
    return (union_count / total) >= ratio


def get_alarm_min_family_size() -> int:
    """Read the minimum device-family size required to generate an alarm.

    Families with `total_mac_count` below this threshold are suppressed from
    both webhook dispatch and the OrgAlerts API feed, even if they otherwise
    pass the dual gate. Default 10 (suppress families smaller than 10 MACs).
    Resolution: config_overrides.json → env var → hardcoded default.
    Imported by routes.py so the same floor is used for API alert filtering.
    """
    return config.get("general", "alarm_min_family_size")


async def _get_webhook_config() -> dict:
    """
    Read runtime webhook configuration from Redis (sasquatch:webhook_config).
    Falls back to .env defaults for any keys not present in Redis.
    """
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        raw = await redis_client.get("sasquatch:webhook_config")
    finally:
        await redis_client.aclose()

    config = {
        "enabled": bool(WEBHOOK_URL),
        "url": WEBHOOK_URL,
        "scope": "org_and_site",
        "marvis_tshoot_enabled": bool(MIST_ORG_ID and MIST_API_TOKEN),
        "family_size_threshold": 1,
    }
    if raw:
        config.update(json.loads(raw))
    return config

async def _run_client_tshoot(site_id: str, mac: str) -> dict:
    """
    Call the Mist org-level client TSHOOT API for a single MAC.

    GET /api/v1/orgs/{org_id}/troubleshoot?mac={mac}&site_id={site_id}

    Returns a dict with keys:
      status   — "completed" | "error"
      results  — raw Mist `results` list on success, [] otherwise
      error    — error message string (only on "error" status)

    Handles 429 rate-limiting: reads Retry-After header (default 10s, capped at 60s)
    and retries once. Never raises — TSHOOT failures must not block webhook delivery.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return {"status": "error", "error": "MIST_ORG_ID or MIST_API_TOKEN not configured", "results": []}
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}
    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/troubleshoot?mac={mac}&site_id={site_id}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            for attempt in range(2):
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 10))
                    log.warning(
                        "TSHOOT rate-limited for %s at site %s — backing off %ds",
                        mac, site_id, retry_after,
                    )
                    await asyncio.sleep(retry_after)
                    continue
                resp.raise_for_status()
                return {"status": "completed", "results": resp.json().get("results", [])}
            # Exhausted retries after 429
            return {"status": "error", "error": "rate limited (429)", "results": []}
    except httpx.HTTPStatusError as exc:
        log.warning(
            "Client TSHOOT HTTP error for %s at site %s: %s %s",
            mac, site_id, exc.response.status_code, exc.response.text[:200],
        )
        return {"status": "error", "error": str(exc), "results": []}
    except Exception as exc:
        log.warning("Client TSHOOT failed for %s at site %s: %s", mac, site_id, exc)
        return {"status": "error", "error": str(exc), "results": []}


async def run_family_tshoot(site_id: str, family: str, wlan: str) -> list[dict]:
    """
    Public API for the manual dashboard trigger.

    Reads worst_health_macs from the current finding for the given family/wlan
    and runs TSHOOT for all worst-health MACs concurrently.

    Returns a list of {mac, ap, status, results, [error]} dicts — one per MAC.
    Returns [] if no finding exists for this family or no worst_health_macs present.
    """
    findings = await get_findings(site_id, wlan)
    target_finding = next(
        (f for f in findings if f.get("device_family") == family), None
    )
    if not target_finding:
        return []

    worst_macs = target_finding.get("worst_health_macs", [])
    if not worst_macs or not MIST_API_TOKEN:
        return []

    try:
        cache = await get_client_cache() or {}
    except Exception:
        cache = {}

    async def _one(mac_entry: dict) -> dict:
        mac = mac_entry["mac"]
        mac_norm = mac.replace(":", "").lower()
        ap = (cache.get(mac_norm) or cache.get(mac) or {}).get("last_ap", "")
        result = await _run_client_tshoot(site_id, mac)
        return {"mac": mac, "ap": ap, **result}

    return list(await asyncio.gather(*[_one(m) for m in worst_macs]))


def _slim_finding_for_webhook(finding: dict, org_scope: bool) -> dict:
    """
    Project a finding down to the minimal shape the Sasquatch webhook consumer cares about.

    Dropped as of the 2026-04 trim (reasoning in TODO.md):
      - severity, outlier_ratio, weighted_outlier_score
          → admin tunes alerting via thresholds, raw ratio is hard to interpret
      - centroid_dist_score, dbscan_family_noise_ratio, dbscan_severity,
        dbscan_outlier_ratio, dbscan_outlier_count, dbscan_outlier_site_count
          → internal detector metrics; consumers only need the is_family_*_outlier flags
      - if_outlier_macs, if_outlier_count
          → subsumed by affected_mac_count + worst_health_macs
      - markov_family_anomaly_ratio, markov_evaluatable_count,
        markov_family_anomalous_count
          → collapsed into markov_family_reason
      - example_macs
          → legacy component; worst_health_macs carries the actionable devices
      - top_features
          → current feature list needs rework before it is useful downstream
      - service_alarm_counts
          → consumer reads service_alarms list + service_health dict
      - health_components (family-level and per-MAC on worst_health_macs)
          → redundant with service_health; service_health is success-ratio per
            active MAC and is the actionable per-service signal. health_components
            used an all-MACs denominator that diluted services where only a subset
            of the family is active (e.g. printers and DNS).
      - wlan (per-finding)
          → always matches top-level wlan in the envelope

    Kept: family identity, gate flags, health evidence, worst-health MACs, marvis_tshoot,
    and org-only site fanout fields.
    """
    slim = {
        "device_family": finding.get("device_family"),
        "family_kind": finding.get("family_kind"),
        "affected_mac_count": finding.get("affected_mac_count"),
        "total_mac_count": finding.get("total_mac_count"),
        "is_family_outlier": finding.get("is_family_outlier", False),
        "is_family_dbscan_outlier": finding.get("is_family_dbscan_outlier", False),
        "is_family_markov_outlier": finding.get("is_family_markov_outlier", False),
        "markov_family_reason": finding.get("markov_family_reason"),
        "probable_pattern": finding.get("probable_pattern"),
        "health_score": finding.get("health_score"),
        "service_alarms": finding.get("service_alarms", []),
        "service_health": finding.get("service_health", {}),
    }

    # Service-account fields — only include when the family actually is one,
    # so non-SA payloads aren't cluttered with empty strings / empty lists.
    if finding.get("family_kind") == "service_account":
        slim["service_account_label"] = finding.get("service_account_label", "")
        slim["service_account_member_families"] = finding.get(
            "service_account_member_families", []
        )

    # Worst-health MACs + TSHOOT enrichment are populated for both site- and
    # org-scope findings. Org-scope entries include a per-MAC `site_id` so the
    # consumer can correlate each troubled MAC with the specific site it lives
    # at; site-scope entries omit it (the outer `site_id` already identifies
    # the site).
    if "worst_health_macs" in finding:
        slim["worst_health_macs"] = [
            {k: v for k, v in entry.items() if k != "health_components"}
            for entry in finding["worst_health_macs"]
        ]
    if "marvis_tshoot" in finding:
        slim["marvis_tshoot"] = finding["marvis_tshoot"]

    # Org-only fanout fields so downstream can page the right site owners.
    if org_scope:
        slim["site_count"] = finding.get("site_count", 0)
        slim["sites_affected"] = finding.get("sites_affected", [])

    return slim


async def _post_with_retry(url: str, payload: dict) -> bool:
    """
    POST payload to url. Retries 3 times with exponential backoff.
    Returns True on success, False on all failures.
    """
    delays = [1, 2, 4]
    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt, delay in enumerate(delays, start=1):
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                log.info(f"Webhook delivered on attempt {attempt}: {resp.status_code}")
                return True
            except httpx.HTTPStatusError as exc:
                log.warning(
                    f"Webhook attempt {attempt} HTTP error: "
                    f"{exc.response.status_code} {exc.response.text[:200]}"
                )
            except Exception as exc:
                log.warning(f"Webhook attempt {attempt} failed: {exc}")

            if attempt < len(delays):
                await asyncio.sleep(delay)

    log.error(f"Webhook delivery failed after {len(delays)} attempts to {url}")
    return False


async def evaluate_and_dispatch(
    site_id: str,
    wlan: str,
    org_scope: bool = False,
) -> bool:
    """
    Load findings and health scores from Redis, apply dual alert gate, POST to
    webhook if any findings qualify.

    Dual gate — a finding is webhook-eligible only when:
      - finding["is_family_outlier"] is True  (centroid IF flagged the whole family)
      - family health_score < HEALTH_SCORE_THRESHOLD (family is also measurably failing)

    wlan: WLAN scope to evaluate (specific SSID name, required).
    org_scope=True: read from org-wide findings/health keys instead of per-site keys.

    Runtime config (stored in Redis key sasquatch:webhook_config) overrides .env:
      - enabled: bool — master on/off switch
      - url: str — POST destination
      - scope: "org_only" | "org_and_site" — whether site-level alarms are dispatched
      - marvis_tshoot_enabled: bool — whether TSHOOT enrichment runs before dispatch

    Returns True if webhook was sent (or no qualifying findings), False on delivery failure.
    """
    config = await _get_webhook_config()
    threshold = get_health_score_threshold()
    alarm_min_family_size = int(get_alarm_min_family_size())
    service_device_pct = float(get_alarm_service_device_pct())
    dbscan_markov_ratio = float(get_alarm_dbscan_markov_ratio())
    health_combine = get_alarm_health_combine()

    effective_url = config["url"]
    if not config["enabled"] or not effective_url:
        log.debug(
            "Webhook dispatch skipped (enabled=%s, url_set=%s)",
            config["enabled"], bool(effective_url),
        )
        return True

    findings = await (get_org_findings(wlan) if org_scope else get_findings(site_id, wlan))
    # For org_scope, health_score is embedded directly on each finding by score_org_wide().
    # For site scope, look up health from the per-site Redis key.
    health = {} if org_scope else await get_health(site_id, wlan)

    qualifying = []
    for f in findings:
        family = f.get("device_family", "")

        # Gate 1: family must qualify via the centroid OR the
        # DBSCAN-or-Markov rollup gate. Centroid (is_family_outlier) is
        # independently sufficient. Otherwise the per-MAC union of DBSCAN
        # and Markov flags must reach `alarm_dbscan_markov_ratio` of the
        # family's total client count.
        if not family_passes_dbscan_markov_gate(f, dbscan_markov_ratio):
            continue

        # Gate 2: family must be unhealthy by EITHER metric:
        #   - aggregate health score below threshold, OR
        #   - at least one service alarm present (>50% of active MACs unhealthy in a service)
        # For org_scope, both health_score and service_alarms are embedded on the finding
        # by score_org_wide(). For site scope, cross-reference against the per-site health dict.
        if org_scope:
            health_score = f.get("health_score", 1.0)
            health_components = f.get("health_components", {})
            service_alarms = f.get("service_alarms", []) or []
            service_health = f.get("service_health", {}) or {}
            mac_alarm_ratio = float(f.get("mac_alarm_ratio", 0.0) or 0.0)
        else:
            family_health = health.get(family, {})
            health_score = family_health.get("health_score", 1.0)
            health_components = family_health.get("components", {})
            service_alarms = family_health.get("service_alarms", []) or []
            service_health = family_health.get("service_health", {}) or {}
            mac_alarm_ratio = float(family_health.get("mac_alarm_ratio", 0.0) or 0.0)

        unhealthy_by_score = health_score < threshold
        # Service-alarm gate fires only when the share of devices in the family
        # that have individually tripped a service alarm meets the admin-set
        # device-percentage floor. With the default floor of 0.0, any single
        # tripped device is enough — matching the prior "any service alarm fires"
        # behavior.
        unhealthy_by_service = (
            len(service_alarms) > 0 and mac_alarm_ratio >= service_device_pct
        )
        if not health_gate_passes(unhealthy_by_score, unhealthy_by_service, health_combine):
            log.debug(
                "[%s] Skipping webhook for [%s]: rollup gate passed but "
                "health_score=%.3f >= threshold %.3f and service-alarm device "
                "ratio %.3f < %.3f (centroid=%s dbscan_or_markov=%d/%d)",
                wlan, family, health_score, threshold,
                mac_alarm_ratio, service_device_pct,
                f.get("is_family_outlier"),
                f.get("dbscan_or_markov_outlier_count", 0),
                f.get("total_mac_count", 0),
            )
            continue

        # Gate 3: family must have at least family_size_threshold affected devices.
        # Families below the threshold are visible in the UI but suppressed from webhook dispatch.
        family_size_threshold = config.get("family_size_threshold", 1)
        affected_count = f.get("affected_mac_count", 0)
        if affected_count < family_size_threshold:
            log.debug(
                "[%s] Skipping webhook for [%s]: affected_mac_count=%d < family_size_threshold=%d",
                wlan, family, affected_count, family_size_threshold,
            )
            continue

        # Gate 4: suppress tiny device families entirely — a family with fewer than
        # alarm_min_family_size total members can't produce a statistically meaningful
        # alarm. Set via the General Config tab; default 1 = no suppression.
        total_count = f.get("total_mac_count", 0) or 0
        if total_count < alarm_min_family_size:
            log.debug(
                "[%s] Skipping alarm for [%s]: total_mac_count=%d < alarm_min_family_size=%d",
                wlan, family, total_count, alarm_min_family_size,
            )
            continue

        # Attach health data to the outbound finding payload
        qualifying.append({
            **f,
            "health_score": health_score,
            "health_components": health_components,
            "service_alarms": service_alarms,
            "service_health": service_health,
            "mac_alarm_ratio": mac_alarm_ratio,
        })

    if not qualifying:
        log.info(
            f"[{wlan}] No findings passed dual alert gate "
            f"(family_outlier + health < {threshold}) — no webhook sent"
        )
        return True

    # Scope gate: "org_only" means site-level dispatches are suppressed.
    # Alert history was already recorded above so sessions remain consistent.
    if not org_scope and config["scope"] == "org_only":
        log.debug(
            "[%s] Webhook scope is org_only — %d qualifying finding(s) tracked but not dispatched",
            wlan, len(qualifying),
        )
        return True

    # Enrich each qualifying finding with TSHOOT results for its worst MACs.
    # All TSHOOT calls across all findings are dispatched concurrently. For
    # org-scope dispatch each mac_entry carries its own site_id (set by
    # score_org_wide) so TSHOOT targets the Mist site where that MAC lives;
    # site-scope entries have no site_id and fall back to the outer site_id.
    if config["marvis_tshoot_enabled"] and MIST_ORG_ID and MIST_API_TOKEN:
        # Build a flat list of (finding_index, mac_entry, target_site) tuples so
        # we can scatter/gather.
        tshoot_tasks: list[tuple[int, dict, str]] = []
        for i, finding in enumerate(qualifying):
            for mac_entry in finding.get("worst_health_macs", []):
                target_site = mac_entry.get("site_id") or site_id
                tshoot_tasks.append((i, mac_entry, target_site))

        if tshoot_tasks:
            # return_exceptions=True so a single bad MAC (timeout, 500, malformed
            # response) cannot crash the entire webhook dispatch. Failed lookups
            # fall through as empty tshoot_results and are logged.
            results = await asyncio.gather(
                *[_run_client_tshoot(t[2], t[1]["mac"]) for t in tshoot_tasks],
                return_exceptions=True,
            )
            # Group results back onto each finding.
            finding_tshoot: dict[int, list[dict]] = {i: [] for i in range(len(qualifying))}
            for (i, mac_entry, target_site), result in zip(tshoot_tasks, results):
                if isinstance(result, BaseException):
                    log.warning(
                        "[%s] TSHOOT failed for MAC %s at site %s: %s",
                        wlan, mac_entry["mac"], target_site, result,
                    )
                    tshoot_results = []
                else:
                    tshoot_results = result.get("results", [])
                entry = {
                    "mac": mac_entry["mac"],
                    "tshoot_results": tshoot_results,
                }
                # Preserve per-MAC site_id for org-scope consumers so they can
                # correlate each tshoot block with its sites_affected entry.
                if org_scope:
                    entry["site_id"] = target_site
                finding_tshoot[i].append(entry)
            for i, finding in enumerate(qualifying):
                finding["marvis_tshoot"] = finding_tshoot[i]
            log.info(
                "[%s] TSHOOT enrichment complete: %d MACs queried across %d finding(s)",
                wlan, len(tshoot_tasks), len(qualifying),
            )
    else:
        log.debug(
            "[%s] TSHOOT skipped (marvis_tshoot_enabled=%s, org_id_set=%s, token_set=%s)",
            wlan, config["marvis_tshoot_enabled"], bool(MIST_ORG_ID), bool(MIST_API_TOKEN),
        )

    slim_findings = [_slim_finding_for_webhook(f, org_scope) for f in qualifying]

    payload = {
        "source": "sasquatch_client_anomaly",
        "scope": "org" if org_scope else "site",
        # site_id is meaningful only for site-scope dispatch; org-scope callers
        # pass the sentinel "__org__" which is not a valid Mist site_id.
        "site_id": None if org_scope else site_id,
        "wlan": wlan,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "findings": slim_findings,
    }

    # Summary log at INFO so ops can see dispatches without drowning in megabytes
    # of findings + TSHOOT JSON. Full payload available at DEBUG.
    preview_families = [f.get("device_family", "?") for f in qualifying[:3]]
    more = max(0, len(qualifying) - 3)
    log.info(
        "[%s] Dispatching webhook: %d finding(s) passed dual alert gate "
        "(is_family_outlier + health_score < %s). Families: %s%s",
        wlan, len(qualifying), threshold, preview_families,
        f" (+{more} more)" if more else "",
    )
    if log.isEnabledFor(logging.DEBUG):
        log.debug("[%s] Full webhook payload: %s", wlan, json.dumps(payload, indent=2))
    return await _post_with_retry(effective_url, payload)

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

from . import alert_tracker, config
from .anomaly_detector import get_findings, get_org_findings
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

    Resolution: config_overrides.json → env var → hardcoded default (0.80).
    Imported by routes.py so the same value is used for API alert filtering.
    """
    return config.get("anomaly", "anomaly_health_score_threshold")


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
        cache = await get_client_cache(site_id)
    except Exception:
        cache = {}

    async def _one(mac_entry: dict) -> dict:
        mac = mac_entry["mac"]
        mac_norm = mac.replace(":", "").lower()
        ap = (cache.get(mac_norm) or cache.get(mac) or {}).get("last_ap", "")
        result = await _run_client_tshoot(site_id, mac)
        return {"mac": mac, "ap": ap, **result}

    return list(await asyncio.gather(*[_one(m) for m in worst_macs]))


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

        # Gate 1: must carry at least one family-level anomaly label
        # (centroid IF/distance, DBSCAN family noise, or Markov Chain)
        is_any_family_anomaly = (
            f.get("is_family_outlier", False)
            or f.get("is_family_dbscan_outlier", False)
            or f.get("is_family_markov_outlier", False)
        )
        if not is_any_family_anomaly:
            continue

        # Gate 2: family health score must be below threshold.
        # For org_scope, use health_score embedded on the finding by score_org_wide().
        # For site scope, cross-reference against the per-site health dict.
        if org_scope:
            health_score = f.get("health_score", 1.0)
            health_components = f.get("health_components", {})
        else:
            family_health = health.get(family, {})
            health_score = family_health.get("health_score", 1.0)
            health_components = family_health.get("components", {})

        if health_score >= threshold:
            log.debug(
                "[%s] Skipping webhook for [%s]: family anomaly label present but "
                "health_score=%.3f >= threshold %.3f (if=%s dbscan=%s markov=%s)",
                wlan, family, health_score, threshold,
                f.get("is_family_outlier"), f.get("is_family_dbscan_outlier"),
                f.get("is_family_markov_outlier"),
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

        # Attach health data to the outbound finding payload
        qualifying.append({
            **f,
            "health_score": health_score,
            "health_components": health_components,
        })

    # Track alert history regardless of qualifying count or scope setting.
    # Skip for org_scope — org findings are cross-site composites, not single-site events.
    if not org_scope:
        active_findings = {
            f["device_family"]: f
            for f in qualifying
            if f.get("device_family")
        }
        await alert_tracker.record_cycle(site_id, wlan, active_findings)

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
    # All TSHOOT calls across all findings are dispatched concurrently.
    if config["marvis_tshoot_enabled"] and MIST_ORG_ID and MIST_API_TOKEN:
        # Build a flat list of (finding_index, mac_entry) pairs so we can scatter/gather.
        tshoot_tasks: list[tuple[int, dict]] = []
        for i, finding in enumerate(qualifying):
            for mac_entry in finding.get("worst_health_macs", []):
                tshoot_tasks.append((i, mac_entry))

        if tshoot_tasks:
            results = await asyncio.gather(
                *[_run_client_tshoot(site_id, t[1]["mac"]) for t in tshoot_tasks]
            )
            # Group results back onto each finding.
            finding_tshoot: dict[int, list[dict]] = {i: [] for i in range(len(qualifying))}
            for (i, mac_entry), result in zip(tshoot_tasks, results):
                finding_tshoot[i].append({
                    "mac": mac_entry["mac"],
                    "tshoot_results": result.get("results", []),
                })
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

    payload = {
        "source": "sasquatch_client_anomaly",
        "site_id": site_id,
        "wlan": wlan,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "finding_count": len(qualifying),
        "findings": qualifying,
    }

    log.info(
        f"[{wlan}] Dispatching webhook: {len(qualifying)} finding(s) passed dual alert gate "
        f"(is_family_outlier + health_score < {threshold})\n"
        f"Payload: {json.dumps(payload, indent=2)}"
    )
    return await _post_with_retry(effective_url, payload)

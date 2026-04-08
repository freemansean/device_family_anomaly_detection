"""
webhook_dispatcher.py — Evaluate findings against dual alert gate and POST to webhook.

A finding triggers the webhook only when BOTH conditions are true:
  1. The device family is flagged as a family-level outlier by the centroid
     Isolation Forest (is_family_outlier = True). This means the entire device
     type is behaving differently from all other families at the site — not just
     one misconfigured device.
  2. The family's health score is below ANOMALY_HEALTH_SCORE_THRESHOLD. This
     confirms that the behavioral anomaly is accompanied by measurable failure
     degradation, not just an unusual-but-healthy traffic pattern.

Single-device anomalies (per-family IF or DBSCAN outliers for one MAC) produce
findings visible in the UI but never trigger the webhook.

Retry logic: 3 attempts with exponential backoff (1s, 2s, 4s).
Never raises — webhook failure does not kill the scheduler job.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import httpx

from . import alert_tracker
from .anomaly_detector import get_findings, get_org_findings
from .health_scorer import get_health

log = logging.getLogger(__name__)

WEBHOOK_URL = os.getenv("ANOMALY_WEBHOOK_URL", "")
WEBHOOK_SEVERITY_THRESHOLD = os.getenv("ANOMALY_WEBHOOK_SEVERITY_THRESHOLD", "significant")
HEALTH_SCORE_THRESHOLD = float(os.getenv("ANOMALY_HEALTH_SCORE_THRESHOLD", "0.75"))

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

_SEVERITY_RANK = {"minimal": 0, "moderate": 1, "significant": 2}


async def _fetch_marvis_tshoot(mac: str) -> list[dict]:
    """
    Call the Marvis TSHOOT API for a single client MAC.
    Returns the 'results' list from the response, or [] on any failure.
    Never raises — a TSHOOT failure must not block webhook delivery.
    """
    if not MIST_ORG_ID or not MIST_API_TOKEN:
        return []
    url = f"https://{MIST_CLOUD_HOST}/api/v1/orgs/{MIST_ORG_ID}/troubleshoot?mac={mac}"
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json().get("results", [])
    except Exception as exc:
        log.warning("Marvis TSHOOT fetch failed for %s: %s", mac, exc)
        return []


def _meets_severity(severity: str, threshold: str) -> bool:
    return _SEVERITY_RANK.get(severity, -1) >= _SEVERITY_RANK.get(threshold, 2)


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
    wlan: str = "__all__",
    org_scope: bool = False,
) -> bool:
    """
    Load findings and health scores from Redis, apply dual alert gate, POST to
    webhook if any findings qualify.

    Dual gate — a finding is webhook-eligible only when:
      - finding["is_family_outlier"] is True  (centroid IF flagged the whole family)
      - family health_score < HEALTH_SCORE_THRESHOLD (family is also measurably failing)

    wlan: WLAN scope to evaluate. Defaults to "__all__" (cross-WLAN findings).
      Pass a specific SSID to evaluate that WLAN's scoped findings independently.
    org_scope=True: read from org-wide findings/health keys instead of per-site keys.

    Returns True if webhook was sent (or no qualifying findings), False on delivery failure.
    """
    if not WEBHOOK_URL:
        log.debug("ANOMALY_WEBHOOK_URL not set — skipping webhook dispatch")
        return True

    findings = await (get_org_findings() if org_scope else get_findings(site_id, wlan))
    health = await get_health(site_id, wlan)

    qualifying = []
    for f in findings:
        family = f.get("device_family", "")
        severity = f.get("severity", "")

        # Gate 1: must be a family-level behavioral anomaly
        if not f.get("is_family_outlier", False):
            continue

        # Gate 2: family health score must be below threshold
        family_health = health.get(family, {})
        health_score = family_health.get("health_score", 1.0)
        if health_score >= HEALTH_SCORE_THRESHOLD:
            log.debug(
                f"[{wlan}] Skipping webhook for [{family}]: is_family_outlier=True but "
                f"health_score={health_score:.3f} >= threshold {HEALTH_SCORE_THRESHOLD}"
            )
            continue

        # Gate 3: severity threshold
        if not _meets_severity(severity, WEBHOOK_SEVERITY_THRESHOLD):
            continue

        # Attach health data to the outbound finding payload
        qualifying.append({
            **f,
            "health_score": health_score,
            "health_components": family_health.get("components", {}),
        })

    # Track alert history regardless of webhook configuration or qualifying count.
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
            f"(family_outlier + health < {HEALTH_SCORE_THRESHOLD}) — no webhook sent"
        )
        return True

    # Enrich each qualifying finding with Marvis TSHOOT results for its worst MACs.
    # All TSHOOT calls across all findings are dispatched concurrently.
    if MIST_ORG_ID and MIST_API_TOKEN:
        # Build a flat list of (finding_index, mac_entry) pairs so we can scatter/gather.
        tshoot_tasks: list[tuple[int, dict]] = []
        for i, finding in enumerate(qualifying):
            for mac_entry in finding.get("worst_health_macs", []):
                tshoot_tasks.append((i, mac_entry))

        if tshoot_tasks:
            results = await asyncio.gather(
                *[_fetch_marvis_tshoot(t[1]["mac"]) for t in tshoot_tasks]
            )
            # Group results back onto each finding.
            finding_tshoot: dict[int, list[dict]] = {i: [] for i in range(len(qualifying))}
            for (i, mac_entry), tshoot_results in zip(tshoot_tasks, results):
                finding_tshoot[i].append({
                    "mac": mac_entry["mac"],
                    "tshoot_results": tshoot_results,
                })
            for i, finding in enumerate(qualifying):
                finding["marvis_tshoot"] = finding_tshoot[i]
            log.info(
                "[%s] Marvis TSHOOT enrichment complete: %d MACs queried across %d finding(s)",
                wlan, len(tshoot_tasks), len(qualifying),
            )
    else:
        log.debug("[%s] Marvis TSHOOT skipped — MIST_ORG_ID or MIST_API_TOKEN not configured", wlan)

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
        f"(is_family_outlier + health_score < {HEALTH_SCORE_THRESHOLD})"
    )
    return await _post_with_retry(WEBHOOK_URL, payload)

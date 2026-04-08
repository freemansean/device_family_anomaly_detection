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

Client TSHOOT enrichment (TODO #21):
  When MIST_TSHOOT_ENABLED=true, each qualifying finding is enriched with results
  from the Mist site-level client troubleshoot API, targeting the worst-health MACs
  within the impacted family. The `tshoot` field on each finding is a list of per-MAC
  results: {mac, ap, status, results}. TSHOOT failures never block webhook delivery.
  Status values: "completed" | "error".
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import httpx

from . import alert_tracker
from .anomaly_detector import get_findings, get_org_findings
from .client_cache import get_client_cache
from .health_scorer import get_health

log = logging.getLogger(__name__)

WEBHOOK_URL = os.getenv("ANOMALY_WEBHOOK_URL", "")
HEALTH_SCORE_THRESHOLD = float(os.getenv("ANOMALY_HEALTH_SCORE_THRESHOLD", "0.75"))

MIST_CLOUD_HOST = os.getenv("MIST_CLOUD_HOST", "api.mist.com")
MIST_API_TOKEN = os.getenv("MIST_API_TOKEN", "")
MIST_ORG_ID = os.getenv("MIST_ORG_ID", "")

# Client TSHOOT enrichment — off by default until validated against live Mist API.
MIST_TSHOOT_ENABLED: bool = os.getenv("MIST_TSHOOT_ENABLED", "false").lower() == "true"

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


async def _run_client_tshoot(site_id: str, mac: str) -> dict:
    """
    Call the Mist site-level client TSHOOT API for a single MAC.

    GET /api/v1/sites/{site_id}/clients/troubleshoot?mac={mac}

    Mirrors the org-level Marvis endpoint pattern — synchronous GET, results
    returned directly in the response.

    Returns a dict with keys:
      status   — "completed" | "error"
      results  — raw Mist `results` list on success, [] otherwise
      error    — error message string (only on "error" status)

    Never raises — TSHOOT failures must not block webhook delivery.
    """
    headers = {"Authorization": f"Token {MIST_API_TOKEN}"}
    url = f"https://{MIST_CLOUD_HOST}/api/v1/sites/{site_id}/clients/troubleshoot?mac={mac}"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return {"status": "completed", "results": resp.json().get("results", [])}
    except httpx.HTTPStatusError as exc:
        log.warning(
            "Client TSHOOT HTTP error for %s at site %s: %s %s",
            mac, site_id, exc.response.status_code, exc.response.text[:200],
        )
        return {"status": "error", "error": str(exc), "results": []}
    except Exception as exc:
        log.warning("Client TSHOOT failed for %s at site %s: %s", mac, site_id, exc)
        return {"status": "error", "error": str(exc), "results": []}


async def _enrich_with_client_tshoot(
    qualifying: list[dict], site_id: str, wlan: str
) -> None:
    """
    Enrich each qualifying finding with site-level client TSHOOT results.

    Targets the worst_health_macs list (MACs with lowest health scores) within
    each impacted family. Dispatches all TSHOOT calls concurrently via
    asyncio.gather and attaches results as `tshoot` — a list of per-MAC dicts:
      {mac, ap, status, results, [error]}

    Modifies `qualifying` in place. Never raises.
    """
    if not MIST_API_TOKEN:
        log.debug("[%s] Client TSHOOT skipped — MIST_API_TOKEN not configured", wlan)
        return

    try:
        # Load client cache once for ap lookup.
        try:
            cache = await get_client_cache(site_id)
        except Exception:
            cache = {}

        # Build flat job list: (finding_idx, mac, ap)
        jobs: list[tuple[int, str, str]] = []
        for idx, finding in enumerate(qualifying):
            for mac_entry in finding.get("worst_health_macs", []):
                mac = mac_entry["mac"]
                mac_norm = mac.replace(":", "").lower()
                ap = (cache.get(mac_norm) or cache.get(mac) or {}).get("last_ap", "")
                jobs.append((idx, mac, ap))

        if not jobs:
            for finding in qualifying:
                finding["tshoot"] = []
            return

        async def _one(idx: int, mac: str, ap: str):
            result = await _run_client_tshoot(site_id, mac)
            return idx, mac, ap, result

        raw_results = await asyncio.gather(*[_one(*j) for j in jobs])

        # Group back onto findings.
        by_finding: dict[int, list[dict]] = {i: [] for i in range(len(qualifying))}
        for idx, mac, ap, result in raw_results:
            by_finding[idx].append({"mac": mac, "ap": ap, **result})

        for i, finding in enumerate(qualifying):
            finding["tshoot"] = by_finding[i]

        completed = sum(1 for _, _, _, r in raw_results if r.get("status") == "completed")
        log.info(
            "[%s] Client TSHOOT enrichment: %d MACs queried, %d completed",
            wlan, len(jobs), completed,
        )

    except Exception as exc:
        log.warning("[%s] Client TSHOOT enrichment error (non-blocking): %s", wlan, exc)
        for finding in qualifying:
            finding.setdefault("tshoot", [])


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

        # Gate 1: must carry at least one family-level anomaly label
        # (centroid IF/distance, DBSCAN family noise, or Markov Chain)
        is_any_family_anomaly = (
            f.get("is_family_outlier", False)
            or f.get("is_family_dbscan_outlier", False)
            or f.get("is_family_markov_outlier", False)
        )
        if not is_any_family_anomaly:
            continue

        # Gate 2: family health score must be below threshold
        family_health = health.get(family, {})
        health_score = family_health.get("health_score", 1.0)
        if health_score >= HEALTH_SCORE_THRESHOLD:
            log.debug(
                "[%s] Skipping webhook for [%s]: family anomaly label present but "
                "health_score=%.3f >= threshold %.3f (if=%s dbscan=%s markov=%s)",
                wlan, family, health_score, HEALTH_SCORE_THRESHOLD,
                f.get("is_family_outlier"), f.get("is_family_dbscan_outlier"),
                f.get("is_family_markov_outlier"),
            )
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

    # Site-level client TSHOOT enrichment (TODO #21).
    # Targets worst_health_macs — the MACs with the lowest health scores in each
    # impacted family. Only runs for per-site findings (not org-scope composites)
    # and only when MIST_TSHOOT_ENABLED=true.
    if MIST_TSHOOT_ENABLED and not org_scope:
        await _enrich_with_client_tshoot(qualifying, site_id, wlan)
    elif MIST_TSHOOT_ENABLED and org_scope:
        log.debug("[%s] Client TSHOOT skipped for org-scope findings", wlan)

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

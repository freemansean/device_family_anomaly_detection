"""
webhook_dispatcher.py — Evaluate findings against severity threshold and POST to webhook.

Only significant findings (configurable) trigger the webhook.
Retry logic: 3 attempts with exponential backoff (1s, 2s, 4s).
Never raises — webhook failure does not kill the scheduler job.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import httpx

from .anomaly_detector import get_findings

log = logging.getLogger(__name__)

WEBHOOK_URL = os.getenv("ANOMALY_WEBHOOK_URL", "")
WEBHOOK_SEVERITY_THRESHOLD = os.getenv("ANOMALY_WEBHOOK_SEVERITY_THRESHOLD", "significant")

_SEVERITY_RANK = {"minimal": 0, "moderate": 1, "significant": 2}


def _meets_threshold(severity: str, threshold: str) -> bool:
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


async def evaluate_and_dispatch(site_id: str) -> bool:
    """
    Load findings from Redis, filter by severity threshold, POST to webhook if any qualify.
    Returns True if webhook was sent (or no qualifying findings), False on delivery failure.
    """
    if not WEBHOOK_URL:
        log.debug("ANOMALY_WEBHOOK_URL not set — skipping webhook dispatch")
        return True

    findings = await get_findings(site_id)
    qualifying = [
        f for f in findings if _meets_threshold(f.get("severity", "INFO"), WEBHOOK_SEVERITY_THRESHOLD)
    ]

    if not qualifying:
        log.info(
            f"No findings at or above {WEBHOOK_SEVERITY_THRESHOLD} threshold — no webhook sent"
        )
        return True

    payload = {
        "source": "sasquatch_client_anomaly",
        "site_id": site_id,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "finding_count": len(qualifying),
        "findings": qualifying,
    }

    log.info(
        f"Dispatching webhook: {len(qualifying)} {WEBHOOK_SEVERITY_THRESHOLD}+ findings"
    )
    return await _post_with_retry(WEBHOOK_URL, payload)

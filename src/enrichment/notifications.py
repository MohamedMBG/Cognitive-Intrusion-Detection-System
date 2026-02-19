"""Webhook/Slack/email notifications for critical alerts (Phase 8)."""

import json
import logging
from typing import Dict

import httpx

from ..config import WEBHOOK_URLS, NOTIFY_MIN_SEVERITY

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


async def notify_alert(alert_data: Dict) -> None:
    """Send alert to all configured webhook URLs if severity meets threshold."""
    if not WEBHOOK_URLS:
        return

    severity = alert_data.get("severity", "low")
    if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(NOTIFY_MIN_SEVERITY, 2):
        return

    payload = {
        "text": (
            f"🚨 *CNDS Alert* [{severity.upper()}]\n"
            f"Source: {alert_data.get('src_ip', '?')} → {alert_data.get('dst_ip', '?')}\n"
            f"Score: {alert_data.get('ensemble_score', 0):.3f}\n"
            f"Type: {alert_data.get('attack_type', 'unknown')}\n"
            f"Rules: {', '.join(alert_data.get('triggered_rules', []))}"
        ),
        **alert_data,
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in WEBHOOK_URLS:
            try:
                resp = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code >= 400:
                    logger.warning("Webhook %s returned %d", url, resp.status_code)
            except Exception as e:
                logger.error("Webhook %s failed: %s", url, e)

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger()


def webhook_send(
    url: str,
    headers: Dict[str, str],
    matched_event: Dict[str, Any],
    rule_metadata: Dict[str, Any],
    correlated_events: Optional[List[Dict[str, Any]]] = None,
    threshold_info: Optional[Dict[str, Any]] = None,
) -> bool:
    """Send an alert notification as a JSON POST to a webhook endpoint.

    Args:
        url: The webhook URL to POST to.
        headers: Additional HTTP headers (e.g. Authorization).
        matched_event: The matched CloudTrail event.
        rule_metadata: The Sigma rule metadata that triggered the alert.
        correlated_events: Optional list of correlated events.
        threshold_info: Optional threshold information dict.

    Returns:
        True when the webhook accepted the request (2xx), False otherwise.
    """
    severity = rule_metadata.get("level", "unknown")

    payload: Dict[str, Any] = {
        "source": "TrailAlerts",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {
            "title": rule_metadata.get("title", "Unknown"),
            "id": rule_metadata.get("id"),
            "level": severity,
            "description": rule_metadata.get("description"),
            "author": rule_metadata.get("author"),
            "references": rule_metadata.get("references", []),
        },
        "event": matched_event,
    }

    if correlated_events:
        payload["correlatedEvents"] = [
            {
                "ruleTitle": e.get("sigmaRuleTitle"),
                "timestamp": e.get("timestamp"),
                "actor": e.get("actor"),
                "target": e.get("target"),
            }
            for e in correlated_events
        ]

    if threshold_info:
        payload["thresholdInfo"] = {
            "eventCount": threshold_info.get("eventCount", threshold_info.get("event_count", 0)),
            "thresholdCount": threshold_info.get("thresholdCount", threshold_info.get("threshold_count", 0)),
            "windowMinutes": threshold_info.get("windowMinutes", threshold_info.get("window_minutes", 0)),
            "actor": threshold_info.get("actor"),
            "ruleTitle": threshold_info.get("ruleTitle", threshold_info.get("rule_title")),
        }

    data = json.dumps(payload, default=str).encode("utf-8")

    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})

    req = Request(url, data=data, headers=request_headers, method="POST")

    try:
        with urlopen(req, timeout=10) as resp:
            logger.info(f"Webhook notification sent to {url} — HTTP {resp.status}")
            return True
    except HTTPError as exc:
        logger.error(f"Webhook request failed: HTTP {exc.code} — {exc.reason}")
        return False
    except URLError as exc:
        logger.error(f"Webhook connection error: {exc.reason}")
        return False
    except Exception as exc:
        logger.error(f"Unexpected webhook error: {exc}")
        return False

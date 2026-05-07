import json
import ipaddress
import logging
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

logger = logging.getLogger()

HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def is_safe_webhook_url(url: str) -> bool:
    parsed = urlparse(str(url or ""))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return False

    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    for address in addresses:
        host = address[4][0]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        if not ip.is_global:
            return False

    return bool(addresses)


def safe_webhook_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    safe_headers = {}
    for name, value in (headers or {}).items():
        header_name = str(name)
        header_value = str(value)
        if not HEADER_NAME_PATTERN.fullmatch(header_name):
            logger.warning("Skipping webhook header with invalid name")
            continue
        if "\r" in header_value or "\n" in header_value:
            logger.warning("Skipping webhook header with invalid value")
            continue
        safe_headers[header_name] = header_value
    return safe_headers


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
    if not is_safe_webhook_url(url):
        logger.error("Blocked unsafe webhook URL")
        return False

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
    request_headers.update(safe_webhook_headers(headers))

    req = Request(url, data=data, headers=request_headers, method="POST")

    try:
        with urlopen(req, timeout=10) as resp:
            logger.info(f"Webhook notification sent — HTTP {resp.status}")
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

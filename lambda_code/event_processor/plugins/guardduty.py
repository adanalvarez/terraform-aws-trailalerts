"""
GuardDuty plugin for the TrailAlerts Event Processor.
This plugin formats normalized GuardDuty findings produced by the GuardDuty ingester.
"""
import html
import logging
from typing import Any, Dict, List

from plugins.base import EventSourcePlugin

logger = logging.getLogger()


def _escape(value: Any) -> str:
    return html.escape(str(value if value not in (None, "") else "unknown"))


def _detail_row(label: str, value: Any, value_class: str = "value") -> str:
    return f"""
        <div class='detail-row'>
            <div class='detail-label'>{html.escape(label)}</div>
            <div class='{value_class}'>{_escape(value)}</div>
        </div>
    """


def _nested(obj: Any, *path: str) -> Any:
    current = obj
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def _first_value(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _finding(event: Dict[str, Any]) -> Dict[str, Any]:
    finding = event.get("guardDutyFinding") or {}
    return finding if isinstance(finding, dict) else {}


def _remote_ips(event: Dict[str, Any]) -> List[str]:
    values = event.get("remoteIpAddresses") or []
    if isinstance(values, str):
        values = [values]
    if event.get("sourceIPAddress") and event.get("sourceIPAddress") != "unknown":
        values = [event["sourceIPAddress"], *values]
    deduped: List[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(str(value))
    return deduped


class GuardDutyPlugin(EventSourcePlugin):
    """Plugin for processing normalized GuardDuty finding events."""

    def get_plugin_name(self) -> str:
        return "guardduty"

    def get_event_type(self) -> str:
        return "GuardDuty"

    def can_process_event(self, event: Dict[str, Any]) -> bool:
        return event.get("sigmaEventSource") == "GuardDuty"

    def extract_actor(self, event: Dict[str, Any]) -> str:
        finding = _finding(event)
        resource = finding.get("resource") or {}
        service = finding.get("service") or {}
        process = _nested(service, "runtimeDetails", "process") or {}

        actor = _first_value(
            event.get("actor"),
            _nested(resource, "accessKeyDetails", "userName"),
            _nested(resource, "accessKeyDetails", "principalId"),
            _nested(resource, "eksClusterDetails", "kubernetesDetails", "kubernetesUserDetails", "username"),
            _nested(resource, "kubernetesDetails", "kubernetesUserDetails", "username"),
            _nested(resource, "rdsDbUserDetails", "user"),
            process.get("user"),
            process.get("name"),
            _nested(resource, "lambdaDetails", "functionName"),
            _nested(resource, "containerDetails", "name"),
            _nested(resource, "instanceDetails", "iamInstanceProfile", "arn"),
        )
        if actor:
            return str(actor)

        remote_ips = _remote_ips(event)
        return remote_ips[0] if remote_ips else "unknown"

    def _extract_process_summary(self, event: Dict[str, Any]) -> str:
        process = _nested(_finding(event), "service", "runtimeDetails", "process") or {}
        if not process:
            return "unknown"
        parts = [process.get("name"), process.get("cmdLine"), process.get("executablePath")]
        return " | ".join(str(part) for part in parts if part) or "unknown"

    def _threat_names(self, event: Dict[str, Any]) -> str:
        evidence = _nested(_finding(event), "service", "evidence") or {}
        threat_details = evidence.get("threatIntelligenceDetails") or []
        names: List[str] = []
        for detail in threat_details:
            if detail.get("threatListName"):
                names.append(str(detail["threatListName"]))
            for threat_name in detail.get("threatNames") or []:
                names.append(str(threat_name))
        return ", ".join(dict.fromkeys(names)) if names else "unknown"

    def generate_event_section(self, event: Dict[str, Any]) -> str:
        finding = _finding(event)
        service = finding.get("service") or {}
        resource = finding.get("resource") or {}
        remote_ips = ", ".join(_remote_ips(event)) or "unknown"

        rows = [
            _detail_row("Finding type", event.get("guardDutyFindingType") or event.get("eventName"), "value value-mono"),
            _detail_row("Finding ID", event.get("guardDutyFindingId"), "value value-mono"),
            _detail_row("GuardDuty severity", event.get("guardDutySeverity"), "value value-strong"),
            _detail_row("Action", event.get("guardDutyActionType"), "value value-mono"),
            _detail_row("Resource type", event.get("guardDutyResourceType") or resource.get("resourceType"), "value value-mono"),
            _detail_row("Target", event.get("target"), "value value-mono"),
            _detail_row("Actor", self.extract_actor(event), "value value-mono"),
            _detail_row("Remote IPs", remote_ips, "value value-mono"),
            _detail_row("First seen", event.get("guardDutyFirstSeen") or service.get("eventFirstSeen"), "value value-mono"),
            _detail_row("Last seen", event.get("guardDutyLastSeen") or service.get("eventLastSeen"), "value value-mono"),
            _detail_row("Finding count", event.get("guardDutyCount") or service.get("count"), "value value-strong"),
            _detail_row("Process", self._extract_process_summary(event), "value value-mono"),
            _detail_row("Threat intel", self._threat_names(event)),
        ]

        return f"""
        <div class='section'>
            <div class='section-title'>GuardDuty Finding Evidence</div>
            <div class='section-body'>
                {''.join(rows)}
            </div>
        </div>
        """

    def get_event_details(self, event: Dict[str, Any]) -> Dict[str, Any]:
        finding = _finding(event)
        return {
            "eventType": "GuardDuty",
            "actor": self.extract_actor(event),
            "sourceIPAddress": event.get("sourceIPAddress", "unknown"),
            "eventName": event.get("eventName", "unknown"),
            "target": event.get("target", "unknown"),
            "accountId": event.get("recipientAccountId", finding.get("accountId", "unknown")),
            "region": event.get("awsRegion", finding.get("region", "unknown")),
            "eventTime": event.get("eventTime", finding.get("updatedAt", "unknown")),
            "eventSource": event.get("eventSource", "guardduty.amazonaws.com"),
            "resources": [finding.get("resource", {})] if finding.get("resource") else [],
            "userAgent": "guardduty",
            "requestParameters": {},
            "responseElements": {},
            "errorCode": "unknown",
            "errorMessage": "unknown",
            "guardDutyFindingId": event.get("guardDutyFindingId"),
            "guardDutySeverity": event.get("guardDutySeverity"),
            "guardDutyActionType": event.get("guardDutyActionType"),
        }
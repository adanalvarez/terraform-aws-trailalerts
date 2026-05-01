import gzip
import json
import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote_plus

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client("s3")
sqs = boto3.client("sqs")

SQS_QUEUE_URL = os.environ["SQS_QUEUE_URL"]
MIN_SEVERITY = float(os.environ.get("GUARDDUTY_MIN_SEVERITY", "0") or 0)
INCLUDE_ARCHIVED = os.environ.get("GUARDDUTY_INCLUDE_ARCHIVED", "false").lower() == "true"
FINDINGS_SUFFIX = os.environ.get("GUARD_DUTY_FINDINGS_SUFFIX", ".jsonl.gz") or ".jsonl.gz"

SQS_BATCH_SIZE = 10
MAX_SQS_RETRIES = 3
MAX_SQS_BODY_BYTES = 240_000
MAX_RAW_FINDING_BYTES = int(os.environ.get("GUARDDUTY_MAX_RAW_FINDING_BYTES", "120000") or 120000)

_sqs_msg_counter = 0


def _nested(obj: Any, *path: str) -> Any:
    current = obj
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def _first_value(*values: Any) -> Optional[Any]:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _json_size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), default=str).encode("utf-8"))


def fetch_s3_object(bucket: str, key: str) -> str:
    body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
    try:
        return gzip.decompress(body).decode("utf-8")
    except OSError:
        return body.decode("utf-8")


def parse_guardduty_findings(content: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    stripped = content.strip()
    if not stripped:
        return findings

    if stripped.startswith("["):
        parsed = json.loads(stripped)
        return [item for item in parsed if isinstance(item, dict)]

    if stripped.startswith("{") and "\n" not in stripped:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
            return [item for item in parsed["findings"] if isinstance(item, dict)]
        return [parsed] if isinstance(parsed, dict) else []

    for line_number, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.error("Invalid GuardDuty JSONL record at line %s: %s", line_number, exc)
            raise
        if isinstance(parsed, dict):
            findings.append(parsed)
        else:
            logger.warning("Skipping non-object GuardDuty JSONL record at line %s", line_number)

    return findings


def guardduty_severity_to_level(severity: Any) -> str:
    try:
        numeric = float(severity)
    except (TypeError, ValueError):
        return "info"

    if numeric >= 7:
        return "high"
    if numeric >= 4:
        return "medium"
    if numeric > 0:
        return "low"
    return "info"


def _remote_ip_values(finding: Dict[str, Any]) -> List[str]:
    action = _nested(finding, "service", "action") or {}
    values = [
        _nested(action, "awsApiCallAction", "remoteIpDetails", "ipAddressV4"),
        _nested(action, "kubernetesApiCallAction", "remoteIpDetails", "ipAddressV4"),
        _nested(action, "networkConnectionAction", "remoteIpDetails", "ipAddressV4"),
        _nested(action, "rdsLoginAttemptAction", "remoteIpDetails", "ipAddressV4"),
    ]

    for probe_detail in _nested(action, "portProbeAction", "portProbeDetails") or []:
        values.append(_nested(probe_detail, "remoteIpDetails", "ipAddressV4"))

    for source_ip in _nested(action, "kubernetesApiCallAction", "sourceIPs") or []:
        values.append(source_ip)

    deduped: List[str] = []
    for value in values:
        if value and value not in deduped:
            deduped.append(str(value))
    return deduped


def extract_actor(finding: Dict[str, Any]) -> str:
    resource = finding.get("resource") or {}
    service = finding.get("service") or {}
    process = _nested(service, "runtimeDetails", "process") or {}

    actor = _first_value(
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

    remote_ips = _remote_ip_values(finding)
    return remote_ips[0] if remote_ips else "unknown"


def extract_target(finding: Dict[str, Any]) -> str:
    resource = finding.get("resource") or {}
    target = _first_value(
        _nested(resource, "instanceDetails", "instanceId"),
        _nested(resource, "lambdaDetails", "functionArn"),
        _nested(resource, "lambdaDetails", "functionName"),
        _nested(resource, "eksClusterDetails", "arn"),
        _nested(resource, "eksClusterDetails", "name"),
        _nested(resource, "ecsClusterDetails", "taskDetails", "arn"),
        _nested(resource, "ecsClusterDetails", "arn"),
        _nested(resource, "ecsClusterDetails", "name"),
        _nested(resource, "kubernetesDetails", "kubernetesWorkloadDetails", "name"),
        _nested(resource, "containerDetails", "id"),
        _nested(resource, "containerDetails", "name"),
        _nested(resource, "accessKeyDetails", "accessKeyId"),
        _nested(resource, "rdsLimitlessDbDetails", "dbShardGroupArn"),
        _nested(resource, "rdsLimitlessDbDetails", "dbClusterIdentifier"),
        _nested(resource, "recoveryPointDetails", "recoveryPointArn"),
    )
    return str(target) if target else str(resource.get("resourceType") or "unknown")


def _action_name(finding: Dict[str, Any]) -> str:
    service = finding.get("service") or {}
    return str(_first_value(_nested(service, "action", "actionType"), service.get("featureName"), service.get("serviceName"), "guardduty"))


def _raw_finding_for_event(finding: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    if _json_size(finding) <= MAX_RAW_FINDING_BYTES:
        return finding, False

    compact = {
        "id": finding.get("id"),
        "arn": finding.get("arn"),
        "type": finding.get("type"),
        "title": finding.get("title"),
        "description": finding.get("description"),
        "severity": finding.get("severity"),
        "resource": finding.get("resource"),
        "service": finding.get("service"),
    }
    return compact, True


def normalize_finding(finding: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    service = finding.get("service") or {}
    event_time = _first_value(service.get("eventLastSeen"), finding.get("updatedAt"), finding.get("createdAt"))
    remote_ips = _remote_ip_values(finding)
    raw_finding, raw_truncated = _raw_finding_for_event(finding)
    finding_type = str(finding.get("type") or "UnknownGuardDutyFinding")
    severity_level = guardduty_severity_to_level(finding.get("severity"))
    action_name = _action_name(finding)

    matched_event = {
        "sigmaEventSource": "GuardDuty",
        "eventSource": "guardduty.amazonaws.com",
        "eventName": finding_type,
        "eventTime": event_time,
        "awsRegion": finding.get("region", "unknown"),
        "recipientAccountId": finding.get("accountId", "unknown"),
        "sourceIPAddress": remote_ips[0] if remote_ips else "unknown",
        "remoteIpAddresses": remote_ips,
        "actor": extract_actor(finding),
        "target": extract_target(finding),
        "guardDutyFindingId": finding.get("id"),
        "guardDutyFindingArn": finding.get("arn"),
        "guardDutyFindingType": finding_type,
        "guardDutySeverity": finding.get("severity"),
        "guardDutyActionType": action_name,
        "guardDutyResourceType": _nested(finding, "resource", "resourceType"),
        "guardDutyFeatureName": service.get("featureName"),
        "guardDutyDetectorId": service.get("detectorId"),
        "guardDutyCount": service.get("count"),
        "guardDutyFirstSeen": service.get("eventFirstSeen"),
        "guardDutyLastSeen": service.get("eventLastSeen"),
        "guardDutyArchived": service.get("archived", False),
        "guardDutyDedupeKey": f"{finding.get('id', 'unknown')}#{event_time or 'unknown'}",
        "guardDutyFindingTruncated": raw_truncated,
        "guardDutyFinding": raw_finding,
    }

    rule_metadata = {
        "id": f"guardduty:{finding_type}",
        "title": finding.get("title") or finding_type,
        "level": severity_level,
        "description": finding.get("description", ""),
        "logsource": {"product": "aws", "service": "guardduty"},
        "status": "stable",
    }

    return matched_event, rule_metadata


def _build_sqs_message(finding: Dict[str, Any]) -> Dict[str, str]:
    global _sqs_msg_counter
    _sqs_msg_counter += 1
    matched_event, rule_metadata = normalize_finding(finding)

    message_body = {
        "sigma_rule_id": rule_metadata["id"],
        "sigma_rule_title": rule_metadata["title"],
        "matched_event": matched_event,
        "sigma_rule_data": rule_metadata,
    }

    encoded = json.dumps(message_body, default=str)
    if len(encoded.encode("utf-8")) > MAX_SQS_BODY_BYTES:
        matched_event["guardDutyFinding"] = {
            "id": finding.get("id"),
            "arn": finding.get("arn"),
            "type": finding.get("type"),
            "title": finding.get("title"),
            "description": finding.get("description"),
            "severity": finding.get("severity"),
        }
        matched_event["guardDutyFindingTruncated"] = True
        matched_event["guardDutyFindingDroppedForSqsSize"] = True
        encoded = json.dumps(message_body, default=str)

    return {
        "Id": str(_sqs_msg_counter % 100000000),
        "MessageBody": encoded,
    }


def _flush_sqs_batch(messages: List[Dict[str, str]]) -> None:
    if not messages:
        return

    to_send = list(messages)
    for attempt in range(MAX_SQS_RETRIES):
        response = sqs.send_message_batch(QueueUrl=SQS_QUEUE_URL, Entries=to_send)
        failed = response.get("Failed", [])
        if not failed:
            logger.info("GuardDuty SQS batch: %s messages sent", len(messages))
            return

        failed_ids = {item["Id"] for item in failed}
        to_send = [message for message in to_send if message["Id"] in failed_ids]
        logger.warning("GuardDuty SQS batch: %s messages failed on attempt %s", len(failed_ids), attempt + 1)

    raise RuntimeError(f"GuardDuty SQS batch send failed after {MAX_SQS_RETRIES} retries")


def process_guardduty_findings(content: str) -> Dict[str, Any]:
    findings = parse_guardduty_findings(content)
    sqs_batch: List[Dict[str, str]] = []
    seen_keys = set()
    metrics: Dict[str, Any] = {
        "findings_count": len(findings),
        "findings_sent": 0,
        "findings_skipped_archived": 0,
        "findings_skipped_severity": 0,
        "findings_skipped_duplicate": 0,
        "sqs_batches": 0,
        "severity_counts": {},
    }

    def flush_batch() -> None:
        nonlocal sqs_batch
        if not sqs_batch:
            return
        _flush_sqs_batch(sqs_batch)
        metrics["sqs_batches"] += 1
        sqs_batch = []

    for finding in findings:
        try:
            severity = float(finding.get("severity") or 0)
        except (TypeError, ValueError):
            severity = 0
        severity_key = str(finding.get("severity", "unknown"))
        metrics["severity_counts"][severity_key] = metrics["severity_counts"].get(severity_key, 0) + 1

        if finding.get("id") in seen_keys:
            metrics["findings_skipped_duplicate"] += 1
            continue
        seen_keys.add(finding.get("id"))

        if _nested(finding, "service", "archived") and not INCLUDE_ARCHIVED:
            metrics["findings_skipped_archived"] += 1
            continue

        if severity < MIN_SEVERITY:
            metrics["findings_skipped_severity"] += 1
            continue

        sqs_batch.append(_build_sqs_message(finding))
        metrics["findings_sent"] += 1
        if len(sqs_batch) >= SQS_BATCH_SIZE:
            flush_batch()

    flush_batch()
    return metrics


def _log_processing_summary(summary: Dict[str, Any]) -> None:
    logger.info(json.dumps({"message": "guardduty_ingester_summary", **summary}, sort_keys=True))


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, str]:
    s3_errors = 0

    for record in event.get("Records", []):
        try:
            start_time = time.perf_counter()
            bucket = record["s3"]["bucket"]["name"]
            key = unquote_plus(record["s3"]["object"]["key"])

            allowed_suffixes = {FINDINGS_SUFFIX, ".jsonl"}
            if not any(key.endswith(suffix) for suffix in allowed_suffixes if suffix):
                logger.info("Skipping non-GuardDuty JSONL file: %s", key)
                continue

            logger.info("Processing GuardDuty export object: bucket=%s key=%s", bucket, key)
            content = fetch_s3_object(bucket, key)
            if not content:
                logger.warning("Empty GuardDuty export object: %s", key)
                continue

            summary = process_guardduty_findings(content)
            summary.update({
                "bucket": bucket,
                "key": key,
                "duration_ms": int((time.perf_counter() - start_time) * 1000),
            })
            _log_processing_summary(summary)
        except KeyError as exc:
            s3_errors += 1
            logger.error("Missing key in GuardDuty S3 event: %s", exc)
        except Exception as exc:
            s3_errors += 1
            logger.exception("Error processing GuardDuty S3 event: %s", exc)

    if s3_errors:
        raise RuntimeError(f"Failed to process {s3_errors} GuardDuty S3 event record(s)")

    return {"statusCode": "200", "body": "GuardDuty findings processed successfully"}
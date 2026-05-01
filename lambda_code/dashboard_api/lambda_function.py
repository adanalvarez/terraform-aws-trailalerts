"""
TrailAlerts Dashboard API Lambda

Provides a REST API for managing Sigma rules (CRUD on S3),
postprocessing rules (correlation/threshold), exceptions, and
querying alert history (DynamoDB). All routes require Cognito JWT
authentication enforced at the API Gateway level.
"""

import json
import os
import re
import logging
import yaml
import boto3
from urllib.parse import unquote_plus
from botocore.exceptions import ClientError
from decimal import Decimal
from datetime import datetime, timedelta, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")

RULES_BUCKET = os.environ["RULES_BUCKET"]
RULES_PREFIX = "sigma_rules/"
DISABLED_RULES_PREFIX = "disabled_sigma_rules/"
RULE_PREFIXES = (RULES_PREFIX, DISABLED_RULES_PREFIX)
POSTPROCESSING_PREFIX = "postprocessing_rules/"
EXCEPTIONS_KEY = "exceptions.json"
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "")

# Lazy-init DynamoDB table reference
_table = None


def _get_table():
    global _table
    if _table is None and DYNAMODB_TABLE_NAME:
        _table = dynamodb.Table(DYNAMODB_TABLE_NAME)
    return _table


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class DecimalEncoder(json.JSONEncoder):
    """Handle DynamoDB Decimal types."""
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
        "body": json.dumps(body, cls=DecimalEncoder),
    }


def _normalize_rule_key(key: str) -> str:
    """Return the dashboard-facing rule filename without any S3 prefix."""
    key = key.strip("/")
    for prefix in RULE_PREFIXES:
        if key.startswith(prefix):
            key = key.removeprefix(prefix)
            break
    if not key.endswith((".yaml", ".yml")):
        key += ".yaml"
    return key


def _safe_key(key: str, enabled: bool = True) -> str:
    """Ensure the key is within the active or disabled Sigma rule prefix."""
    prefix = RULES_PREFIX if enabled else DISABLED_RULES_PREFIX
    return f"{prefix}{_normalize_rule_key(key)}"


def _display_rule_key(s3_key: str) -> str:
    for prefix in RULE_PREFIXES:
        if s3_key.startswith(prefix):
            return s3_key.removeprefix(prefix)
    return s3_key


def _enabled_param(value, default: bool | None = True) -> bool | None:
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in ("1", "true", "yes", "on", "enabled"):
        return True
    if normalized in ("0", "false", "no", "off", "disabled"):
        return False
    return default


def _find_rule_location(key: str, preferred_enabled: bool | None = None) -> tuple[str | None, bool | None, dict | None]:
    """Find an active or disabled rule object, preferring the requested state when provided."""
    if preferred_enabled is None:
        candidates = [(True, _safe_key(key, True)), (False, _safe_key(key, False))]
    else:
        candidates = [
            (preferred_enabled, _safe_key(key, preferred_enabled)),
            (not preferred_enabled, _safe_key(key, not preferred_enabled)),
        ]

    for enabled, s3_key in candidates:
        try:
            obj = s3.head_object(Bucket=RULES_BUCKET, Key=s3_key)
            return s3_key, enabled, obj
        except ClientError as exc:
            if exc.response["Error"].get("Code") in ("404", "NoSuchKey", "NotFound"):
                continue
            raise

    return None, None, None


def _event_body_text(event: dict) -> str:
    body = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        import base64
        body = base64.b64decode(body).decode("utf-8")
    return body


def _yaml_error_detail(exc: yaml.YAMLError) -> dict:
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    detail = {"message": f"Invalid YAML: {str(exc)}"}
    if mark is not None:
        detail["line"] = mark.line + 1
        detail["column"] = mark.column + 1
    return detail


def _field_line(content: str, field: str) -> int | None:
    pattern = re.compile(rf"^\s*{re.escape(field)}\s*:", re.MULTILINE)
    match = pattern.search(content)
    if not match:
        return None
    return content[:match.start()].count("\n") + 1


def _condition_references(condition: str, block_names: set[str]) -> set[str]:
    tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_-]*\*?\b", condition or ""))
    reserved = {"and", "or", "not", "of", "them", "all", "near", "by"}
    refs = set()
    for token in tokens:
        if token.lower() in reserved or token.isdigit():
            continue
        if token.endswith("*"):
            prefix = token[:-1]
            if any(name.startswith(prefix) for name in block_names):
                continue
        refs.add(token)
    return refs


def _analyze_sigma_rule(content: str) -> dict:
    errors = []
    warnings = []
    hints = []

    if not content or not content.strip():
        return {
            "valid": False,
            "errors": [{"message": "Rule content is empty", "line": 1, "column": 1}],
            "warnings": [],
            "hints": ["Start with title, logsource, detection, and detection.condition."],
            "metadata": {},
            "blocks": [],
            "rule": None,
        }

    try:
        rule = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return {
            "valid": False,
            "errors": [_yaml_error_detail(e)],
            "warnings": [],
            "hints": ["Fix the YAML syntax before Sigma fields can be checked."],
            "metadata": {},
            "blocks": [],
            "rule": None,
        }

    if not isinstance(rule, dict):
        return {
            "valid": False,
            "errors": [{"message": "Rule must be a YAML mapping", "line": 1, "column": 1}],
            "warnings": [],
            "hints": ["A Sigma rule should be a top-level YAML object with named fields."],
            "metadata": {},
            "blocks": [],
            "rule": None,
        }

    required_fields = ["title", "logsource", "detection"]
    for field in required_fields:
        if field not in rule:
            errors.append({"message": f"Missing required Sigma field: {field}", "field": field})

    title = str(rule.get("title") or "").strip()
    if "title" in rule and not title:
        errors.append({"message": "Title must not be empty", "field": "title", "line": _field_line(content, "title")})

    level = str(rule.get("level") or "").strip().lower()
    if level and level not in _SEVERITY_RANK:
        warnings.append({"message": "Level should be one of critical, high, medium, low, or info", "field": "level", "line": _field_line(content, "level")})

    status = str(rule.get("status") or "").strip().lower()
    if status and status not in {"stable", "test", "experimental", "deprecated", "unsupported"}:
        warnings.append({"message": "Status is not a standard Sigma status value", "field": "status", "line": _field_line(content, "status")})

    logsource = rule.get("logsource")
    if "logsource" in rule and not isinstance(logsource, dict):
        errors.append({"message": "Logsource must be a mapping", "field": "logsource", "line": _field_line(content, "logsource")})
    elif isinstance(logsource, dict):
        if not logsource.get("product"):
            warnings.append({"message": "Logsource should include product: aws", "field": "logsource", "line": _field_line(content, "logsource")})
        if not logsource.get("service"):
            hints.append("Add logsource.service: cloudtrail when the rule is CloudTrail-specific.")

    detection = rule.get("detection", {})
    detection_line = _field_line(content, "detection")
    block_names = set()
    if "detection" in rule and not isinstance(detection, dict):
        errors.append({"message": "Detection must be a mapping", "field": "detection", "line": detection_line})
    elif isinstance(detection, dict):
        block_names = {name for name in detection.keys() if name != "condition"}
        if "condition" not in detection:
            errors.append({"message": "Detection block must contain a condition field", "field": "detection.condition", "line": detection_line})
        elif not str(detection.get("condition") or "").strip():
            errors.append({"message": "Detection condition must not be empty", "field": "detection.condition", "line": detection_line})
        if not block_names:
            errors.append({"message": "Detection must include at least one selection block", "field": "detection", "line": detection_line})
        for block_name in sorted(block_names):
            if not isinstance(detection.get(block_name), dict):
                errors.append({"message": f"Detection block '{block_name}' must be a mapping", "field": f"detection.{block_name}", "line": detection_line})
        unknown_refs = _condition_references(str(detection.get("condition") or ""), block_names)
        for ref in sorted(unknown_refs - block_names):
            errors.append({"message": f"Condition references unknown detection block: {ref}", "field": "detection.condition", "line": detection_line})

    if "id" not in rule:
        hints.append("Add a stable id so alerts can be traced back to this rule over time.")
    if "description" not in rule:
        hints.append("Add description to explain the detection intent to operators.")

    metadata = {
        "title": title or "Untitled rule",
        "id": rule.get("id", ""),
        "status": rule.get("status", ""),
        "level": level or "info",
        "logsource": logsource if isinstance(logsource, dict) else {},
        "condition": detection.get("condition", "") if isinstance(detection, dict) else "",
    }

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "hints": hints,
        "metadata": metadata,
        "blocks": sorted(block_names),
        "rule": rule,
    }


def _validate_sigma_rule(content: str) -> tuple:
    """
    Validate that the content is valid YAML and has basic Sigma rule structure.
    Returns (is_valid, parsed_rule_or_error_message).
    """
    analysis = _analyze_sigma_rule(content)
    if not analysis["valid"]:
        return False, "; ".join(error["message"] for error in analysis["errors"])

    return True, analysis["rule"]


def _get_nested_value(record: dict, field: str):
    value = record
    for part in field.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list):
            try:
                value = value[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return value


def _matches_value(actual, expected) -> bool:
    if isinstance(expected, list):
        return actual in expected
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(_matches_value(actual.get(key), value) for key, value in expected.items())
    return actual == expected


def _evaluate_sigma_block(record: dict, criteria: dict) -> tuple[bool, list[dict]]:
    checks = []
    matched = True
    for field, expected in criteria.items():
        operator = "equals"
        base_field = field
        if "|" in field:
            base_field, operator = field.split("|", 1)
        actual = _get_nested_value(record, base_field.strip())

        if operator == "contains":
            result = actual is not None and str(expected) in str(actual)
        elif operator == "startswith":
            result = isinstance(actual, str) and str(actual).startswith(str(expected))
        elif operator == "endswith":
            result = isinstance(actual, str) and str(actual).endswith(str(expected))
        elif operator == "re":
            try:
                result = actual is not None and re.search(str(expected), str(actual)) is not None
            except re.error:
                result = False
        else:
            result = _matches_value(actual, expected)

        checks.append({"field": base_field.strip(), "operator": operator, "matched": result, "actual": actual})
        if not result:
            matched = False

    return matched, checks


def _evaluate_condition(condition: str, block_results: dict[str, bool]) -> bool:
    condition = (condition or "").strip()
    if condition in block_results:
        return block_results[condition]

    one_of = re.fullmatch(r"1\s+of\s+([A-Za-z_][A-Za-z0-9_-]*)\*", condition)
    if one_of:
        prefix = one_of.group(1)
        return any(value for name, value in block_results.items() if name.startswith(prefix))

    all_of = re.fullmatch(r"all\s+of\s+([A-Za-z_][A-Za-z0-9_-]*)\*", condition)
    if all_of:
        prefix = all_of.group(1)
        matches = [value for name, value in block_results.items() if name.startswith(prefix)]
        return bool(matches) and all(matches)

    expression = condition
    for name in sorted(block_results.keys(), key=len, reverse=True):
        expression = re.sub(rf"\b{re.escape(name)}\b", str(bool(block_results[name])), expression)
    if re.fullmatch(r"[\sTrueFalsandornt()]+", expression):
        return bool(eval(expression, {"__builtins__": {}}, {}))
    return False


def _test_sigma_rule(rule: dict, sample_event: dict) -> dict:
    detection = rule.get("detection", {})
    condition = str(detection.get("condition", "selection"))
    evaluated = []
    block_results = {}
    for block_name, criteria in detection.items():
        if block_name == "condition":
            continue
        matched, checks = _evaluate_sigma_block(sample_event, criteria)
        block_results[block_name] = matched
        evaluated.append({"block": block_name, "matched": matched, "checks": checks})

    return {
        "matched": _evaluate_condition(condition, block_results),
        "condition": condition,
        "evaluatedBlocks": evaluated,
    }


_ALERT_SUMMARY_PROJECTION = (
    "pk, sk, #ts, actor, target, accountId, severity, sourceIp, "
    "userAgent, sigmaRuleId, sigmaRuleTitle, eventName, sourceType, eventType, awsRegion"
)

_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _truthy_param(value) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _parse_alert_timestamp(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def _query_alert_stats_window(table, start: datetime, end: datetime) -> list[dict]:
    query_params = {
        "IndexName": "recentAlertsIndex",
        "KeyConditionExpression": "pk = :pk AND #ts BETWEEN :start AND :end",
        "ExpressionAttributeNames": {"#ts": "timestamp"},
        "ExpressionAttributeValues": {
            ":pk": "EVENT",
            ":start": start.isoformat(),
            ":end": end.isoformat(),
        },
        "ProjectionExpression": "#ts, severity, sigmaRuleTitle, sourceType",
        "ScanIndexForward": False,
    }

    items = []
    while True:
        response = table.query(**query_params)
        items.extend(response.get("Items", []))

        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break
        query_params["ExclusiveStartKey"] = last_evaluated_key

    return items


def _aggregate_alert_stats(items: list[dict]) -> dict:
    by_severity = {}
    by_source = {}
    by_rule = {}
    for item in items:
        sev = str(item.get("severity", "unknown") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

        source = str(item.get("sourceType", "unknown") or "unknown").lower()
        by_source[source] = by_source.get(source, 0) + 1

        rule = item.get("sigmaRuleTitle", "unknown") or "unknown"
        rule_stats = by_rule.setdefault(rule, {"count": 0, "severity": sev})
        rule_stats["count"] += 1
        current_rank = _SEVERITY_RANK.get(rule_stats.get("severity", ""), -1)
        candidate_rank = _SEVERITY_RANK.get(sev, -1)
        if candidate_rank > current_rank:
            rule_stats["severity"] = sev

    top_rules = sorted(by_rule.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    return {
        "totalAlerts": len(items),
        "bySeverity": by_severity,
        "bySource": by_source,
        "topRules": [{"rule": rule, "count": data["count"], "severity": data["severity"]} for rule, data in top_rules],
    }


def _build_alert_trend(items: list[dict], start: datetime, end: datetime, bucket_count: int = 24) -> list[dict]:
    total_seconds = max(1, (end - start).total_seconds())
    bucket_seconds = total_seconds / bucket_count
    buckets = []
    for idx in range(bucket_count):
        bucket_start = start + timedelta(seconds=bucket_seconds * idx)
        bucket_end = start + timedelta(seconds=bucket_seconds * (idx + 1))
        buckets.append({
            "start": bucket_start.isoformat(),
            "end": bucket_end.isoformat(),
            "count": 0,
        })

    for item in items:
        timestamp = _parse_alert_timestamp(item.get("timestamp"))
        if not timestamp:
            continue
        index = int((timestamp - start).total_seconds() / bucket_seconds)
        if index == bucket_count and timestamp <= end:
            index = bucket_count - 1
        if 0 <= index < bucket_count:
            buckets[index]["count"] += 1

    return buckets


def _parse_next_token(next_token: str) -> dict | None:
    """Decode a pagination token coming from the dashboard query string."""
    if not next_token:
        return None

    try:
        return json.loads(unquote_plus(next_token))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid nextToken") from exc


def _collect_alert_pages(fetch_page, base_params: dict, limit: int) -> tuple[list[dict], int, dict | None]:
    """
    Keep querying DynamoDB until we collect enough matching alert summaries.

    DynamoDB applies filters after reading a page, so a single query can return
    fewer matching items than requested even when more recent matches exist.
    Use a broader internal page size than the UI display limit so busy
    deployments don't need dozens of tiny round-trips before any rows appear.
    """
    items = []
    scanned_count = 0
    last_evaluated_key = base_params.get("ExclusiveStartKey")
    request_params = dict(base_params)
    page_size = max(50, min(500, limit * 5))

    while len(items) < limit:
        page_params = dict(request_params)
        page_params["Limit"] = page_size

        response = fetch_page(**page_params)
        page_items = response.get("Items", [])
        items.extend(page_items)
        scanned_count += response.get("ScannedCount", len(page_items))

        last_evaluated_key = response.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

        request_params["ExclusiveStartKey"] = last_evaluated_key

    return items[:limit], scanned_count, last_evaluated_key


# ---------------------------------------------------------------------------
# Rules endpoints
# ---------------------------------------------------------------------------

def list_rules() -> dict:
    """GET /api/rules — list active and disabled Sigma rules."""
    try:
        paginator = s3.get_paginator("list_objects_v2")
        rules = []
        for prefix, enabled in ((RULES_PREFIX, True), (DISABLED_RULES_PREFIX, False)):
            for page in paginator.paginate(Bucket=RULES_BUCKET, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if not key.endswith((".yaml", ".yml")):
                        continue

                    display_key = _display_rule_key(key)
                    base_rule = {
                        "key": display_key,
                        "enabled": enabled,
                        "prefix": prefix,
                        "lastModified": obj["LastModified"].isoformat(),
                        "size": obj["Size"],
                    }
                    try:
                        body = s3.get_object(Bucket=RULES_BUCKET, Key=key)["Body"].read().decode("utf-8")
                        parsed = yaml.safe_load(body)
                        if isinstance(parsed, dict):
                            base_rule.update({
                                "title": parsed.get("title", "Untitled"),
                                "level": parsed.get("level", "unknown"),
                                "status": parsed.get("status", "unknown"),
                                "description": parsed.get("description", ""),
                            })
                        else:
                            base_rule.update({"title": display_key, "level": "unknown", "status": "parse_error", "description": "Rule is not a YAML mapping"})
                        rules.append(base_rule)
                    except Exception as e:
                        logger.warning(f"Failed to parse rule {key}: {e}")
                        base_rule.update({
                            "title": display_key,
                            "level": "unknown",
                            "status": "parse_error",
                            "description": str(e),
                        })
                        rules.append(base_rule)

        return _response(200, {"rules": rules, "count": len(rules)})
    except Exception as e:
        logger.error(f"Error listing rules: {e}")
        return _response(500, {"error": "Failed to list rules"})


def get_rule(key: str, enabled: bool | None = None) -> dict:
    """GET /api/rules/{key} — get a single rule's YAML content."""
    display_key = _normalize_rule_key(key)
    try:
        s3_key, resolved_enabled, _ = _find_rule_location(display_key, enabled)
        if not s3_key:
            return _response(404, {"error": f"Rule not found: {display_key}"})
        get_args = {"Bucket": RULES_BUCKET, "Key": s3_key}
        obj = s3.get_object(**get_args)
        content = obj["Body"].read().decode("utf-8")
        version_id = obj.get("VersionId")
        return _response(200, {
            "key": display_key,
            "content": content,
            "enabled": resolved_enabled,
            "prefix": RULES_PREFIX if resolved_enabled else DISABLED_RULES_PREFIX,
            "versionId": version_id,
            "lastModified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
        })
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return _response(404, {"error": f"Rule not found: {key}"})
        logger.error(f"Error getting rule {key}: {e}")
        return _response(500, {"error": "Failed to get rule"})


def get_rule_version(key: str, version_id: str, enabled: bool | None = None) -> dict:
    """GET /api/rules/{key}?versionId=... — get a specific S3 object version."""
    display_key = _normalize_rule_key(key)
    try:
        s3_key, resolved_enabled, _ = _find_rule_location(display_key, enabled)
        if not s3_key:
            return _response(404, {"error": f"Rule not found: {display_key}"})
        obj = s3.get_object(Bucket=RULES_BUCKET, Key=s3_key, VersionId=version_id)
        content = obj["Body"].read().decode("utf-8")
        return _response(200, {
            "key": display_key,
            "content": content,
            "enabled": resolved_enabled,
            "prefix": RULES_PREFIX if resolved_enabled else DISABLED_RULES_PREFIX,
            "versionId": obj.get("VersionId", version_id),
            "lastModified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
        })
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "NoSuchVersion", "404"):
            return _response(404, {"error": f"Rule version not found: {key}"})
        logger.error(f"Error getting rule version {key}: {e}")
        return _response(500, {"error": "Failed to get rule version"})


def validate_rule(body: str) -> dict:
    """POST /api/rules/validate — validate rule YAML without saving."""
    analysis = _analyze_sigma_rule(body)
    return _response(200, {key: value for key, value in analysis.items() if key != "rule"})


def test_rule(body: str) -> dict:
    """POST /api/rules/test — validate and optionally run a rule against a sample event."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError as exc:
        return _response(400, {"error": f"Invalid JSON test payload: {exc}"})

    content = payload.get("content", "")
    sample_event = payload.get("sampleEvent")
    analysis = _analyze_sigma_rule(content)
    if not analysis["valid"]:
        return _response(200, {
            "valid": False,
            "matched": None,
            "errors": analysis["errors"],
            "warnings": analysis["warnings"],
            "summary": "Fix validation errors before testing this rule.",
        })

    if isinstance(sample_event, str) and sample_event.strip():
        try:
            sample_event = json.loads(sample_event)
        except json.JSONDecodeError as exc:
            return _response(200, {
                "valid": True,
                "matched": None,
                "errors": [{"message": f"Sample event is not valid JSON: {exc}"}],
                "warnings": analysis["warnings"],
                "summary": "Rule is valid, but the sample event could not be parsed.",
            })

    if not isinstance(sample_event, dict):
        return _response(200, {
            "valid": True,
            "matched": None,
            "errors": [],
            "warnings": analysis["warnings"],
            "summary": "Rule is valid. Add a sample CloudTrail event to run a match test.",
            "metadata": analysis["metadata"],
            "blocks": analysis["blocks"],
        })

    result = _test_sigma_rule(analysis["rule"], sample_event)
    return _response(200, {
        "valid": True,
        "matched": result["matched"],
        "errors": [],
        "warnings": analysis["warnings"],
        "summary": "Sample event matched this rule." if result["matched"] else "Sample event did not match this rule.",
        "metadata": analysis["metadata"],
        "blocks": analysis["blocks"],
        "condition": result["condition"],
        "evaluatedBlocks": result["evaluatedBlocks"],
    })


def list_rule_versions(key: str, enabled: bool | None = None) -> dict:
    """GET /api/rules/history?key=... — list S3 versions for a rule."""
    if not key:
        return _response(400, {"error": "key query parameter required"})

    display_key = _normalize_rule_key(key)
    try:
        s3_key, resolved_enabled, _ = _find_rule_location(display_key, enabled)
        if not s3_key:
            return _response(200, {"key": display_key, "versions": [], "versioningEnabled": True})
        response = s3.list_object_versions(Bucket=RULES_BUCKET, Prefix=s3_key)
        versions = []
        for version in response.get("Versions", []):
            if version.get("Key") != s3_key:
                continue
            versions.append({
                "versionId": version.get("VersionId"),
                "lastModified": version.get("LastModified").isoformat() if version.get("LastModified") else None,
                "size": version.get("Size", 0),
                "isLatest": version.get("IsLatest", False),
                "etag": (version.get("ETag") or "").strip('"'),
            })

        versions.sort(key=lambda item: item.get("lastModified") or "", reverse=True)
        return _response(200, {
            "key": display_key,
            "enabled": resolved_enabled,
            "prefix": RULES_PREFIX if resolved_enabled else DISABLED_RULES_PREFIX,
            "versions": versions[:25],
            "versioningEnabled": True,
        })
    except ClientError as e:
        logger.error(f"Error listing versions for rule {key}: {e}")
        return _response(500, {"error": "Failed to list rule history"})


def put_rule(key: str, body: str, enabled: bool = True) -> dict:
    """PUT /api/rules/{key} — create or update a rule."""
    if not body:
        return _response(400, {"error": "Request body is empty"})

    is_valid, result = _validate_sigma_rule(body)
    if not is_valid:
        return _response(400, {"error": result})

    display_key = _normalize_rule_key(key)
    s3_key = _safe_key(display_key, enabled)
    try:
        s3.put_object(
            Bucket=RULES_BUCKET,
            Key=s3_key,
            Body=body.encode("utf-8"),
            ContentType="text/yaml",
            ServerSideEncryption="AES256",
        )
        return _response(200, {
            "message": f"Rule saved: {display_key}",
            "key": display_key,
            "enabled": enabled,
            "prefix": RULES_PREFIX if enabled else DISABLED_RULES_PREFIX,
        })
    except Exception as e:
        logger.error(f"Error saving rule {key}: {e}")
        return _response(500, {"error": "Failed to save rule"})


def delete_rule(key: str, enabled: bool | None = None) -> dict:
    """DELETE /api/rules/{key} — delete a rule."""
    display_key = _normalize_rule_key(key)
    try:
        s3_key, resolved_enabled, _ = _find_rule_location(display_key, enabled)
        if not s3_key:
            return _response(404, {"error": f"Rule not found: {display_key}"})
        s3.delete_object(Bucket=RULES_BUCKET, Key=s3_key)
        return _response(200, {"message": f"Rule deleted: {display_key}", "key": display_key, "enabled": resolved_enabled})
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return _response(404, {"error": f"Rule not found: {display_key}"})
        logger.error(f"Error deleting rule {display_key}: {e}")
        return _response(500, {"error": "Failed to delete rule"})


def set_rule_enabled(key: str, body: str) -> dict:
    """POST /api/rules/{key}/state — move a rule between active and disabled prefixes."""
    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError as exc:
        return _response(400, {"error": f"Invalid JSON state payload: {exc}"})

    if "enabled" not in payload:
        return _response(400, {"error": "enabled field required"})

    target_enabled = _enabled_param(payload.get("enabled"), None)
    if target_enabled is None:
        return _response(400, {"error": "enabled must be true or false"})
    display_key = _normalize_rule_key(key)

    try:
        current_s3_key, current_enabled, _ = _find_rule_location(display_key, not target_enabled)
        if not current_s3_key:
            current_s3_key, current_enabled, _ = _find_rule_location(display_key, target_enabled)
        if not current_s3_key:
            return _response(404, {"error": f"Rule not found: {display_key}"})
        if current_enabled == target_enabled:
            return _response(200, {
                "message": f"Rule already {'enabled' if target_enabled else 'disabled'}: {display_key}",
                "key": display_key,
                "enabled": target_enabled,
                "prefix": RULES_PREFIX if target_enabled else DISABLED_RULES_PREFIX,
            })

        target_s3_key = _safe_key(display_key, target_enabled)
        s3.copy_object(
            Bucket=RULES_BUCKET,
            Key=target_s3_key,
            CopySource={"Bucket": RULES_BUCKET, "Key": current_s3_key},
            MetadataDirective="COPY",
            ServerSideEncryption="AES256",
        )
        s3.delete_object(Bucket=RULES_BUCKET, Key=current_s3_key)
        return _response(200, {
            "message": f"Rule {'enabled' if target_enabled else 'disabled'}: {display_key}",
            "key": display_key,
            "enabled": target_enabled,
            "prefix": RULES_PREFIX if target_enabled else DISABLED_RULES_PREFIX,
        })
    except ClientError as e:
        logger.error(f"Error changing rule state {display_key}: {e}")
        return _response(500, {"error": "Failed to change rule state"})


# ---------------------------------------------------------------------------
# Alerts endpoints
# ---------------------------------------------------------------------------

def get_alerts(params: dict) -> dict:
    """GET /api/alerts — query alert history from DynamoDB."""
    table = _get_table()
    if table is None:
        return _response(503, {"error": "Alert history not available (DynamoDB not configured)"})

    try:
        limit = max(1, min(int(params.get("limit", 50)), 200))
        rule_filter = (params.get("rule", "") or "").strip()
        severity_filter = (params.get("severity", "") or "").strip()
        source_filter = (params.get("source", "") or "").strip().lower()
        hours = max(1, int(params.get("hours", 24)))
        exclusive_start_key = _parse_next_token(params.get("nextToken", ""))

        # Determine time range
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        start_time = (now - timedelta(hours=hours)).isoformat()

        # Build recent-first query parameters
        if rule_filter:
            query_params = {
                "IndexName": "sigmaRuleTitleIndex",
                "KeyConditionExpression": "sigmaRuleTitle = :rule AND #ts >= :start",
                "ExpressionAttributeNames": {"#ts": "timestamp"},
                "ExpressionAttributeValues": {
                    ":rule": rule_filter,
                    ":start": start_time,
                },
                "ProjectionExpression": _ALERT_SUMMARY_PROJECTION,
                "ScanIndexForward": False,
            }
        elif source_filter:
            query_params = {
                "IndexName": "sourceTypeIndex",
                "KeyConditionExpression": "sourceType = :source AND #ts >= :start",
                "ExpressionAttributeNames": {"#ts": "timestamp"},
                "ExpressionAttributeValues": {
                    ":source": source_filter,
                    ":start": start_time,
                },
                "ProjectionExpression": _ALERT_SUMMARY_PROJECTION,
                "ScanIndexForward": False,
            }
        else:
            query_params = {
                "IndexName": "recentAlertsIndex",
                "KeyConditionExpression": "pk = :pk AND #ts >= :start",
                "ExpressionAttributeNames": {"#ts": "timestamp"},
                "ExpressionAttributeValues": {
                    ":pk": "EVENT",
                    ":start": start_time,
                },
                "ProjectionExpression": _ALERT_SUMMARY_PROJECTION,
                "ScanIndexForward": False,
            }

        filter_expressions = []
        if severity_filter:
            filter_expressions.append("severity = :sev")
            query_params["ExpressionAttributeValues"][":sev"] = severity_filter
        if source_filter and rule_filter:
            filter_expressions.append("sourceType = :source")
            query_params["ExpressionAttributeValues"][":source"] = source_filter
        if filter_expressions:
            query_params["FilterExpression"] = " AND ".join(filter_expressions)

        if exclusive_start_key:
            query_params["ExclusiveStartKey"] = exclusive_start_key

        items, scanned_count, last_evaluated_key = _collect_alert_pages(
            table.query,
            query_params,
            limit,
        )

        result = {
            "alerts": items,
            "count": len(items),
            "scannedCount": scanned_count,
        }

        if last_evaluated_key:
            result["nextToken"] = json.dumps(last_evaluated_key, cls=DecimalEncoder)

        return _response(200, result)

    except ValueError as e:
        return _response(400, {"error": str(e)})
    except Exception as e:
        logger.error(f"Error querying alerts: {e}")
        return _response(500, {"error": "Failed to query alerts"})


def get_alert_detail(pk: str, sk: str) -> dict:
    """GET /api/alerts/detail — get full alert detail including rawEvent."""
    table = _get_table()
    if table is None:
        return _response(503, {"error": "Alert history not available"})

    try:
        response = table.get_item(Key={"pk": pk, "sk": sk})
        item = response.get("Item")
        if not item:
            return _response(404, {"error": "Alert not found"})
        return _response(200, {"alert": item})
    except Exception as e:
        logger.error(f"Error getting alert detail: {e}")
        return _response(500, {"error": "Failed to get alert detail"})


def get_alert_stats(params: dict) -> dict:
    """GET /api/alerts/stats — summary statistics for dashboard-visible EVENT history."""
    table = _get_table()
    if table is None:
        return _response(503, {"error": "Alert history not available"})

    try:
        hours = max(1, int(params.get("hours", 24)))
        include_comparisons = _truthy_param(params.get("includeComparisons"))
        include_trend = _truthy_param(params.get("includeTrend"))
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        start = now - timedelta(hours=hours)

        items = _query_alert_stats_window(table, start, now)
        result = _aggregate_alert_stats(items)
        result["hours"] = hours

        if include_trend:
            result["trend"] = _build_alert_trend(items, start, now)

        if include_comparisons:
            previous_start = start - timedelta(hours=hours)
            previous_items = _query_alert_stats_window(table, previous_start, start)

            last_week_start = start - timedelta(days=7)
            last_week_end = now - timedelta(days=7)
            last_week_items = _query_alert_stats_window(table, last_week_start, last_week_end)

            result["comparisons"] = {
                "previous24h": _aggregate_alert_stats(previous_items),
                "previousWeek": _aggregate_alert_stats(last_week_items),
            }

        return _response(200, result)

    except Exception as e:
        logger.error(f"Error computing stats: {e}")
        return _response(500, {"error": "Failed to compute stats"})


# ---------------------------------------------------------------------------
# Postprocessing rules endpoints (correlation & threshold)
# ---------------------------------------------------------------------------

POSTPROCESSING_REQUIRED = {
    "correlation": ["type", "sigmaRuleTitle", "lookFor", "windowMinutes"],
    "threshold": ["type", "sigmaRuleTitle", "thresholdCount", "windowMinutes"],
}


def _json_error_detail(exc: json.JSONDecodeError) -> dict:
    return {
        "message": f"Invalid JSON: {exc.msg}",
        "line": exc.lineno,
        "column": exc.colno,
    }


def _analyze_postprocessing_rules(content: str) -> dict:
    errors = []
    warnings = []
    hints = []

    if not content or not content.strip():
        return {
            "valid": False,
            "errors": [{"message": "Postprocessing content is empty", "line": 1, "column": 1}],
            "warnings": [],
            "hints": ["Start with a correlation or threshold rule object, or an array of rule objects."],
            "metadata": {},
            "rules": [],
        }

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        return {
            "valid": False,
            "errors": [_json_error_detail(exc)],
            "warnings": [],
            "hints": ["Fix the JSON syntax before rule fields can be checked."],
            "metadata": {},
            "rules": [],
        }

    rules = parsed if isinstance(parsed, list) else [parsed]
    if not isinstance(parsed, list):
        warnings.append({"message": "Single rule objects are accepted, but the dashboard saves files as a JSON array.", "line": 1})

    correlation_count = 0
    threshold_count = 0
    for index, rule in enumerate(rules):
        label = f"Rule {index + 1}"
        if not isinstance(rule, dict):
            errors.append({"message": f"{label} must be an object"})
            continue

        rule_type = rule.get("type")
        if rule_type not in POSTPROCESSING_REQUIRED:
            errors.append({"message": f"{label}: type must be 'correlation' or 'threshold'"})
            continue

        if rule_type == "correlation":
            correlation_count += 1
        if rule_type == "threshold":
            threshold_count += 1

        missing = [field for field in POSTPROCESSING_REQUIRED[rule_type] if field not in rule]
        if missing:
            errors.append({"message": f"{label} ({rule_type}) missing fields: {', '.join(missing)}"})

        if not rule.get("sigmaRuleTitle"):
            warnings.append({"message": f"{label}: sigmaRuleTitle is empty, so it will not attach to a detection title."})

        window_minutes = rule.get("windowMinutes")
        if not isinstance(window_minutes, (int, float)) or window_minutes <= 0:
            errors.append({"message": f"{label}: windowMinutes must be a positive number"})

        if rule_type == "correlation":
            look_for = rule.get("lookFor")
            if isinstance(look_for, str):
                warnings.append({"message": f"{label}: lookFor can be a string, but an array is clearer for multiple related rules."})
            elif not isinstance(look_for, list) or not look_for:
                errors.append({"message": f"{label}: lookFor must be a non-empty string or array"})

        if rule_type == "threshold":
            threshold_count_value = rule.get("thresholdCount")
            if not isinstance(threshold_count_value, (int, float)) or threshold_count_value <= 0:
                errors.append({"message": f"{label}: thresholdCount must be a positive number"})

        adjust_severity = rule.get("adjustSeverity") or rule.get("severity_adjustment")
        if adjust_severity and str(adjust_severity).lower() not in _SEVERITY_RANK:
            warnings.append({"message": f"{label}: adjustSeverity should usually be critical, high, medium, low, or info."})

    if not rules:
        errors.append({"message": "Postprocessing file must contain at least one rule"})

    hints.extend([
        "Correlation rules need type, sigmaRuleTitle, lookFor, and windowMinutes.",
        "Threshold rules need type, sigmaRuleTitle, thresholdCount, and windowMinutes.",
        "adjustSeverity can raise the notification/dashboard severity after a match.",
    ])

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "hints": hints,
        "metadata": {
            "ruleCount": len(rules),
            "correlationCount": correlation_count,
            "thresholdCount": threshold_count,
        },
        "rules": rules if len(errors) == 0 else [],
    }


def _validate_postprocessing_rules(content: str) -> tuple:
    """Validate JSON content as postprocessing rules (list of correlation/threshold)."""
    analysis = _analyze_postprocessing_rules(content)
    if not analysis["valid"]:
        return False, "; ".join(error["message"] for error in analysis["errors"])

    return True, analysis["rules"]


def validate_postprocessing(body: str) -> dict:
    """POST /api/postprocessing/validate — validate postprocessing JSON without saving."""
    analysis = _analyze_postprocessing_rules(body)
    return _response(200, {key: value for key, value in analysis.items() if key != "rules"})


def list_postprocessing() -> dict:
    """GET /api/postprocessing — list all postprocessing rule files with parsed content."""
    try:
        paginator = s3.get_paginator("list_objects_v2")
        files = []
        correlation_rules = []
        threshold_rules = []

        for page in paginator.paginate(Bucket=RULES_BUCKET, Prefix=POSTPROCESSING_PREFIX):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".json"):
                    try:
                        body = s3.get_object(Bucket=RULES_BUCKET, Key=key)["Body"].read().decode("utf-8")
                        parsed = json.loads(body)
                        if not isinstance(parsed, list):
                            parsed = [parsed]
                        fname = key.removeprefix(POSTPROCESSING_PREFIX)
                        files.append({
                            "key": fname,
                            "lastModified": obj["LastModified"].isoformat(),
                            "size": obj["Size"],
                            "ruleCount": len(parsed),
                        })
                        for rule in parsed:
                            rule["_file"] = fname
                            if rule.get("type") == "correlation":
                                correlation_rules.append(rule)
                            elif rule.get("type") == "threshold":
                                threshold_rules.append(rule)
                    except Exception as e:
                        logger.warning(f"Failed to parse postprocessing file {key}: {e}")
                        files.append({
                            "key": key.removeprefix(POSTPROCESSING_PREFIX),
                            "lastModified": obj["LastModified"].isoformat(),
                            "size": obj["Size"],
                            "ruleCount": 0,
                            "error": str(e),
                        })

        return _response(200, {
            "files": files,
            "correlationRules": correlation_rules,
            "thresholdRules": threshold_rules,
        })
    except Exception as e:
        logger.error(f"Error listing postprocessing rules: {e}")
        return _response(500, {"error": "Failed to list postprocessing rules"})


def get_postprocessing(key: str) -> dict:
    """GET /api/postprocessing/{key} — get raw JSON content of a file."""
    s3_key = f"{POSTPROCESSING_PREFIX}{key.strip('/')}"
    if not s3_key.endswith(".json"):
        s3_key += ".json"
    try:
        obj = s3.get_object(Bucket=RULES_BUCKET, Key=s3_key)
        content = obj["Body"].read().decode("utf-8")
        return _response(200, {
            "key": key,
            "content": content,
            "lastModified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
            "versionId": obj.get("VersionId"),
        })
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return _response(404, {"error": f"File not found: {key}"})
        logger.error(f"Error getting postprocessing file {key}: {e}")
        return _response(500, {"error": "Failed to get file"})


def put_postprocessing(key: str, body: str) -> dict:
    """PUT /api/postprocessing/{key} — create or update a postprocessing rules file."""
    if not body:
        return _response(400, {"error": "Request body is empty"})

    is_valid, result = _validate_postprocessing_rules(body)
    if not is_valid:
        return _response(400, {"error": result})

    s3_key = f"{POSTPROCESSING_PREFIX}{key.strip('/')}"
    if not s3_key.endswith(".json"):
        s3_key += ".json"
    try:
        s3.put_object(
            Bucket=RULES_BUCKET,
            Key=s3_key,
            Body=body.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        return _response(200, {"message": f"Postprocessing rules saved: {key}", "key": key})
    except Exception as e:
        logger.error(f"Error saving postprocessing file {key}: {e}")
        return _response(500, {"error": "Failed to save file"})


def delete_postprocessing(key: str) -> dict:
    """DELETE /api/postprocessing/{key} — delete a postprocessing rules file."""
    s3_key = f"{POSTPROCESSING_PREFIX}{key.strip('/')}"
    if not s3_key.endswith(".json"):
        s3_key += ".json"
    try:
        s3.head_object(Bucket=RULES_BUCKET, Key=s3_key)
        s3.delete_object(Bucket=RULES_BUCKET, Key=s3_key)
        return _response(200, {"message": f"File deleted: {key}"})
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return _response(404, {"error": f"File not found: {key}"})
        logger.error(f"Error deleting postprocessing file {key}: {e}")
        return _response(500, {"error": "Failed to delete file"})


# ---------------------------------------------------------------------------
# Exceptions endpoints
# ---------------------------------------------------------------------------

EXCEPTION_ALLOWED_FIELDS = {"excludedActors", "excludedSourceIPs", "excludedActorsRegex"}


def _json_key_line(content: str, key: str) -> int | None:
    pattern = re.compile(rf"{re.escape(json.dumps(key))}\s*:")
    match = pattern.search(content)
    if not match:
        return None
    return content[:match.start()].count("\n") + 1


def _analyze_exceptions(content: str) -> dict:
    errors = []
    warnings = []
    hints = []

    if not content or not content.strip():
        return {
            "valid": False,
            "errors": [{"message": "Exceptions content is empty", "line": 1, "column": 1}],
            "warnings": [],
            "hints": ["Start with a JSON object keyed by Sigma rule title."],
            "metadata": {},
            "exceptions": {},
        }

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        return {
            "valid": False,
            "errors": [_json_error_detail(exc)],
            "warnings": [],
            "hints": ["Fix the JSON syntax before exception fields can be checked."],
            "metadata": {},
            "exceptions": {},
        }

    if not isinstance(data, dict):
        return {
            "valid": False,
            "errors": [{"message": "Exceptions must be a JSON object keyed by rule title", "line": 1}],
            "warnings": [],
            "hints": ["Use the Sigma rule title as the object key, then add excludedActors, excludedSourceIPs, or excludedActorsRegex arrays."],
            "metadata": {},
            "exceptions": {},
        }

    actor_count = 0
    source_ip_count = 0
    regex_count = 0
    empty_rule_count = 0

    for rule_title, config in data.items():
        rule_line = _json_key_line(content, rule_title) or 1
        if not isinstance(rule_title, str) or not rule_title.strip():
            errors.append({"message": "Rule title keys must be non-empty strings", "line": rule_line})
            continue

        if not isinstance(config, dict):
            errors.append({"message": f"Config for '{rule_title}' must be an object", "line": rule_line})
            continue

        unknown_fields = sorted(set(config.keys()) - EXCEPTION_ALLOWED_FIELDS)
        for field in unknown_fields:
            errors.append({
                "message": f"Unknown field '{field}' in '{rule_title}'. Allowed fields: {', '.join(sorted(EXCEPTION_ALLOWED_FIELDS))}",
                "line": _json_key_line(content, field) or rule_line,
            })

        criteria_count = 0
        for field in sorted(EXCEPTION_ALLOWED_FIELDS):
            if field not in config:
                continue

            field_line = _json_key_line(content, field) or rule_line
            values = config[field]
            if not isinstance(values, list):
                errors.append({"message": f"'{field}' in '{rule_title}' must be an array", "line": field_line})
                continue

            criteria_count += len(values)
            for index, value in enumerate(values):
                if not isinstance(value, str):
                    errors.append({"message": f"'{field}[{index}]' in '{rule_title}' must be a string", "line": field_line})

            if field == "excludedActors":
                actor_count += len(values)
            elif field == "excludedSourceIPs":
                source_ip_count += len(values)
            elif field == "excludedActorsRegex":
                regex_count += len(values)
                for index, pattern in enumerate(values):
                    if not isinstance(pattern, str):
                        continue
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        errors.append({
                            "message": f"Invalid regex in '{rule_title}'.excludedActorsRegex[{index}]: {str(exc)}",
                            "line": field_line,
                        })

        if criteria_count == 0:
            empty_rule_count += 1
            warnings.append({"message": f"'{rule_title}' has no exclusion criteria yet", "line": rule_line})

    if not data:
        hints.append("No exceptions are currently defined. Add a rule title key to suppress known benign activity.")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "hints": hints,
        "metadata": {
            "ruleCount": len(data),
            "actorCount": actor_count,
            "sourceIpCount": source_ip_count,
            "regexCount": regex_count,
            "emptyRuleCount": empty_rule_count,
        },
        "exceptions": data,
    }


def _validate_exceptions(content: str) -> tuple:
    """Validate JSON content as exceptions config."""
    analysis = _analyze_exceptions(content)
    if not analysis["valid"]:
        first_error = analysis["errors"][0] if analysis["errors"] else {"message": "Invalid exceptions configuration"}
        return False, first_error["message"]
    return True, analysis["exceptions"]


def validate_exceptions(body: str) -> dict:
    """POST /api/exceptions/validate — validate exceptions JSON without saving."""
    analysis = _analyze_exceptions(body)
    analysis.pop("exceptions", None)
    return _response(200, analysis)


def get_exceptions() -> dict:
    """GET /api/exceptions — get the exceptions configuration."""
    try:
        obj = s3.get_object(Bucket=RULES_BUCKET, Key=EXCEPTIONS_KEY)
        content = obj["Body"].read().decode("utf-8")
        return _response(200, {
            "content": content,
            "exceptions": json.loads(content),
            "lastModified": obj.get("LastModified").isoformat() if obj.get("LastModified") else None,
            "versionId": obj.get("VersionId"),
        })
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return _response(200, {"content": "{}", "exceptions": {}, "lastModified": None, "versionId": None})
        logger.error(f"Error getting exceptions: {e}")
        return _response(500, {"error": "Failed to get exceptions"})


def put_exceptions(body: str) -> dict:
    """PUT /api/exceptions — save the exceptions configuration."""
    if not body:
        return _response(400, {"error": "Request body is empty"})

    is_valid, result = _validate_exceptions(body)
    if not is_valid:
        return _response(400, {"error": result})

    try:
        # Pretty-print for readability in S3
        formatted = json.dumps(result, indent=4)
        s3.put_object(
            Bucket=RULES_BUCKET,
            Key=EXCEPTIONS_KEY,
            Body=formatted.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        return _response(200, {"message": "Exceptions saved"})
    except Exception as e:
        logger.error(f"Error saving exceptions: {e}")
        return _response(500, {"error": "Failed to save exceptions"})


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    """Main handler — routes HTTP API v2 events."""
    request_context = event.get("requestContext", {}) or {}
    http = request_context.get("http", {}) or {}
    auth_claims = ((request_context.get("authorizer") or {}).get("jwt") or {}).get("claims") or {}
    safe_request_log = {
        "requestId": request_context.get("requestId"),
        "method": http.get("method", ""),
        "path": event.get("rawPath", ""),
        "routeKey": request_context.get("routeKey"),
        "sourceIp": http.get("sourceIp"),
        "queryParamKeys": sorted((event.get("queryStringParameters") or {}).keys()),
    }
    if auth_claims.get("sub"):
        safe_request_log["principalSub"] = auth_claims.get("sub")
    logger.info("Received request: %s", json.dumps(safe_request_log, default=str))

    method = http.get("method", "")
    path = event.get("rawPath", "")
    params = event.get("queryStringParameters") or {}

    try:
        # Rules routes
        if path == "/api/rules" and method == "GET":
            return list_rules()

        if path == "/api/rules/validate" and method == "POST":
            return validate_rule(_event_body_text(event))

        if path == "/api/rules/test" and method == "POST":
            return test_rule(_event_body_text(event))

        if path == "/api/rules/history" and method == "GET":
            return list_rule_versions(params.get("key", ""), _enabled_param(params.get("enabled"), None))

        if path.startswith("/api/rules/") and path.endswith("/state") and method == "POST":
            key = unquote_plus(path[len("/api/rules/"):-len("/state")])
            return set_rule_enabled(key, _event_body_text(event))

        if path.startswith("/api/rules/") and len(path) > len("/api/rules/"):
            key = unquote_plus(path[len("/api/rules/"):])
            if method == "GET":
                version_id = params.get("versionId")
                if version_id:
                    return get_rule_version(key, version_id, _enabled_param(params.get("enabled"), None))
                return get_rule(key, _enabled_param(params.get("enabled"), None))
            if method == "PUT":
                return put_rule(key, _event_body_text(event), _enabled_param(params.get("enabled"), True))
            if method == "DELETE":
                return delete_rule(key, _enabled_param(params.get("enabled"), None))

        # Alert routes
        if path == "/api/alerts" and method == "GET":
            return get_alerts(params)

        if path == "/api/alerts/detail" and method == "GET":
            pk = params.get("pk", "")
            sk = params.get("sk", "")
            if not pk or not sk:
                return _response(400, {"error": "pk and sk query parameters required"})
            return get_alert_detail(pk, sk)

        if path == "/api/alerts/stats" and method == "GET":
            return get_alert_stats(params)

        # Postprocessing routes
        if path == "/api/postprocessing" and method == "GET":
            return list_postprocessing()

        if path == "/api/postprocessing/validate" and method == "POST":
            return validate_postprocessing(_event_body_text(event))

        if path.startswith("/api/postprocessing/") and len(path) > len("/api/postprocessing/"):
            key = unquote_plus(path[len("/api/postprocessing/"):])
            if method == "GET":
                return get_postprocessing(key)
            if method == "PUT":
                return put_postprocessing(key, _event_body_text(event))
            if method == "DELETE":
                return delete_postprocessing(key)

        # Exceptions routes
        if path == "/api/exceptions" and method == "GET":
            return get_exceptions()

        if path == "/api/exceptions/validate" and method == "POST":
            return validate_exceptions(_event_body_text(event))

        if path == "/api/exceptions" and method == "PUT":
            return put_exceptions(_event_body_text(event))

        return _response(404, {"error": "Not found"})

    except Exception as e:
        logger.error(f"Unhandled error: {e}", exc_info=True)
        return _response(500, {"error": "Internal server error"})

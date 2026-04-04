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


def _safe_key(key: str) -> str:
    """Ensure the key is within the sigma_rules prefix and is a YAML file."""
    key = key.strip("/")
    if not key.endswith((".yaml", ".yml")):
        key += ".yaml"
    return f"{RULES_PREFIX}{key}" if not key.startswith(RULES_PREFIX) else key


def _validate_sigma_rule(content: str) -> tuple:
    """
    Validate that the content is valid YAML and has basic Sigma rule structure.
    Returns (is_valid, parsed_rule_or_error_message).
    """
    try:
        rule = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {str(e)}"

    if not isinstance(rule, dict):
        return False, "Rule must be a YAML mapping"

    required_fields = ["title", "logsource", "detection"]
    missing = [f for f in required_fields if f not in rule]
    if missing:
        return False, f"Missing required Sigma fields: {', '.join(missing)}"

    detection = rule.get("detection", {})
    if "condition" not in detection:
        return False, "Detection block must contain a 'condition' field"

    return True, rule


_ALERT_SUMMARY_PROJECTION = (
    "pk, sk, #ts, actor, target, accountId, severity, sourceIp, "
    "userAgent, sigmaRuleId, sigmaRuleTitle, eventName, sourceType, eventType"
)


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
    """
    items = []
    scanned_count = 0
    last_evaluated_key = base_params.get("ExclusiveStartKey")
    request_params = dict(base_params)

    while len(items) < limit:
        page_params = dict(request_params)
        page_params["Limit"] = max(1, limit - len(items))

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
    """GET /api/rules — list all Sigma rules."""
    try:
        paginator = s3.get_paginator("list_objects_v2")
        rules = []
        for page in paginator.paginate(Bucket=RULES_BUCKET, Prefix=RULES_PREFIX):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith((".yaml", ".yml")):
                    # Fetch and parse each rule for metadata
                    try:
                        body = s3.get_object(Bucket=RULES_BUCKET, Key=key)["Body"].read().decode("utf-8")
                        parsed = yaml.safe_load(body)
                        if isinstance(parsed, dict):
                            rules.append({
                                "key": key.removeprefix(RULES_PREFIX),
                                "title": parsed.get("title", "Untitled"),
                                "level": parsed.get("level", "unknown"),
                                "status": parsed.get("status", "unknown"),
                                "description": parsed.get("description", ""),
                                "lastModified": obj["LastModified"].isoformat(),
                                "size": obj["Size"],
                            })
                    except Exception as e:
                        logger.warning(f"Failed to parse rule {key}: {e}")
                        rules.append({
                            "key": key.removeprefix(RULES_PREFIX),
                            "title": key,
                            "level": "unknown",
                            "status": "parse_error",
                            "description": str(e),
                            "lastModified": obj["LastModified"].isoformat(),
                            "size": obj["Size"],
                        })

        return _response(200, {"rules": rules, "count": len(rules)})
    except Exception as e:
        logger.error(f"Error listing rules: {e}")
        return _response(500, {"error": "Failed to list rules"})


def get_rule(key: str) -> dict:
    """GET /api/rules/{key} — get a single rule's YAML content."""
    s3_key = _safe_key(key)
    try:
        obj = s3.get_object(Bucket=RULES_BUCKET, Key=s3_key)
        content = obj["Body"].read().decode("utf-8")
        return _response(200, {"key": key, "content": content})
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return _response(404, {"error": f"Rule not found: {key}"})
        logger.error(f"Error getting rule {key}: {e}")
        return _response(500, {"error": "Failed to get rule"})


def put_rule(key: str, body: str) -> dict:
    """PUT /api/rules/{key} — create or update a rule."""
    if not body:
        return _response(400, {"error": "Request body is empty"})

    is_valid, result = _validate_sigma_rule(body)
    if not is_valid:
        return _response(400, {"error": result})

    s3_key = _safe_key(key)
    try:
        s3.put_object(
            Bucket=RULES_BUCKET,
            Key=s3_key,
            Body=body.encode("utf-8"),
            ContentType="text/yaml",
            ServerSideEncryption="AES256",
        )
        return _response(200, {"message": f"Rule saved: {key}", "key": key})
    except Exception as e:
        logger.error(f"Error saving rule {key}: {e}")
        return _response(500, {"error": "Failed to save rule"})


def delete_rule(key: str) -> dict:
    """DELETE /api/rules/{key} — delete a rule."""
    s3_key = _safe_key(key)
    try:
        # Check it exists first
        s3.head_object(Bucket=RULES_BUCKET, Key=s3_key)
        s3.delete_object(Bucket=RULES_BUCKET, Key=s3_key)
        return _response(200, {"message": f"Rule deleted: {key}"})
    except ClientError as e:
        if e.response["Error"]["Code"] in ("404", "NoSuchKey"):
            return _response(404, {"error": f"Rule not found: {key}"})
        logger.error(f"Error deleting rule {key}: {e}")
        return _response(500, {"error": "Failed to delete rule"})


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

            if severity_filter:
                query_params["FilterExpression"] = "severity = :sev"
                query_params["ExpressionAttributeValues"][":sev"] = severity_filter
        else:
            query_params = {
                "KeyConditionExpression": "pk = :pk",
                "ExpressionAttributeNames": {"#ts": "timestamp"},
                "ExpressionAttributeValues": {
                    ":pk": "EVENT",
                    ":start": start_time,
                },
                "ProjectionExpression": _ALERT_SUMMARY_PROJECTION,
                "FilterExpression": "#ts >= :start",
                "ScanIndexForward": False,
            }

            if severity_filter:
                query_params["FilterExpression"] += " AND severity = :sev"
                query_params["ExpressionAttributeValues"][":sev"] = severity_filter

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
    """GET /api/alerts/stats — summary statistics."""
    table = _get_table()
    if table is None:
        return _response(503, {"error": "Alert history not available"})

    try:
        hours = max(1, int(params.get("hours", 24)))
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        start_time = (now - timedelta(hours=hours)).isoformat()

        scan_params = {
            "FilterExpression": "#ts >= :start",
            "ExpressionAttributeNames": {"#ts": "timestamp"},
            "ExpressionAttributeValues": {":start": start_time},
            "ProjectionExpression": "#ts, severity, sigmaRuleTitle",
        }

        items = []
        while True:
            response = table.scan(**scan_params)
            items.extend(response.get("Items", []))

            if "LastEvaluatedKey" not in response:
                break
            scan_params["ExclusiveStartKey"] = response["LastEvaluatedKey"]

        # Aggregate stats
        by_severity = {}
        by_rule = {}
        for item in items:
            sev = item.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1

            rule = item.get("sigmaRuleTitle", "unknown")
            by_rule[rule] = by_rule.get(rule, 0) + 1

        # Sort rules by count descending
        top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10]

        return _response(200, {
            "totalAlerts": len(items),
            "hours": hours,
            "bySeverity": by_severity,
            "topRules": [{"rule": r, "count": c} for r, c in top_rules],
        })

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


def _validate_postprocessing_rules(content: str) -> tuple:
    """Validate JSON content as postprocessing rules (list of correlation/threshold)."""
    try:
        rules = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}"

    if not isinstance(rules, list):
        return False, "Content must be a JSON array of rules"

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            return False, f"Rule at index {i} must be an object"
        rule_type = rule.get("type")
        if rule_type not in POSTPROCESSING_REQUIRED:
            return False, f"Rule at index {i}: 'type' must be 'correlation' or 'threshold', got '{rule_type}'"
        required = POSTPROCESSING_REQUIRED[rule_type]
        missing = [f for f in required if f not in rule]
        if missing:
            return False, f"Rule at index {i} ({rule_type}): missing fields: {', '.join(missing)}"
        if not isinstance(rule.get("windowMinutes"), (int, float)) or rule["windowMinutes"] <= 0:
            return False, f"Rule at index {i}: 'windowMinutes' must be a positive number"
        if rule_type == "threshold":
            if not isinstance(rule.get("thresholdCount"), (int, float)) or rule["thresholdCount"] <= 0:
                return False, f"Rule at index {i}: 'thresholdCount' must be a positive number"

    return True, rules


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
        return _response(200, {"key": key, "content": content})
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

def _validate_exceptions(content: str) -> tuple:
    """Validate JSON content as exceptions config."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}"

    if not isinstance(data, dict):
        return False, "Exceptions must be a JSON object keyed by rule title"

    allowed_keys = {"excludedActors", "excludedSourceIPs", "excludedActorsRegex"}
    for rule_title, config in data.items():
        if not isinstance(rule_title, str) or not rule_title.strip():
            return False, f"Rule title keys must be non-empty strings, got: {repr(rule_title)}"
        if not isinstance(config, dict):
            return False, f"Config for '{rule_title}' must be an object"
        unknown = set(config.keys()) - allowed_keys
        if unknown:
            return False, f"Unknown fields in '{rule_title}': {', '.join(unknown)}. Allowed: {', '.join(allowed_keys)}"
        for field in ["excludedActors", "excludedSourceIPs", "excludedActorsRegex"]:
            if field in config:
                if not isinstance(config[field], list):
                    return False, f"'{field}' in '{rule_title}' must be an array"
                for i, val in enumerate(config[field]):
                    if not isinstance(val, str):
                        return False, f"'{field}[{i}]' in '{rule_title}' must be a string"
        # Validate regex patterns
        for i, pattern in enumerate(config.get("excludedActorsRegex", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                return False, f"Invalid regex in '{rule_title}'.excludedActorsRegex[{i}]: {str(e)}"

    return True, data


def get_exceptions() -> dict:
    """GET /api/exceptions — get the exceptions configuration."""
    try:
        obj = s3.get_object(Bucket=RULES_BUCKET, Key=EXCEPTIONS_KEY)
        content = obj["Body"].read().decode("utf-8")
        return _response(200, {"content": content, "exceptions": json.loads(content)})
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return _response(200, {"content": "{}", "exceptions": {}})
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
    logger.info(f"Received event: {json.dumps(event, default=str)}")

    http = event.get("requestContext", {}).get("http", {})
    method = http.get("method", "")
    path = event.get("rawPath", "")
    params = event.get("queryStringParameters") or {}

    try:
        # Rules routes
        if path == "/api/rules" and method == "GET":
            return list_rules()

        if path.startswith("/api/rules/") and len(path) > len("/api/rules/"):
            key = unquote_plus(path[len("/api/rules/"):])
            if method == "GET":
                return get_rule(key)
            if method == "PUT":
                body = event.get("body", "")
                if event.get("isBase64Encoded"):
                    import base64
                    body = base64.b64decode(body).decode("utf-8")
                return put_rule(key, body)
            if method == "DELETE":
                return delete_rule(key)

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

        if path.startswith("/api/postprocessing/") and len(path) > len("/api/postprocessing/"):
            key = unquote_plus(path[len("/api/postprocessing/"):])
            if method == "GET":
                return get_postprocessing(key)
            if method == "PUT":
                body = event.get("body", "")
                if event.get("isBase64Encoded"):
                    import base64
                    body = base64.b64decode(body).decode("utf-8")
                return put_postprocessing(key, body)
            if method == "DELETE":
                return delete_postprocessing(key)

        # Exceptions routes
        if path == "/api/exceptions" and method == "GET":
            return get_exceptions()

        if path == "/api/exceptions" and method == "PUT":
            body = event.get("body", "")
            if event.get("isBase64Encoded"):
                import base64
                body = base64.b64decode(body).decode("utf-8")
            return put_exceptions(body)

        return _response(404, {"error": "Not found"})

    except Exception as e:
        logger.error(f"Unhandled error: {e}", exc_info=True)
        return _response(500, {"error": "Internal server error"})

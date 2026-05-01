import gzip
import importlib
import json
import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue")

with patch("boto3.client"):
    import lambda_function
    from lambda_function import (
        fetch_s3_object,
        guardduty_severity_to_level,
        normalize_finding,
        parse_guardduty_findings,
        process_guardduty_findings,
    )


def _finding(**overrides):
    base = {
        "schemaVersion": "2.0",
        "accountId": "123456789012",
        "region": "us-east-1",
        "id": "finding-1",
        "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/d/finding/finding-1",
        "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": "AKIAEXAMPLE",
                "principalId": "AIDAEXAMPLE",
                "userType": "IAMUser",
                "userName": "alice",
            },
        },
        "service": {
            "serviceName": "guardduty",
            "detectorId": "detector-1",
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "ConsoleLogin",
                    "serviceName": "signin.amazonaws.com",
                    "remoteIpDetails": {"ipAddressV4": "198.51.100.10"},
                },
            },
            "eventFirstSeen": "2026-04-28T20:03:10.000Z",
            "eventLastSeen": "2026-04-28T20:03:11.000Z",
            "archived": False,
            "count": 1,
        },
        "severity": 5,
        "createdAt": "2026-04-28T20:03:10.861Z",
        "updatedAt": "2026-04-28T20:03:11.861Z",
        "title": "API invoked from malicious IP",
        "description": "The API was invoked from a malicious IP.",
    }
    base.update(overrides)
    return base


def test_parse_guardduty_jsonl_records():
    content = "\n".join(json.dumps(item) for item in [_finding(id="one"), _finding(id="two")])

    findings = parse_guardduty_findings(content)

    assert [finding["id"] for finding in findings] == ["one", "two"]


def test_fetch_s3_object_decompresses_jsonl_gzip():
    compressed = gzip.compress(json.dumps(_finding()).encode("utf-8"))
    fake_s3 = Mock()
    fake_s3.get_object.return_value = {"Body": Mock(read=Mock(return_value=compressed))}

    with patch.object(lambda_function, "s3_client", fake_s3):
        content = fetch_s3_object("bucket", "finding.jsonl.gz")

    assert "UnauthorizedAccess:IAMUser" in content


def test_guardduty_severity_mapping():
    assert guardduty_severity_to_level(8) == "high"
    assert guardduty_severity_to_level(5) == "medium"
    assert guardduty_severity_to_level(2) == "low"
    assert guardduty_severity_to_level(0) == "info"


def test_normalize_finding_extracts_alert_contract_fields():
    event, rule = normalize_finding(_finding())

    assert event["sigmaEventSource"] == "GuardDuty"
    assert event["eventSource"] == "guardduty.amazonaws.com"
    assert event["eventName"] == "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
    assert event["eventTime"] == "2026-04-28T20:03:11.000Z"
    assert event["actor"] == "alice"
    assert event["sourceIPAddress"] == "198.51.100.10"
    assert event["target"] == "AKIAEXAMPLE"
    assert rule["id"] == "guardduty:UnauthorizedAccess:IAMUser/MaliciousIPCaller"
    assert rule["level"] == "medium"
    assert rule["logsource"]["service"] == "guardduty"


def test_process_guardduty_findings_batches_to_sqs_and_skips_archived(monkeypatch):
    monkeypatch.setattr(lambda_function, "INCLUDE_ARCHIVED", False)
    monkeypatch.setattr(lambda_function, "MIN_SEVERITY", 0)
    fake_sqs = Mock()
    fake_sqs.send_message_batch.return_value = {"Successful": [{"Id": "1"}], "Failed": []}
    content = "\n".join([
        json.dumps(_finding(id="active")),
        json.dumps(_finding(id="archived", service={"archived": True})),
    ])

    with patch.object(lambda_function, "sqs", fake_sqs):
        metrics = process_guardduty_findings(content)

    assert metrics["findings_count"] == 2
    assert metrics["findings_sent"] == 1
    assert metrics["findings_skipped_archived"] == 1
    fake_sqs.send_message_batch.assert_called_once()


def test_process_guardduty_findings_applies_min_severity(monkeypatch):
    monkeypatch.setattr(lambda_function, "MIN_SEVERITY", 7)
    fake_sqs = Mock()
    content = "\n".join([json.dumps(_finding(id="low", severity=2)), json.dumps(_finding(id="high", severity=8))])

    with patch.object(lambda_function, "sqs", fake_sqs):
        fake_sqs.send_message_batch.return_value = {"Failed": []}
        metrics = process_guardduty_findings(content)

    assert metrics["findings_sent"] == 1
    assert metrics["findings_skipped_severity"] == 1
import json
import os
import sys
from pathlib import Path

import pytest


os.environ.setdefault("RULES_BUCKET", "test-rules-bucket")
os.environ.setdefault("DYNAMODB_TABLE_NAME", "test-security-events")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "lambda_code" / "dashboard_api"))

import lambda_function as dashboard_api  # noqa: E402


class FakeTable:
    def __init__(self, pages=None):
        self.pages = list(pages or [])
        self.query_calls = []
        self.scan_calls = []

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        if not self.pages:
            return {"Items": [], "ScannedCount": 0}
        return self.pages.pop(0)

    def scan(self, **kwargs):
        self.scan_calls.append(kwargs)
        raise AssertionError("Recent dashboard alert loading should not use DynamoDB scan")


class FakeS3Body:
    def __init__(self, content):
        self.content = content.encode("utf-8")

    def read(self):
        return self.content


class FakeS3Paginator:
    def __init__(self, fake_s3):
        self.fake_s3 = fake_s3

    def paginate(self, Bucket, Prefix):
        contents = []
        for key, obj in self.fake_s3.objects.items():
            if key.startswith(Prefix):
                contents.append({
                    "Key": key,
                    "LastModified": obj["LastModified"],
                    "Size": len(obj["Body"]),
                    "ETag": '"fake-etag"',
                })
        return [{"Contents": contents}]


class FakeS3:
    def __init__(self, objects):
        self.objects = objects

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return FakeS3Paginator(self)

    def get_object(self, Bucket, Key, VersionId=None):
        if Key not in self.objects:
            raise dashboard_api.ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        obj = self.objects[Key]
        return {
            "Body": FakeS3Body(obj["Body"]),
            "LastModified": obj["LastModified"],
            "VersionId": obj.get("VersionId", "v1"),
        }

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise dashboard_api.ClientError({"Error": {"Code": "404"}}, "HeadObject")
        obj = self.objects[Key]
        return {"LastModified": obj["LastModified"], "VersionId": obj.get("VersionId", "v1")}

    def put_object(self, Bucket, Key, Body, ContentType=None, ServerSideEncryption=None):
        self.objects[Key] = {
            "Body": Body.decode("utf-8") if isinstance(Body, bytes) else Body,
            "LastModified": dashboard_api.datetime.now(dashboard_api.timezone.utc),
            "VersionId": "v-put",
        }

    def copy_object(self, Bucket, Key, CopySource, MetadataDirective=None, ServerSideEncryption=None):
        source_key = CopySource["Key"]
        if source_key not in self.objects:
            raise dashboard_api.ClientError({"Error": {"Code": "NoSuchKey"}}, "CopyObject")
        self.objects[Key] = dict(self.objects[source_key])
        self.objects[Key]["VersionId"] = "v-copy"

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)


@pytest.fixture
def decode_body():
    def _decode(response):
        return json.loads(response["body"])
    return _decode


def test_get_alerts_uses_recent_first_query_for_dashboard(monkeypatch, decode_body):
    fake_table = FakeTable(
        pages=[
            {
                "Items": [
                    {"pk": "EVENT", "sk": "2026-04-04T12:00:00#b", "timestamp": "2026-04-04T12:00:00", "severity": "high"},
                    {"pk": "EVENT", "sk": "2026-04-04T11:00:00#a", "timestamp": "2026-04-04T11:00:00", "severity": "medium"},
                ],
                "ScannedCount": 2,
            }
        ]
    )
    monkeypatch.setattr(dashboard_api, "_get_table", lambda: fake_table)

    response = dashboard_api.get_alerts({"limit": "2", "hours": "24"})
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert len(body["alerts"]) == 2
    assert fake_table.scan_calls == []
    assert len(fake_table.query_calls) == 1
    assert fake_table.query_calls[0]["IndexName"] == "recentAlertsIndex"
    assert fake_table.query_calls[0]["ExpressionAttributeValues"][":pk"] == "EVENT"
    assert "#ts >= :start" in fake_table.query_calls[0]["KeyConditionExpression"]
    assert fake_table.query_calls[0]["ScanIndexForward"] is False


def test_get_alerts_continues_loading_until_limit_is_filled(monkeypatch, decode_body):
    fake_table = FakeTable(
        pages=[
            {
                "Items": [
                    {"pk": "EVENT", "sk": "2026-04-04T12:00:00#1", "timestamp": "2026-04-04T12:00:00", "severity": "high", "sigmaRuleTitle": "Suspicious Console Login"}
                ],
                "ScannedCount": 25,
                "LastEvaluatedKey": {"pk": "EVENT", "sk": "2026-04-04T12:00:00#1"},
            },
            {
                "Items": [
                    {"pk": "EVENT", "sk": "2026-04-04T11:59:00#2", "timestamp": "2026-04-04T11:59:00", "severity": "high", "sigmaRuleTitle": "Suspicious Console Login"}
                ],
                "ScannedCount": 20,
                "LastEvaluatedKey": {"pk": "EVENT", "sk": "2026-04-04T11:59:00#2"},
            },
        ]
    )
    monkeypatch.setattr(dashboard_api, "_get_table", lambda: fake_table)

    response = dashboard_api.get_alerts(
        {
            "limit": "2",
            "hours": "24",
            "rule": "Suspicious Console Login",
            "severity": "high",
        }
    )
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert len(body["alerts"]) == 2
    assert len(fake_table.query_calls) == 2
    assert fake_table.query_calls[0]["Limit"] > 2
    assert body["nextToken"] == json.dumps({"pk": "EVENT", "sk": "2026-04-04T11:59:00#2"})


def test_get_alerts_can_filter_by_source(monkeypatch, decode_body):
    fake_table = FakeTable(
        pages=[
            {
                "Items": [
                    {"pk": "EVENT", "sk": "2026-04-04T12:00:00#1", "timestamp": "2026-04-04T12:00:00", "sourceType": "guardduty"}
                ],
                "ScannedCount": 1,
            }
        ]
    )
    monkeypatch.setattr(dashboard_api, "_get_table", lambda: fake_table)

    response = dashboard_api.get_alerts({"limit": "10", "hours": "24", "source": "guardduty"})
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert len(body["alerts"]) == 1
    assert fake_table.query_calls[0]["IndexName"] == "sourceTypeIndex"
    assert fake_table.query_calls[0]["ExpressionAttributeValues"][":source"] == "guardduty"


def test_get_alert_stats_uses_event_query_instead_of_scanning_all_items(monkeypatch, decode_body):
    fake_table = FakeTable(
        pages=[
            {
                "Items": [
                    {"pk": "EVENT", "timestamp": "2026-04-04T12:00:00", "severity": "high", "sigmaRuleTitle": "Suspicious Console Login", "sourceType": "cloudtrail"},
                    {"pk": "EVENT", "timestamp": "2026-04-04T11:00:00", "severity": "medium", "sigmaRuleTitle": "IAM User Created", "sourceType": "guardduty"},
                ],
                "ScannedCount": 2,
            }
        ]
    )
    monkeypatch.setattr(dashboard_api, "_get_table", lambda: fake_table)

    response = dashboard_api.get_alert_stats({"hours": "24"})
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert body["totalAlerts"] == 2
    assert body["topRules"] == [
        {"rule": "Suspicious Console Login", "count": 1, "severity": "high"},
        {"rule": "IAM User Created", "count": 1, "severity": "medium"},
    ]
    assert body["bySource"] == {"cloudtrail": 1, "guardduty": 1}
    assert len(fake_table.query_calls) == 1
    assert fake_table.query_calls[0]["IndexName"] == "recentAlertsIndex"
    assert fake_table.query_calls[0]["ExpressionAttributeValues"][":pk"] == "EVENT"
    assert "#ts BETWEEN :start AND :end" in fake_table.query_calls[0]["KeyConditionExpression"]
    assert "trend" not in body
    assert "comparisons" not in body


def test_get_alert_stats_can_include_trend_and_comparisons(monkeypatch, decode_body):
    now = dashboard_api.datetime.now(dashboard_api.timezone.utc).replace(tzinfo=None)
    fake_table = FakeTable(
        pages=[
            {
                "Items": [
                    {"pk": "EVENT", "timestamp": (now - dashboard_api.timedelta(hours=1)).isoformat(), "severity": "critical", "sigmaRuleTitle": "Root Login"},
                    {"pk": "EVENT", "timestamp": (now - dashboard_api.timedelta(hours=3)).isoformat(), "severity": "high", "sigmaRuleTitle": "Suspicious Console Login"},
                ],
                "ScannedCount": 2,
            },
            {
                "Items": [
                    {"pk": "EVENT", "timestamp": (now - dashboard_api.timedelta(hours=25)).isoformat(), "severity": "high", "sigmaRuleTitle": "Suspicious Console Login"},
                ],
                "ScannedCount": 1,
            },
            {
                "Items": [
                    {"pk": "EVENT", "timestamp": (now - dashboard_api.timedelta(days=7, hours=1)).isoformat(), "severity": "critical", "sigmaRuleTitle": "Root Login"},
                ],
                "ScannedCount": 1,
            },
        ]
    )
    monkeypatch.setattr(dashboard_api, "_get_table", lambda: fake_table)

    response = dashboard_api.get_alert_stats({"hours": "24", "includeTrend": "true", "includeComparisons": "true"})
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert body["totalAlerts"] == 2
    assert len(body["trend"]) == 24
    assert sum(bucket["count"] for bucket in body["trend"]) == 2
    assert body["comparisons"]["previous24h"]["totalAlerts"] == 1
    assert body["comparisons"]["previousWeek"]["totalAlerts"] == 1
    assert len(fake_table.query_calls) == 3
    assert fake_table.scan_calls == []
    assert all(call["ExpressionAttributeValues"][":pk"] == "EVENT" for call in fake_table.query_calls)


def test_validate_rule_returns_inline_yaml_error(decode_body):
        response = dashboard_api.validate_rule("title: Bad\nlogsource: [\n")
        body = decode_body(response)

        assert response["statusCode"] == 200
        assert body["valid"] is False
        assert body["errors"][0]["line"] >= 1
        assert "Invalid YAML" in body["errors"][0]["message"]


def test_test_rule_matches_sample_event(decode_body):
        content = """
title: IAM User Created
id: test-rule
status: experimental
level: medium
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: iam.amazonaws.com
        eventName: CreateUser
    condition: selection
"""
        payload = {
                "content": content,
                "sampleEvent": {
                        "eventSource": "iam.amazonaws.com",
                        "eventName": "CreateUser",
                },
        }

        response = dashboard_api.test_rule(json.dumps(payload))
        body = decode_body(response)

        assert response["statusCode"] == 200
        assert body["valid"] is True
        assert body["matched"] is True
        assert body["evaluatedBlocks"][0]["block"] == "selection"


def test_validate_postprocessing_returns_inline_json_error(decode_body):
    response = dashboard_api.validate_postprocessing('{"type": "threshold",')
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert body["valid"] is False
    assert body["errors"][0]["line"] == 1
    assert "Invalid JSON" in body["errors"][0]["message"]


def test_validate_postprocessing_accepts_single_rule_with_warning(decode_body):
    payload = {
        "type": "threshold",
        "sigmaRuleTitle": "IAM User Created",
        "thresholdCount": 5,
        "windowMinutes": 10,
        "adjustSeverity": "critical",
    }

    response = dashboard_api.validate_postprocessing(json.dumps(payload))
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert body["valid"] is True
    assert body["metadata"]["thresholdCount"] == 1
    assert body["warnings"]


def test_validate_exceptions_returns_inline_json_error(decode_body):
    response = dashboard_api.validate_exceptions('{"Suspicious Rule":')
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert body["valid"] is False
    assert body["errors"][0]["line"] == 1
    assert "Invalid JSON" in body["errors"][0]["message"]


def test_validate_exceptions_rejects_bad_regex(decode_body):
    payload = {
        "Suspicious Console Login": {
            "excludedActors": ["arn:aws:iam::123456789012:user/admin"],
            "excludedSourceIPs": ["203.0.113.10"],
            "excludedActorsRegex": ["[broken"],
        }
    }

    response = dashboard_api.validate_exceptions(json.dumps(payload))
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert body["valid"] is False
    assert body["metadata"]["actorCount"] == 1
    assert "Invalid regex" in body["errors"][0]["message"]


def test_list_rules_includes_disabled_prefix_state(monkeypatch, decode_body):
    last_modified = dashboard_api.datetime(2026, 4, 4, 12, 0, tzinfo=dashboard_api.timezone.utc)
    fake_s3 = FakeS3({
        "sigma_rules/active.yaml": {
            "Body": "title: Active Rule\nstatus: stable\nlevel: high\ndetection:\n  selection:\n    eventName: CreateUser\n  condition: selection\n",
            "LastModified": last_modified,
        },
        "disabled_sigma_rules/disabled.yaml": {
            "Body": "title: Disabled Rule\nstatus: experimental\nlevel: medium\ndetection:\n  selection:\n    eventName: DeleteUser\n  condition: selection\n",
            "LastModified": last_modified,
        },
    })
    monkeypatch.setattr(dashboard_api, "s3", fake_s3)

    response = dashboard_api.list_rules()
    body = decode_body(response)

    assert response["statusCode"] == 200
    rules_by_key = {rule["key"]: rule for rule in body["rules"]}
    assert rules_by_key["active.yaml"]["enabled"] is True
    assert rules_by_key["active.yaml"]["prefix"] == "sigma_rules/"
    assert rules_by_key["disabled.yaml"]["enabled"] is False
    assert rules_by_key["disabled.yaml"]["prefix"] == "disabled_sigma_rules/"


def test_set_rule_enabled_moves_between_s3_prefixes(monkeypatch, decode_body):
    last_modified = dashboard_api.datetime(2026, 4, 4, 12, 0, tzinfo=dashboard_api.timezone.utc)
    fake_s3 = FakeS3({
        "sigma_rules/move-me.yaml": {
            "Body": "title: Move Me\nstatus: stable\nlevel: high\ndetection:\n  selection:\n    eventName: CreateUser\n  condition: selection\n",
            "LastModified": last_modified,
        },
    })
    monkeypatch.setattr(dashboard_api, "s3", fake_s3)

    response = dashboard_api.set_rule_enabled("move-me.yaml", json.dumps({"enabled": False}))
    body = decode_body(response)

    assert response["statusCode"] == 200
    assert body["enabled"] is False
    assert "sigma_rules/move-me.yaml" not in fake_s3.objects
    assert "disabled_sigma_rules/move-me.yaml" in fake_s3.objects

    get_response = dashboard_api.get_rule("move-me.yaml", enabled=False)
    get_body = decode_body(get_response)

    assert get_response["statusCode"] == 200
    assert get_body["enabled"] is False
    assert get_body["key"] == "move-me.yaml"

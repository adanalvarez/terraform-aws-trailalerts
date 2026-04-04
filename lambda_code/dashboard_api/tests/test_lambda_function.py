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


def test_get_alert_stats_uses_event_query_instead_of_scanning_all_items(monkeypatch, decode_body):
    fake_table = FakeTable(
        pages=[
            {
                "Items": [
                    {"pk": "EVENT", "timestamp": "2026-04-04T12:00:00", "severity": "high", "sigmaRuleTitle": "Suspicious Console Login"},
                    {"pk": "EVENT", "timestamp": "2026-04-04T11:00:00", "severity": "medium", "sigmaRuleTitle": "IAM User Created"},
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
    assert len(fake_table.query_calls) == 1
    assert fake_table.query_calls[0]["IndexName"] == "recentAlertsIndex"
    assert fake_table.query_calls[0]["ExpressionAttributeValues"][":pk"] == "EVENT"
    assert "#ts >= :start" in fake_table.query_calls[0]["KeyConditionExpression"]

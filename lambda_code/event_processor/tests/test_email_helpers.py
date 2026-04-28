import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloudtrail_helpers import generate_cloudtrail_information_section
from email_helpers import (
    generate_email_html,
    generate_sigma_rule_section,
    ses_send_email,
    sns_send_email,
)
from ip_helpers import format_ip_information
from styles import generate_style


def _event():
    return {
        "sigmaEventSource": "CloudTrail",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "eventTime": "2025-01-15T10:30:00Z",
        "eventID": "event-123",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {
            "arn": "arn:aws:iam::123456789012:user/alice",
            "principalId": "AIDAEXAMPLE",
            "accountId": "123456789012",
        },
    }


def _rule():
    return {
        "title": "Console login without MFA",
        "id": "rule-123",
        "level": "high",
        "description": "Detects <sensitive> sign-in activity",
    }


def test_email_html_uses_brand_header_and_alert_title():
    html = generate_email_html("<style></style>", ["<div>section</div>"], "S3 bucket versioning disabled")

    assert "trailalerts &middot; alert" in html
    assert "S3 bucket versioning disabled" in html
    assert "CloudTrail Alert" not in html


def test_style_uses_brand_email_tokens_and_severity_pills():
    style = generate_style()

    assert "#E2F1F8" in style
    assert "#023047" in style
    assert "max-width: 600px" in style
    assert ".severity-pill" in style
    assert "#fde2d4" in style
    assert "JetBrains+Mono" in style


def test_sigma_section_uses_canonical_severity_and_mono_rule_id():
    section = generate_sigma_rule_section(_rule())

    assert "severity-pill severity-high" in section
    assert ">High</span>" in section
    assert "value value-mono" in section
    assert "Detects &lt;sensitive&gt; sign-in activity" in section


def test_ses_send_email_uses_brand_subject_and_text_fallback():
    fake_ses = Mock()
    fake_ses.send_email.return_value = {"MessageId": "message-123"}

    with patch("email_helpers.boto3.client", return_value=fake_ses):
        sent = ses_send_email(
            "<html></html>",
            _event(),
            "alerts@example.com",
            "security@example.com",
            _rule(),
            correlated_events=[{"sigmaRuleTitle": "Related rule"}],
            threshold_info={"eventCount": 3, "thresholdCount": 2, "windowMinutes": 10},
        )

    assert sent is True
    message = fake_ses.send_email.call_args.kwargs["Message"]
    subject = message["Subject"]["Data"]

    assert subject == "TrailAlerts - High - Console login without MFA - correlated activity - threshold activity"
    assert "TRAILALERTS" not in subject
    assert "[" not in subject
    assert "Text" in message["Body"]
    assert "TrailAlerts alert" in message["Body"]["Text"]["Data"]


def test_sns_send_email_uses_calm_brand_copy():
    fake_sns = Mock()
    fake_sns.publish.return_value = {"MessageId": "message-123"}

    with patch("email_helpers.boto3.client", return_value=fake_sns):
        sent = sns_send_email(
            "arn:aws:sns:us-east-1:123456789012:alerts",
            _event(),
            correlated_events=[{"sigmaRuleTitle": "Related rule"}],
            threshold_info={"eventCount": 3, "thresholdCount": 2, "windowMinutes": 10},
            rule_metadata=_rule(),
        )

    assert sent is True
    publish_args = fake_sns.publish.call_args.kwargs

    assert publish_args["Subject"].startswith("TrailAlerts - High")
    assert "[" not in publish_args["Subject"]
    assert "TRAILALERTS" not in publish_args["Subject"]
    assert "CORRELATED" not in publish_args["Message"]
    assert "THRESHOLD EXCEEDED" not in publish_args["Message"]
    assert "\u26a0" not in publish_args["Message"]


def test_cloudtrail_section_keeps_only_evidence_fields():
    section = generate_cloudtrail_information_section(_event())

    assert "CloudTrail Evidence" in section
    assert "Event ID" in section
    assert "User ARN" in section
    assert "View in CloudTrail Console" in section
    assert "Event Time" not in section
    assert "AWS Account" not in section
    assert "CloudTrail Information" not in section


def test_ip_information_escapes_external_api_values():
    section = format_ip_information(
        "203.0.113.10",
        {
            "ip": "203.0.113.10<script>",
            "security": {"vpn": True},
            "location": {
                "country": "<Country>",
                "city": "Example<script>",
                "region": "Region",
                "continent": "North America",
                "latitude": "10<script>",
                "longitude": "20",
                "time_zone": "UTC<script>",
                "is_in_european_union": False,
            },
            "network": {
                "network": "203.0.113.0/24<script>",
                "autonomous_system_organization": "Bad <Org>",
                "autonomous_system_number": "64500",
            },
        },
    )

    assert "&lt;Country&gt;" in section
    assert "203.0.113.10&lt;script&gt;" in section
    assert "Bad &lt;Org&gt;" in section
    assert "<script>" not in section
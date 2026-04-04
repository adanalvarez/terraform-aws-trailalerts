import importlib
import json
import os
import sys
from unittest.mock import Mock, patch

import pytest

# Ensure the parent package is importable without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(autouse=True)
def _required_env(monkeypatch):
    monkeypatch.setenv("SOURCE_EMAIL", "alerts@example.com")
    monkeypatch.setenv("EMAIL_RECIPIENT", "security@example.com")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def _load_lambda_module():
    sys.modules.pop("lambda_function", None)

    fake_dynamodb = Mock()
    fake_dynamodb.Table.return_value = Mock()

    with patch("boto3.resource", return_value=fake_dynamodb):
        module = importlib.import_module("lambda_function")
        return importlib.reload(module)


def _sqs_record(message_id, body):
    return {
        "messageId": message_id,
        "eventSource": "aws:sqs",
        "body": json.dumps(body),
    }


def _message_body(event_name="ConsoleLogin"):
    return {
        "sigma_rule_title": "Console Login Detection",
        "sigma_rule_id": "rule-123",
        "matched_event": {
            "eventName": event_name,
            "eventSource": "signin.amazonaws.com",
            "sigmaEventSource": "CloudTrail",
            "eventTime": "2025-01-15T10:30:00Z",
            "sourceIPAddress": "203.0.113.10",
        },
    }


def test_lambda_handler_returns_partial_batch_failures_for_failed_sqs_records():
    module = _load_lambda_module()
    event = {
        "Records": [
            _sqs_record("ok-1", _message_body("ConsoleLogin")),
            _sqs_record("bad-1", _message_body("DeleteTrail")),
        ]
    }

    with patch.object(module, "register_plugins"), patch.object(
        module,
        "process_event",
        side_effect=[None, RuntimeError("boom")],
    ):
        response = module.lambda_handler(event, None)

    assert response == {
        "batchItemFailures": [{"itemIdentifier": "bad-1"}]
    }


def test_lambda_handler_marks_invalid_messages_as_failed_for_retry():
    module = _load_lambda_module()
    event = {
        "Records": [
            _sqs_record(
                "bad-2",
                {
                    "sigma_rule_title": "Broken Message",
                    "sigma_rule_id": "rule-999",
                },
            )
        ]
    }

    with patch.object(module, "register_plugins"), patch.object(module, "process_event"):
        response = module.lambda_handler(event, None)

    assert response == {
        "batchItemFailures": [{"itemIdentifier": "bad-2"}]
    }

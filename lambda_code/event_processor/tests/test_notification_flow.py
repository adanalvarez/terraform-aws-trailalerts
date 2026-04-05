import importlib
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


def _event():
    return {
        "sigmaEventSource": "CloudTrail",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "eventTime": "2025-01-15T10:30:00Z",
        "sourceIPAddress": "203.0.113.10",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/test"},
    }


def _rule():
    return {
        "title": "Test Rule",
        "id": "rule-123",
        "level": "high",
    }


def _config():
    return {
        "source_email": "alerts@example.com",
        "destination_email": "security@example.com",
        "sns_topic": None,
        "api_key": None,
        "correlation_enabled": "false",
    }


def _plugin():
    plugin = Mock()
    plugin.get_plugin_name.return_value = "fake-plugin"
    plugin.get_event_type.return_value = "CloudTrail"
    plugin.extract_actor.return_value = "arn:aws:iam::123:user/test"
    plugin.get_event_details.return_value = {}
    return plugin


def test_process_event_updates_notification_time_after_successful_send():
    module = _load_lambda_module()
    helper = Mock()
    helper.should_send_notification.return_value = True

    module.dynamodb_table = Mock()
    module.dynamodb_helper = Mock()

    with patch.object(module.plugin_registry, "get_plugin_for_event", return_value=_plugin()), \
         patch.object(module, "determine_event_type", return_value="regular"), \
         patch.object(module, "should_send_notification", return_value=True), \
         patch.object(module, "send_notifications", return_value=True) as send_mock, \
         patch.object(module, "NotificationHelper", return_value=helper):
        module.process_event(_event(), _rule(), _config())

    send_mock.assert_called_once()
    helper.update_notification_time.assert_called_once_with("Test Rule")


def test_process_event_does_not_update_notification_time_when_send_fails():
    module = _load_lambda_module()
    helper = Mock()
    helper.should_send_notification.return_value = True

    module.dynamodb_table = Mock()
    module.dynamodb_helper = Mock()

    with patch.object(module.plugin_registry, "get_plugin_for_event", return_value=_plugin()), \
         patch.object(module, "determine_event_type", return_value="regular"), \
         patch.object(module, "should_send_notification", return_value=True), \
         patch.object(module, "send_notifications", return_value=False), \
         patch.object(module, "NotificationHelper", return_value=helper):
        module.process_event(_event(), _rule(), _config())

    helper.update_notification_time.assert_not_called()

"""
Tests for bidirectional correlation: verifies that correlations are detected
regardless of which event (sigmaRuleTitle or lookFor target) arrives first.
"""

import importlib
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta, timezone

import pytest

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


def _plugin():
    plugin = Mock()
    plugin.get_plugin_name.return_value = "fake-plugin"
    plugin.get_event_type.return_value = "CloudTrail"
    plugin.extract_actor.return_value = "arn:aws:iam::123:user/test"
    plugin.get_event_details.return_value = {}
    return plugin


# ---------------------------------------------------------------------------
# CorrelationHelper unit tests
# ---------------------------------------------------------------------------

class TestIsLookforTarget:
    def test_returns_true_when_rule_is_lookfor_target(self):
        from correlation_helpers import CorrelationHelper
        helper = CorrelationHelper.__new__(CorrelationHelper)
        helper.correlation_rules_cache = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B", "windowMinutes": 60}
        ]
        helper.etag_hash = "cached"
        helper.s3_client = Mock()
        helper.bucket_name = "test"

        with patch.object(helper, "_refresh_cache_if_needed"):
            assert helper.is_lookfor_target("Rule B") is True

    def test_returns_false_when_rule_is_not_lookfor_target(self):
        from correlation_helpers import CorrelationHelper
        helper = CorrelationHelper.__new__(CorrelationHelper)
        helper.correlation_rules_cache = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B", "windowMinutes": 60}
        ]
        helper.etag_hash = "cached"
        helper.s3_client = Mock()
        helper.bucket_name = "test"

        with patch.object(helper, "_refresh_cache_if_needed"):
            assert helper.is_lookfor_target("Rule C") is False

    def test_returns_false_when_cache_empty(self):
        from correlation_helpers import CorrelationHelper
        helper = CorrelationHelper.__new__(CorrelationHelper)
        helper.correlation_rules_cache = []
        helper.etag_hash = "cached"
        helper.s3_client = Mock()
        helper.bucket_name = "test"

        with patch.object(helper, "_refresh_cache_if_needed"):
            assert helper.is_lookfor_target("Rule B") is False


class TestFindReverseCorrelations:
    def _make_helper(self, rules):
        from correlation_helpers import CorrelationHelper
        helper = CorrelationHelper.__new__(CorrelationHelper)
        helper.correlation_rules_cache = rules
        helper.etag_hash = "cached"
        helper.s3_client = Mock()
        helper.bucket_name = "test"
        return helper

    def test_finds_triggering_rule_in_dynamodb(self):
        """When lookFor target arrives and triggering rule is already stored."""
        rules = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B",
             "windowMinutes": 60, "severity_adjustment": "critical"}
        ]
        helper = self._make_helper(rules)

        table = Mock()
        table.query.return_value = {
            "Items": [{"sigmaRuleTitle": "Rule A", "timestamp": "2025-01-15T10:00:00+00:00"}]
        }

        event = {"eventTime": "2025-01-15T10:30:00Z"}
        rule = {"title": "Rule B"}

        with patch.object(helper, "_refresh_cache_if_needed"):
            matches = helper.find_reverse_correlations(event, rule, table)

        assert len(matches) == 1
        assert matches[0]["severity_adjustment"] == "critical"
        assert matches[0]["correlated_events"][0]["sigmaRuleTitle"] == "Rule A"

    def test_no_match_when_triggering_rule_not_stored(self):
        rules = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B",
             "windowMinutes": 60, "severity_adjustment": "high"}
        ]
        helper = self._make_helper(rules)

        table = Mock()
        table.query.return_value = {"Items": []}

        event = {"eventTime": "2025-01-15T10:30:00Z"}
        rule = {"title": "Rule B"}

        with patch.object(helper, "_refresh_cache_if_needed"):
            matches = helper.find_reverse_correlations(event, rule, table)

        assert len(matches) == 0

    def test_no_match_when_rule_is_not_lookfor_target(self):
        rules = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B",
             "windowMinutes": 60, "severity_adjustment": "high"}
        ]
        helper = self._make_helper(rules)
        table = Mock()

        event = {"eventTime": "2025-01-15T10:30:00Z"}
        rule = {"title": "Rule C"}  # not a lookFor target

        with patch.object(helper, "_refresh_cache_if_needed"):
            matches = helper.find_reverse_correlations(event, rule, table)

        assert len(matches) == 0
        table.query.assert_not_called()

    def test_empty_cache_returns_empty(self):
        helper = self._make_helper([])
        table = Mock()
        event = {"eventTime": "2025-01-15T10:30:00Z"}
        rule = {"title": "Rule B"}

        with patch.object(helper, "_refresh_cache_if_needed"):
            matches = helper.find_reverse_correlations(event, rule, table)

        assert matches == []

    def test_query_uses_correct_time_window(self):
        rules = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B",
             "windowMinutes": 30, "severity_adjustment": "high"}
        ]
        helper = self._make_helper(rules)

        table = Mock()
        table.query.return_value = {"Items": []}

        event = {"eventTime": "2025-01-15T10:30:00Z"}
        rule = {"title": "Rule B"}

        with patch.object(helper, "_refresh_cache_if_needed"):
            helper.find_reverse_correlations(event, rule, table)

        call_kwargs = table.query.call_args[1]
        values = call_kwargs["ExpressionAttributeValues"]
        assert values[":title"] == "Rule A"
        # Window: 10:30 - 30min = 10:00, end = 10:30 + 5s
        assert "10:00:00" in values[":start"]
        assert "10:30:05" in values[":end"]

    def test_dynamodb_error_handled_gracefully(self):
        rules = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B",
             "windowMinutes": 60, "severity_adjustment": "high"}
        ]
        helper = self._make_helper(rules)

        table = Mock()
        table.query.side_effect = Exception("DynamoDB error")

        event = {"eventTime": "2025-01-15T10:30:00Z"}
        rule = {"title": "Rule B"}

        with patch.object(helper, "_refresh_cache_if_needed"):
            matches = helper.find_reverse_correlations(event, rule, table)

        assert matches == []

    def test_multiple_correlation_rules_matched(self):
        """Multiple correlation rules can have the same lookFor target."""
        rules = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B",
             "windowMinutes": 60, "severity_adjustment": "high"},
            {"type": "correlation", "sigmaRuleTitle": "Rule C", "lookFor": "Rule B",
             "windowMinutes": 60, "severity_adjustment": "critical"},
        ]
        helper = self._make_helper(rules)

        table = Mock()
        table.query.return_value = {
            "Items": [{"sigmaRuleTitle": "found", "timestamp": "2025-01-15T10:00:00+00:00"}]
        }

        event = {"eventTime": "2025-01-15T10:30:00Z"}
        rule = {"title": "Rule B"}

        with patch.object(helper, "_refresh_cache_if_needed"):
            matches = helper.find_reverse_correlations(event, rule, table)

        assert len(matches) == 2


# ---------------------------------------------------------------------------
# Integration: process_event with reverse correlation
# ---------------------------------------------------------------------------

class TestReverseCorrelationInProcessEvent:
    def test_reverse_correlation_triggers_for_regular_event(self):
        """A regular event that is a lookFor target should trigger reverse correlation."""
        module = _load_lambda_module()

        module.dynamodb_table = Mock()
        module.dynamodb_helper = Mock()
        module.correlation_helper = Mock()
        module.correlation_helper.has_matching_rule.return_value = False
        module.correlation_helper.is_lookfor_target.return_value = True
        module.correlation_helper.find_reverse_correlations.return_value = [{
            "rule": {"sigmaRuleTitle": "Rule A", "lookFor": "Rule B"},
            "severity_adjustment": "critical",
            "correlated_events": [{"sigmaRuleTitle": "Rule A", "timestamp": "2025-01-15T10:00:00Z"}]
        }]
        module.threshold_helper = Mock()
        module.threshold_helper.has_matching_rule.return_value = False

        config = {
            "source_email": "a@b.com",
            "destination_email": "c@d.com",
            "correlation_enabled": "true",
        }
        event = {
            "sigmaEventSource": "CloudTrail",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "eventTime": "2025-01-15T10:30:00Z",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/test"},
        }
        rule = {"title": "Rule B", "id": "r-b", "level": "low"}

        with patch.object(module.plugin_registry, "get_plugin_for_event", return_value=_plugin()), \
             patch.object(module, "should_send_notification", return_value=True), \
             patch.object(module, "send_notifications", return_value=True) as send_mock, \
             patch.object(module, "NotificationHelper", return_value=Mock(should_send_notification=Mock(return_value=True))):
            module.process_event(event, rule, config)

        # Severity should have been adjusted by the reverse correlation
        assert rule["level"] == "critical"
        module.correlation_helper.find_reverse_correlations.assert_called_once()
        send_mock.assert_called_once()
        # Correlated events should be passed to the notification
        call_args = send_mock.call_args
        assert call_args[0][3] is not None  # correlated_events argument

    def test_reverse_correlation_skipped_when_forward_found(self):
        """If forward correlation already found matches, don't run reverse."""
        module = _load_lambda_module()

        module.dynamodb_table = Mock()
        module.dynamodb_helper = Mock()
        module.correlation_helper = Mock()
        module.correlation_helper.has_matching_rule.return_value = True
        module.correlation_helper.find_correlations.return_value = [{
            "rule": {"sigmaRuleTitle": "Rule A", "lookFor": "Rule B"},
            "severity_adjustment": "high",
            "correlated_events": [{"sigmaRuleTitle": "Rule B"}]
        }]
        module.threshold_helper = Mock()
        module.threshold_helper.has_matching_rule.return_value = False

        config = {
            "source_email": "a@b.com",
            "destination_email": "c@d.com",
            "correlation_enabled": "true",
        }
        event = {
            "sigmaEventSource": "CloudTrail",
            "eventName": "CreateUser",
            "eventSource": "iam.amazonaws.com",
            "eventTime": "2025-01-15T10:30:00Z",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/test"},
        }
        rule = {"title": "Rule A", "id": "r-a", "level": "medium"}

        with patch.object(module.plugin_registry, "get_plugin_for_event", return_value=_plugin()), \
             patch.object(module, "should_send_notification", return_value=True), \
             patch.object(module, "send_notifications", return_value=True), \
             patch.object(module, "NotificationHelper", return_value=Mock(should_send_notification=Mock(return_value=True))):
            module.process_event(event, rule, config)

        module.correlation_helper.find_reverse_correlations.assert_not_called()

    def test_reverse_correlation_skipped_when_correlation_disabled(self):
        """Reverse correlation should not run when correlation is disabled."""
        module = _load_lambda_module()

        module.dynamodb_table = Mock()
        module.dynamodb_helper = Mock()
        module.correlation_helper = Mock()
        module.threshold_helper = Mock()
        module.threshold_helper.has_matching_rule.return_value = False
        module.correlation_helper.has_matching_rule.return_value = False

        config = {
            "source_email": "a@b.com",
            "destination_email": "c@d.com",
            "correlation_enabled": "false",
        }
        event = {
            "sigmaEventSource": "CloudTrail",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "eventTime": "2025-01-15T10:30:00Z",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/test"},
        }
        rule = {"title": "Rule B", "id": "r-b", "level": "medium"}

        with patch.object(module.plugin_registry, "get_plugin_for_event", return_value=_plugin()), \
             patch.object(module, "should_send_notification", return_value=True), \
             patch.object(module, "send_notifications", return_value=True), \
             patch.object(module, "NotificationHelper", return_value=Mock(should_send_notification=Mock(return_value=True))):
            module.process_event(event, rule, config)

        module.correlation_helper.find_reverse_correlations.assert_not_called()

    def test_lookfor_target_stored_as_correlation_record(self):
        """Regular events that are lookFor targets should also be stored as correlation type."""
        module = _load_lambda_module()

        module.dynamodb_table = Mock()
        module.dynamodb_helper = Mock()
        module.correlation_helper = Mock()
        module.correlation_helper.has_matching_rule.return_value = False
        module.correlation_helper.is_lookfor_target.return_value = True
        module.correlation_helper.find_reverse_correlations.return_value = []
        module.threshold_helper = Mock()
        module.threshold_helper.has_matching_rule.return_value = False

        config = {
            "source_email": "a@b.com",
            "destination_email": "c@d.com",
            "correlation_enabled": "true",
        }
        event = {
            "sigmaEventSource": "CloudTrail",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "eventTime": "2025-01-15T10:30:00Z",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/test"},
        }
        rule = {"title": "Rule B", "id": "r-b", "level": "low"}

        with patch.object(module.plugin_registry, "get_plugin_for_event", return_value=_plugin()), \
             patch.object(module, "should_send_notification", return_value=False), \
             patch.object(module, "NotificationHelper", return_value=Mock(should_send_notification=Mock(return_value=False))):
            module.process_event(event, rule, config)

        # Should have been stored twice: once as correlation, once as regular (dashboard)
        store_calls = module.dynamodb_helper.store_event.call_args_list
        event_types = [call[1].get("event_type") or call[0][2] for call in store_calls]
        assert "correlation" in event_types
        assert "regular" in event_types

    def test_reverse_correlation_only_raises_severity(self):
        """Reverse correlation should not lower severity if current is already higher."""
        module = _load_lambda_module()

        module.dynamodb_table = Mock()
        module.dynamodb_helper = Mock()
        module.correlation_helper = Mock()
        module.correlation_helper.has_matching_rule.return_value = False
        module.correlation_helper.is_lookfor_target.return_value = True
        module.correlation_helper.find_reverse_correlations.return_value = [{
            "rule": {"sigmaRuleTitle": "Rule A", "lookFor": "Rule B"},
            "severity_adjustment": "medium",  # lower than current
            "correlated_events": [{"sigmaRuleTitle": "Rule A"}]
        }]
        module.threshold_helper = Mock()
        module.threshold_helper.has_matching_rule.return_value = False

        config = {
            "source_email": "a@b.com",
            "destination_email": "c@d.com",
            "correlation_enabled": "true",
        }
        event = {
            "sigmaEventSource": "CloudTrail",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "eventTime": "2025-01-15T10:30:00Z",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/test"},
        }
        rule = {"title": "Rule B", "id": "r-b", "level": "high"}

        with patch.object(module.plugin_registry, "get_plugin_for_event", return_value=_plugin()), \
             patch.object(module, "should_send_notification", return_value=True), \
             patch.object(module, "send_notifications", return_value=True), \
             patch.object(module, "NotificationHelper", return_value=Mock(should_send_notification=Mock(return_value=True))):
            module.process_event(event, rule, config)

        # Severity should remain "high" (not downgraded to "medium")
        assert rule["level"] == "high"


# ---------------------------------------------------------------------------
# Cache refresh TTL tests
# ---------------------------------------------------------------------------

class TestCacheRefreshTTL:
    def _make_helper(self):
        from correlation_helpers import CorrelationHelper
        helper = CorrelationHelper.__new__(CorrelationHelper)
        helper.correlation_rules_cache = [
            {"type": "correlation", "sigmaRuleTitle": "Rule A", "lookFor": "Rule B", "windowMinutes": 60}
        ]
        helper.etag_hash = "abc123"
        helper.s3_client = Mock()
        helper.bucket_name = "test"
        helper._last_refresh_check = 0.0
        helper._refresh_ttl_seconds = 5
        return helper

    def test_multiple_calls_within_ttl_trigger_one_etag_check(self):
        """Within the TTL window, _compute_etag_hash should be called only once."""
        helper = self._make_helper()

        with patch.object(helper, "_compute_etag_hash", return_value="abc123") as mock_hash:
            # First call should compute the hash
            helper._refresh_cache_if_needed()
            assert mock_hash.call_count == 1

            # Subsequent calls within TTL should skip the hash check entirely
            helper._refresh_cache_if_needed()
            helper._refresh_cache_if_needed()
            assert mock_hash.call_count == 1

    def test_call_after_ttl_expires_hits_s3_again(self):
        """After TTL expires, _compute_etag_hash should be called again."""
        helper = self._make_helper()
        helper._refresh_ttl_seconds = 0  # expire immediately

        with patch.object(helper, "_compute_etag_hash", return_value="abc123") as mock_hash:
            helper._refresh_cache_if_needed()
            assert mock_hash.call_count == 1

            helper._refresh_cache_if_needed()
            assert mock_hash.call_count == 2

    def test_first_load_always_hits_s3(self):
        """When cache is None, S3 is always called regardless of TTL."""
        helper = self._make_helper()
        helper.correlation_rules_cache = None  # force first load

        with patch.object(helper, "_compute_etag_hash", return_value="newhash") as mock_hash, \
             patch.object(helper, "_load_correlation_rules", return_value=[]) as mock_load:
            helper._refresh_cache_if_needed()
            mock_hash.assert_called_once()
            mock_load.assert_called_once()

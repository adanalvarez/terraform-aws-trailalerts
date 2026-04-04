"""
Tests for lambda_function.py — specifically build_rule_index, get_candidate_rules,
_build_sqs_message, and _flush_sqs_batch.
"""

import pytest
import os
import sys
import json
from unittest.mock import patch, MagicMock

# Ensure the parent package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# We need to mock environment variables and boto3 BEFORE importing the module
# because lambda_function reads env vars and creates clients at module level.
os.environ.setdefault("SQS_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue")
os.environ.setdefault("TRAILALERTS_BUCKET", "test-bucket")

with patch("boto3.client"):
    from lambda_function import (
        build_rule_index,
        get_candidate_rules,
        load_sigma_rules,
        reload_sigma_rules_if_needed,
        _build_sqs_message,
        _flush_sqs_batch,
        MAX_SQS_RETRIES,
    )
    import lambda_function


# ---------------------------------------------------------------------------
# Helpers – rule factories
# ---------------------------------------------------------------------------

def _rule(title, detection, **extra):
    """Build a minimal Sigma-style rule dict."""
    r = {"title": title, "detection": detection}
    r.update(extra)
    return r


def _simple_rule(title, event_source, event_names, condition="selection"):
    """Rule with exact eventSource + eventName (str or list)."""
    return _rule(title, {
        "selection": {"eventSource": event_source, "eventName": event_names},
        "condition": condition,
    })


# ---------------------------------------------------------------------------
# build_rule_index
# ---------------------------------------------------------------------------
class TestBuildRuleIndex:
    """Tests for the Sigma rule indexing logic."""

    def test_single_exact_rule_indexed(self):
        rules = [_simple_rule("R1", "iam.amazonaws.com", "CreateUser")]
        indexed, wildcards = build_rule_index(rules)
        assert ("iam.amazonaws.com", "CreateUser") in indexed
        assert len(wildcards) == 0

    def test_single_rule_list_event_names(self):
        rules = [_simple_rule("R1", "iam.amazonaws.com", ["CreateUser", "DeleteUser"])]
        indexed, wildcards = build_rule_index(rules)
        assert ("iam.amazonaws.com", "CreateUser") in indexed
        assert ("iam.amazonaws.com", "DeleteUser") in indexed
        assert len(wildcards) == 0

    def test_missing_event_source_goes_to_wildcard(self):
        rules = [_rule("R1", {
            "selection": {"eventName": "CreateUser"},
            "condition": "selection",
        })]
        indexed, wildcards = build_rule_index(rules)
        assert len(indexed) == 0
        assert len(wildcards) == 1

    def test_missing_event_name_goes_to_wildcard(self):
        rules = [_rule("R1", {
            "selection": {"eventSource": "iam.amazonaws.com"},
            "condition": "selection",
        })]
        indexed, wildcards = build_rule_index(rules)
        assert len(indexed) == 0
        assert len(wildcards) == 1

    def test_empty_detection_goes_to_wildcard(self):
        rules = [_rule("R1", {})]
        _, wildcards = build_rule_index(rules)
        assert len(wildcards) == 1

    def test_no_detection_key_goes_to_wildcard(self):
        rules = [{"title": "R1"}]
        _, wildcards = build_rule_index(rules)
        assert len(wildcards) == 1

    def test_modifier_on_event_source_goes_to_wildcard(self):
        """Fields with modifiers like |contains should NOT be indexed."""
        rules = [_rule("R1", {
            "selection": {
                "eventSource|contains": "iam",
                "eventName": "CreateUser",
            },
            "condition": "selection",
        })]
        indexed, wildcards = build_rule_index(rules)
        assert len(indexed) == 0
        assert len(wildcards) == 1

    def test_modifier_on_event_name_goes_to_wildcard(self):
        rules = [_rule("R1", {
            "selection": {
                "eventSource": "iam.amazonaws.com",
                "eventName|startswith": "Create",
            },
            "condition": "selection",
        })]
        indexed, wildcards = build_rule_index(rules)
        assert len(indexed) == 0
        assert len(wildcards) == 1

    def test_modifier_re_on_event_name_goes_to_wildcard(self):
        rules = [_rule("R1", {
            "selection": {
                "eventSource": "iam.amazonaws.com",
                "eventName|re": "Create.*",
            },
            "condition": "selection",
        })]
        indexed, wildcards = build_rule_index(rules)
        assert len(indexed) == 0
        assert len(wildcards) == 1

    def test_multiple_detection_blocks_same_source(self):
        """Multiple detection blocks with different eventNames but same eventSource."""
        rules = [_rule("R1", {
            "sel1": {"eventSource": "s3.amazonaws.com", "eventName": "PutObject"},
            "sel2": {"eventSource": "s3.amazonaws.com", "eventName": "DeleteObject"},
            "condition": "sel1 or sel2",
        })]
        indexed, wildcards = build_rule_index(rules)
        assert ("s3.amazonaws.com", "PutObject") in indexed
        assert ("s3.amazonaws.com", "DeleteObject") in indexed
        assert len(wildcards) == 0

    def test_cartesian_product_multiple_sources_and_names(self):
        """Cartesian indexing: 2 sources × 2 names = 4 keys."""
        rules = [_rule("R1", {
            "sel1": {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"},
            "sel2": {"eventSource": "sts.amazonaws.com", "eventName": "AssumeRole"},
            "condition": "sel1 or sel2",
        })]
        indexed, wildcards = build_rule_index(rules)
        assert ("iam.amazonaws.com", "CreateUser") in indexed
        assert ("iam.amazonaws.com", "AssumeRole") in indexed
        assert ("sts.amazonaws.com", "CreateUser") in indexed
        assert ("sts.amazonaws.com", "AssumeRole") in indexed
        assert len(wildcards) == 0

    def test_mixed_indexed_and_wildcard_rules(self):
        rules = [
            _simple_rule("Indexed", "iam.amazonaws.com", "CreateUser"),
            _rule("Wildcard", {"selection": {"sourceIPAddress": "1.2.3.4"}, "condition": "selection"}),
        ]
        indexed, wildcards = build_rule_index(rules)
        assert len(indexed) == 1
        assert len(wildcards) == 1
        assert wildcards[0]["title"] == "Wildcard"

    def test_non_dict_detection_block_skipped(self):
        """Detection blocks that are strings or lists (not dicts) are skipped gracefully."""
        rules = [_rule("R1", {
            "selection": {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"},
            "condition": "selection",
            "timeframe": "5m",  # string value — not a dict, should be skipped
        })]
        indexed, wildcards = build_rule_index(rules)
        assert ("iam.amazonaws.com", "CreateUser") in indexed
        assert len(wildcards) == 0

    def test_empty_rules_list(self):
        indexed, wildcards = build_rule_index([])
        assert indexed == {}
        assert wildcards == []

    def test_rule_with_only_condition_goes_to_wildcard(self):
        rules = [_rule("R1", {"condition": "selection"})]
        _, wildcards = build_rule_index(rules)
        assert len(wildcards) == 1

    def test_event_name_list_with_non_strings_filtered(self):
        """Non-string values in an eventName list should be ignored for indexing."""
        rules = [_rule("R1", {
            "selection": {
                "eventSource": "ec2.amazonaws.com",
                "eventName": ["RunInstances", 42, None, "TerminateInstances"],
            },
            "condition": "selection",
        })]
        indexed, _ = build_rule_index(rules)
        assert ("ec2.amazonaws.com", "RunInstances") in indexed
        assert ("ec2.amazonaws.com", "TerminateInstances") in indexed
        # Non-string values should not appear as keys
        assert not any(k[1] in (42, None) for k in indexed)

    def test_same_rule_indexed_under_multiple_keys(self):
        """A single rule can appear in multiple index buckets."""
        rule = _simple_rule("R1", "iam.amazonaws.com", ["CreateUser", "DeleteUser", "UpdateUser"])
        indexed, _ = build_rule_index([rule])
        for name in ["CreateUser", "DeleteUser", "UpdateUser"]:
            assert rule in indexed[("iam.amazonaws.com", name)]


# ---------------------------------------------------------------------------
# get_candidate_rules
# ---------------------------------------------------------------------------
class TestGetCandidateRules:
    """Tests for candidate rule selection using the pre-built index."""

    def _setup_index(self, rules):
        """Build index and inject into module globals."""
        idx, wc = build_rule_index(rules)
        lambda_function.rule_index = idx
        lambda_function.wildcard_rules = wc

    def test_exact_match_returns_indexed_rule(self):
        rule = _simple_rule("R1", "iam.amazonaws.com", "CreateUser")
        self._setup_index([rule])
        record = {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}
        candidates = get_candidate_rules(record)
        assert rule in candidates

    def test_no_match_returns_only_wildcards(self):
        wc_rule = _rule("WC", {"selection": {"sourceIPAddress": "1.2.3.4"}, "condition": "selection"})
        self._setup_index([
            _simple_rule("R1", "iam.amazonaws.com", "CreateUser"),
            wc_rule,
        ])
        record = {"eventSource": "s3.amazonaws.com", "eventName": "PutObject"}
        candidates = get_candidate_rules(record)
        assert wc_rule in candidates
        assert len(candidates) == 1  # only the wildcard

    def test_wildcard_rules_always_included(self):
        wc_rule = _rule("WC", {"selection": {"sourceIPAddress": "1.2.3.4"}, "condition": "selection"})
        idx_rule = _simple_rule("R1", "iam.amazonaws.com", "CreateUser")
        self._setup_index([idx_rule, wc_rule])
        record = {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}
        candidates = get_candidate_rules(record)
        assert idx_rule in candidates
        assert wc_rule in candidates

    def test_missing_event_source_in_record(self):
        self._setup_index([_simple_rule("R1", "iam.amazonaws.com", "CreateUser")])
        record = {"eventName": "CreateUser"}  # no eventSource
        candidates = get_candidate_rules(record)
        # Key would be ('', 'CreateUser') — no match in index
        assert len(candidates) == 0

    def test_missing_event_name_in_record(self):
        self._setup_index([_simple_rule("R1", "iam.amazonaws.com", "CreateUser")])
        record = {"eventSource": "iam.amazonaws.com"}  # no eventName
        candidates = get_candidate_rules(record)
        assert len(candidates) == 0

    def test_empty_index_returns_only_wildcards(self):
        wc_rule = _rule("WC", {"selection": {"userAgent": "test"}, "condition": "selection"})
        self._setup_index([wc_rule])
        record = {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}
        candidates = get_candidate_rules(record)
        assert candidates == [wc_rule]

    def test_none_index_returns_only_wildcards(self):
        lambda_function.rule_index = None
        lambda_function.wildcard_rules = [{"title": "WC"}]
        candidates = get_candidate_rules({"eventSource": "x", "eventName": "y"})
        assert len(candidates) == 1

    def test_none_wildcard_rules_returns_empty(self):
        lambda_function.rule_index = None
        lambda_function.wildcard_rules = None
        candidates = get_candidate_rules({"eventSource": "x", "eventName": "y"})
        assert candidates == []

    def test_modifier_rule_always_evaluated(self):
        """A rule with |contains on eventSource should be wildcard and always returned."""
        modifier_rule = _rule("ModRule", {
            "selection": {"eventSource|contains": "iam", "eventName": "CreateUser"},
            "condition": "selection",
        })
        self._setup_index([modifier_rule])
        # Even though record matches, the rule is in wildcards, so it should be returned
        record = {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}
        candidates = get_candidate_rules(record)
        assert modifier_rule in candidates
        # Also returned for completely different records
        record2 = {"eventSource": "s3.amazonaws.com", "eventName": "PutObject"}
        candidates2 = get_candidate_rules(record2)
        assert modifier_rule in candidates2


# ---------------------------------------------------------------------------
# load_sigma_rules / reload_sigma_rules_if_needed
# ---------------------------------------------------------------------------
class TestSigmaRuleLoading:
    def test_load_sigma_rules_skips_bad_files_and_keeps_good_ones(self):
        objects = [
            {"Key": "sigma_rules/good.yaml"},
            {"Key": "sigma_rules/bad.yaml"},
            {"Key": "sigma_rules/ignore.txt"},
        ]

        def _get_object_side_effect(*, Bucket, Key):
            if Key == "sigma_rules/good.yaml":
                return {
                    "Body": MagicMock(
                        read=MagicMock(
                            return_value=b"title: Good Rule\ndetection:\n  selection:\n    eventSource: iam.amazonaws.com\n    eventName: CreateUser\n  condition: selection\n"
                        )
                    )
                }
            if Key == "sigma_rules/bad.yaml":
                return {"Body": MagicMock(read=MagicMock(return_value=b"title: [broken"))}
            raise AssertionError(f"Unexpected S3 key requested: {Key}")

        with patch.object(lambda_function, "list_s3_objects_cached", return_value=objects), \
             patch.object(lambda_function, "s3_client") as mock_s3:
            mock_s3.get_object.side_effect = _get_object_side_effect

            rules = load_sigma_rules("test-bucket")

        assert len(rules) == 1
        assert rules[0]["title"] == "Good Rule"

    def test_reload_sigma_rules_if_needed_keeps_last_good_cache_on_invalid_refresh(self):
        existing_rule = _simple_rule("Existing Rule", "iam.amazonaws.com", "CreateUser")
        existing_index, existing_wildcards = build_rule_index([existing_rule])

        lambda_function.sigma_rules_cache = [existing_rule]
        lambda_function.sigma_rules_etag_hash = "old-hash"
        lambda_function.rule_index = existing_index
        lambda_function.wildcard_rules = existing_wildcards

        with patch.object(lambda_function, "compute_s3_files_hash", return_value="new-hash"), \
             patch.object(lambda_function, "load_sigma_rules", side_effect=RuntimeError("No valid Sigma rules could be loaded from S3")):
            reload_sigma_rules_if_needed()

        assert lambda_function.sigma_rules_cache == [existing_rule]
        assert lambda_function.sigma_rules_etag_hash == "old-hash"
        assert lambda_function.rule_index == existing_index
        assert lambda_function.wildcard_rules == existing_wildcards


# ---------------------------------------------------------------------------
# _build_sqs_message
# ---------------------------------------------------------------------------
class TestBuildSqsMessage:
    def test_message_has_required_keys(self):
        rule = {"id": "r1", "title": "Test", "level": "high", "description": "desc",
                "logsource": {}, "detection": {}, "status": "stable"}
        record = {"eventName": "CreateUser", "eventSource": "iam.amazonaws.com"}
        msg = _build_sqs_message(rule, record)
        assert "Id" in msg
        assert "MessageBody" in msg

    def test_message_body_is_valid_json(self):
        rule = {"id": "r1", "title": "Test"}
        record = {"eventName": "CreateUser"}
        msg = _build_sqs_message(rule, record)
        body = json.loads(msg["MessageBody"])
        assert body["sigma_rule_id"] == "r1"
        assert body["sigma_rule_title"] == "Test"
        assert body["matched_event"]["eventName"] == "CreateUser"

    def test_sigma_event_source_added(self):
        msg = _build_sqs_message({"id": "r1"}, {"eventName": "X"})
        body = json.loads(msg["MessageBody"])
        assert body["matched_event"]["sigmaEventSource"] == "CloudTrail"

    def test_original_record_not_mutated(self):
        record = {"eventName": "CreateUser"}
        _build_sqs_message({"id": "r1"}, record)
        assert "sigmaEventSource" not in record

    def test_id_is_string_max_8_chars(self):
        msg = _build_sqs_message({"id": "r1"}, {"eventName": "X"})
        assert isinstance(msg["Id"], str)
        assert len(msg["Id"]) <= 8

    def test_missing_rule_fields_use_defaults(self):
        msg = _build_sqs_message({}, {"eventName": "X"})
        body = json.loads(msg["MessageBody"])
        assert body["sigma_rule_title"] == "Unknown Sigma Rule"
        assert body["sigma_rule_data"]["level"] == "info"
        assert body["sigma_rule_data"]["status"] == "experimental"

    def test_unique_ids_per_call(self):
        msg1 = _build_sqs_message({"id": "r1"}, {"eventName": "X"})
        msg2 = _build_sqs_message({"id": "r1"}, {"eventName": "X"})
        assert msg1["Id"] != msg2["Id"]


# ---------------------------------------------------------------------------
# _flush_sqs_batch
# ---------------------------------------------------------------------------
class TestFlushSqsBatch:
    """Tests for SQS batch sending with retry logic."""

    def test_empty_batch_is_noop(self):
        """Empty message list should not call SQS."""
        with patch.object(lambda_function, "sqs") as mock_sqs:
            _flush_sqs_batch([])
            mock_sqs.send_message_batch.assert_not_called()

    def test_successful_batch(self):
        mock_response = {
            "Successful": [{"Id": "a1"}, {"Id": "a2"}],
            "Failed": [],
        }
        with patch.object(lambda_function, "sqs") as mock_sqs:
            mock_sqs.send_message_batch.return_value = mock_response
            messages = [{"Id": "a1", "MessageBody": "{}"}, {"Id": "a2", "MessageBody": "{}"}]
            _flush_sqs_batch(messages)
            mock_sqs.send_message_batch.assert_called_once()

    def test_partial_failure_retries(self):
        """Partially failed messages should be retried."""
        responses = [
            # First attempt: a2 fails
            {"Successful": [{"Id": "a1"}], "Failed": [{"Id": "a2", "Code": "500", "Message": "err"}]},
            # Second attempt: a2 succeeds
            {"Successful": [{"Id": "a2"}], "Failed": []},
        ]
        with patch.object(lambda_function, "sqs") as mock_sqs:
            mock_sqs.send_message_batch.side_effect = responses
            messages = [{"Id": "a1", "MessageBody": "{}"}, {"Id": "a2", "MessageBody": "{}"}]
            _flush_sqs_batch(messages)
            assert mock_sqs.send_message_batch.call_count == 2
            # Second call should only contain the failed message
            second_call_entries = mock_sqs.send_message_batch.call_args_list[1][1]["Entries"]
            assert len(second_call_entries) == 1
            assert second_call_entries[0]["Id"] == "a2"

    def test_all_retries_exhausted_raises(self):
        """After MAX_SQS_RETRIES, should raise RuntimeError."""
        fail_response = {
            "Successful": [],
            "Failed": [{"Id": "a1", "Code": "500", "Message": "err"}],
        }
        with patch.object(lambda_function, "sqs") as mock_sqs:
            mock_sqs.send_message_batch.return_value = fail_response
            messages = [{"Id": "a1", "MessageBody": "{}"}]
            with pytest.raises(RuntimeError, match="failed after"):
                _flush_sqs_batch(messages)
            assert mock_sqs.send_message_batch.call_count == MAX_SQS_RETRIES

    def test_api_exception_re_raised(self):
        """Boto3 exceptions should be re-raised after logging."""
        with patch.object(lambda_function, "sqs") as mock_sqs:
            mock_sqs.send_message_batch.side_effect = Exception("Connection error")
            messages = [{"Id": "a1", "MessageBody": "{}"}]
            with pytest.raises(Exception, match="Connection error"):
                _flush_sqs_batch(messages)

    def test_no_failed_key_treated_as_success(self):
        """If 'Failed' key is missing from response, treat as all successful."""
        with patch.object(lambda_function, "sqs") as mock_sqs:
            mock_sqs.send_message_batch.return_value = {"Successful": [{"Id": "a1"}]}
            _flush_sqs_batch([{"Id": "a1", "MessageBody": "{}"}])
            mock_sqs.send_message_batch.assert_called_once()


# ---------------------------------------------------------------------------
# Failure propagation
# ---------------------------------------------------------------------------
class TestFailurePropagation:
    def test_process_cloudtrail_records_reraises_batch_failures(self):
        content = json.dumps({
            "Records": [{"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"}]
        })

        with patch.object(lambda_function, "get_candidate_rules", return_value=[{"title": "R1"}]), \
             patch.object(lambda_function, "matches_sigma_rule", return_value=True), \
             patch.object(lambda_function, "_build_sqs_message", return_value={"Id": "a1", "MessageBody": "{}"}), \
             patch.object(lambda_function, "_flush_sqs_batch", side_effect=RuntimeError("sqs failed")):
            with pytest.raises(RuntimeError, match="CloudTrail record processing failure"):
                lambda_function.process_cloudtrail_records(content)

    def test_process_cloudtrail_records_continues_after_record_error(self):
        content = json.dumps({
            "Records": [
                {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser"},
                {"eventSource": "iam.amazonaws.com", "eventName": "DeleteUser"},
            ]
        })

        def _match_side_effect(record, _rule):
            if record["eventName"] == "CreateUser":
                raise RuntimeError("bad first record")
            return True

        with patch.object(lambda_function, "get_candidate_rules", return_value=[{"title": "R1"}]), \
             patch.object(lambda_function, "matches_sigma_rule", side_effect=_match_side_effect), \
             patch.object(lambda_function, "_build_sqs_message", return_value={"Id": "a1", "MessageBody": "{}"}) as build_mock, \
             patch.object(lambda_function, "_flush_sqs_batch") as flush_mock:
            with pytest.raises(RuntimeError, match="1 CloudTrail record processing failure"):
                lambda_function.process_cloudtrail_records(content)

        build_mock.assert_called_once()
        flush_mock.assert_called_once()

    def test_lambda_handler_reraises_record_processing_failures(self):
        event = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-bucket"},
                        "object": {"key": "cloudtrail/test.json.gz"},
                    }
                }
            ]
        }

        with patch.object(lambda_function, "reload_sigma_rules_if_needed"), \
             patch.object(lambda_function, "fetch_s3_object", return_value='{"Records": []}'), \
             patch.object(lambda_function, "process_cloudtrail_records", side_effect=RuntimeError("processing failed")):
            with pytest.raises(RuntimeError, match="Failed to process 1 S3 event record"):
                lambda_function.lambda_handler(event, None)

    def test_lambda_handler_continues_other_s3_records_before_raising(self):
        event = {
            "Records": [
                {
                    "s3": {
                        "bucket": {"name": "test-bucket"},
                        "object": {"key": "cloudtrail/first.json.gz"},
                    }
                },
                {
                    "s3": {
                        "bucket": {"name": "test-bucket"},
                        "object": {"key": "cloudtrail/second.json.gz"},
                    }
                },
            ]
        }

        with patch.object(lambda_function, "reload_sigma_rules_if_needed"), \
             patch.object(lambda_function, "fetch_s3_object", side_effect=['{"Records": []}', '{"Records": []}']), \
             patch.object(lambda_function, "process_cloudtrail_records", side_effect=[RuntimeError("processing failed"), None]) as process_mock:
            with pytest.raises(RuntimeError, match="Failed to process 1 S3 event record"):
                lambda_function.lambda_handler(event, None)

        assert process_mock.call_count == 2

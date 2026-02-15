import pytest
import os
import sys
import glob
import json

# Ensure the parent package is importable without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sigma_matcher import (
    matches_sigma_rule,
    evaluate_block,
    match_list_of_dicts,
    check_field_reference,
    get_nested_value,
    evaluate_condition,
    tokenize_condition,
    parse_item,
    evaluate_reference,
    evaluate_wildcard_or_block_count,
    count_true_matches,
)


# ---------------------------------------------------------------------------
# get_nested_value
# ---------------------------------------------------------------------------
class TestGetNestedValue:
    def test_top_level_key(self):
        assert get_nested_value({"a": 1}, "a") == 1

    def test_nested_key(self):
        assert get_nested_value({"a": {"b": {"c": 42}}}, "a.b.c") == 42

    def test_missing_top_level(self):
        assert get_nested_value({"a": 1}, "z") is None

    def test_missing_nested(self):
        assert get_nested_value({"a": {"b": 1}}, "a.x.y") is None

    def test_empty_dict(self):
        assert get_nested_value({}, "a") is None

    def test_array_traversal(self):
        """When an intermediate value is a list of dicts, collect the leaf values."""
        data = {"a": {"b": [{"c": 1}, {"c": 2}, {"d": 3}]}}
        result = get_nested_value(data, "a.b.c")
        assert result == [1, 2]

    def test_array_traversal_no_match(self):
        data = {"a": {"b": [{"x": 1}]}}
        assert get_nested_value(data, "a.b.c") is None

    def test_non_dict_input(self):
        assert get_nested_value("not a dict", "a") is None

    def test_value_is_none(self):
        assert get_nested_value({"a": None}, "a") is None

    def test_value_is_false(self):
        """False is a valid value and should be returned."""
        assert get_nested_value({"a": False}, "a") is False

    def test_value_is_zero(self):
        assert get_nested_value({"a": 0}, "a") == 0

    def test_deep_nesting(self):
        data = {"l1": {"l2": {"l3": {"l4": "deep"}}}}
        assert get_nested_value(data, "l1.l2.l3.l4") == "deep"


# ---------------------------------------------------------------------------
# evaluate_block — modifiers
# ---------------------------------------------------------------------------
class TestEvaluateBlock:
    # --- exact match ---
    def test_exact_match(self):
        assert evaluate_block({"eventName": "CreateUser"}, {"eventName": "CreateUser"}) is True

    def test_exact_mismatch(self):
        assert evaluate_block({"eventName": "DeleteUser"}, {"eventName": "CreateUser"}) is False

    def test_missing_field(self):
        assert evaluate_block({}, {"eventName": "CreateUser"}) is False

    # --- list expected value (any-of) ---
    def test_list_match(self):
        assert evaluate_block({"eventName": "CreateUser"}, {"eventName": ["CreateUser", "DeleteUser"]}) is True

    def test_list_no_match(self):
        assert evaluate_block({"eventName": "UpdateUser"}, {"eventName": ["CreateUser", "DeleteUser"]}) is False

    # --- |startswith ---
    def test_startswith_match(self):
        assert evaluate_block({"name": "HelloWorld"}, {"name|startswith": "Hello"}) is True

    def test_startswith_no_match(self):
        assert evaluate_block({"name": "Goodbye"}, {"name|startswith": "Hello"}) is False

    def test_startswith_non_string(self):
        assert evaluate_block({"name": 123}, {"name|startswith": "1"}) is False

    # --- |endswith ---
    def test_endswith_match(self):
        assert evaluate_block({"name": "HelloWorld"}, {"name|endswith": "World"}) is True

    def test_endswith_no_match(self):
        assert evaluate_block({"name": "HelloWorld"}, {"name|endswith": "Earth"}) is False

    # --- |contains ---
    def test_contains_match(self):
        assert evaluate_block({"name": "HelloWorld"}, {"name|contains": "loWo"}) is True

    def test_contains_no_match(self):
        assert evaluate_block({"name": "HelloWorld"}, {"name|contains": "xyz"}) is False

    def test_contains_wildcard_present(self):
        """'*' means field exists and is non-empty."""
        assert evaluate_block({"name": "anything"}, {"name|contains": "*"}) is True

    def test_contains_wildcard_missing(self):
        assert evaluate_block({}, {"name|contains": "*"}) is False

    def test_contains_wildcard_empty_string(self):
        assert evaluate_block({"name": ""}, {"name|contains": "*"}) is False

    def test_contains_in_list(self):
        assert evaluate_block({"tags": ["a", "b", "c"]}, {"tags|contains": "b"}) is True

    def test_contains_not_in_list(self):
        assert evaluate_block({"tags": ["a", "b"]}, {"tags|contains": "z"}) is False

    # --- |re ---
    def test_re_match(self):
        assert evaluate_block({"name": "abc123"}, {"name|re": r"^abc\d+"}) is True

    def test_re_no_match(self):
        assert evaluate_block({"name": "xyz"}, {"name|re": r"^abc"}) is False

    def test_re_invalid_pattern(self):
        assert evaluate_block({"name": "abc"}, {"name|re": r"[invalid"}) is False

    def test_re_none_value(self):
        assert evaluate_block({}, {"name|re": r".*"}) is False

    def test_re_non_string_value(self):
        """Non-string values are coerced to str."""
        assert evaluate_block({"code": 404}, {"code|re": r"4\d{2}"}) is True

    # --- |fieldref ---
    def test_fieldref_match(self):
        record = {"user": "admin", "actor": "admin"}
        assert evaluate_block(record, {"user|fieldref": "actor"}) is True

    def test_fieldref_mismatch(self):
        record = {"user": "admin", "actor": "root"}
        assert evaluate_block(record, {"user|fieldref": "actor"}) is False

    # --- nested field ---
    def test_nested_field_match(self):
        record = {"userIdentity": {"type": "IAMUser"}}
        assert evaluate_block(record, {"userIdentity.type": "IAMUser"}) is True

    # --- non-dict criteria ---
    def test_non_dict_criteria_returns_false(self):
        assert evaluate_block({"a": 1}, "not a dict") is False

    # --- multiple criteria (all must match) ---
    def test_multiple_criteria_all_match(self):
        record = {"eventName": "CreateUser", "sourceIP": "1.2.3.4"}
        criteria = {"eventName": "CreateUser", "sourceIP": "1.2.3.4"}
        assert evaluate_block(record, criteria) is True

    def test_multiple_criteria_partial_match(self):
        record = {"eventName": "CreateUser", "sourceIP": "5.6.7.8"}
        criteria = {"eventName": "CreateUser", "sourceIP": "1.2.3.4"}
        assert evaluate_block(record, criteria) is False


# ---------------------------------------------------------------------------
# match_list_of_dicts
# ---------------------------------------------------------------------------
class TestMatchListOfDicts:
    def test_simple_match(self):
        record_val = [{"key": "Name", "value": "test"}]
        expected = [{"key": "Name", "value": "test"}]
        assert match_list_of_dicts(record_val, expected) is True

    def test_no_match(self):
        record_val = [{"key": "Name", "value": "other"}]
        expected = [{"key": "Name", "value": "test"}]
        assert match_list_of_dicts(record_val, expected) is False

    def test_nested_dict_match(self):
        record_val = [{"expiration": {"days": 1}}]
        expected = [{"expiration": {"days": 1}}]
        assert match_list_of_dicts(record_val, expected) is True

    def test_nested_dict_mismatch(self):
        record_val = [{"expiration": {"days": 7}}]
        expected = [{"expiration": {"days": 1}}]
        assert match_list_of_dicts(record_val, expected) is False

    def test_none_record_val(self):
        assert match_list_of_dicts(None, [{"a": 1}]) is False

    def test_empty_list(self):
        assert match_list_of_dicts([], [{"a": 1}]) is False

    def test_non_dict_items_ignored(self):
        record_val = ["string", 123, {"key": "match"}]
        expected = [{"key": "match"}]
        assert match_list_of_dicts(record_val, expected) is True

    def test_single_value_wrapped(self):
        """Non-list record_val is wrapped in a list."""
        record_val = {"key": "Name"}
        expected = [{"key": "Name"}]
        assert match_list_of_dicts(record_val, expected) is True


# ---------------------------------------------------------------------------
# check_field_reference
# ---------------------------------------------------------------------------
class TestCheckFieldReference:
    def test_equal_values(self):
        record = {"a": "same", "b": "same"}
        assert check_field_reference(record, "a", "b") is True

    def test_different_values(self):
        record = {"a": "one", "b": "two"}
        assert check_field_reference(record, "a", "b") is False

    def test_missing_field(self):
        assert check_field_reference({"a": "val"}, "a", "missing") is False

    def test_arn_user_extraction(self):
        record = {
            "caller": "arn:aws:iam::123456789012:user/admin",
            "username": "admin",
        }
        assert check_field_reference(record, "caller", "username") is True

    def test_arn_user_mismatch(self):
        record = {
            "caller": "arn:aws:iam::123456789012:user/admin",
            "username": "root",
        }
        assert check_field_reference(record, "caller", "username") is False

    def test_nested_fields(self):
        record = {"a": {"x": "val"}, "b": {"y": "val"}}
        assert check_field_reference(record, "a.x", "b.y") is True


# ---------------------------------------------------------------------------
# tokenize_condition
# ---------------------------------------------------------------------------
class TestTokenizeCondition:
    def test_simple(self):
        assert tokenize_condition("selection") == ["selection"]

    def test_and(self):
        assert tokenize_condition("selection and not filter") == ["selection", "and", "not", "filter"]

    def test_extra_spaces(self):
        assert tokenize_condition("  a   and   b  ") == ["a", "and", "b"]

    def test_empty(self):
        assert tokenize_condition("") == []


# ---------------------------------------------------------------------------
# evaluate_reference
# ---------------------------------------------------------------------------
class TestEvaluateReference:
    def test_direct_true(self):
        assert evaluate_reference({"sel": True}, "sel") is True

    def test_direct_false(self):
        assert evaluate_reference({"sel": False}, "sel") is False

    def test_missing(self):
        assert evaluate_reference({}, "sel") is False

    def test_wildcard_match(self):
        matches = {"selection_a": True, "selection_b": False, "filter": True}
        assert evaluate_reference(matches, "selection_*") is True

    def test_wildcard_no_true(self):
        matches = {"selection_a": False, "selection_b": False}
        assert evaluate_reference(matches, "selection_*") is False


# ---------------------------------------------------------------------------
# count_true_matches
# ---------------------------------------------------------------------------
class TestCountTrueMatches:
    def test_all_true(self):
        matches = {"sel_a": True, "sel_b": True, "sel_c": True}
        assert count_true_matches(matches, "sel_*") == 3

    def test_some_true(self):
        matches = {"sel_a": True, "sel_b": False, "sel_c": True}
        assert count_true_matches(matches, "sel_*") == 2

    def test_none_matching_pattern(self):
        matches = {"other_a": True}
        assert count_true_matches(matches, "sel_*") == 0

    def test_exact_name_no_wildcard(self):
        matches = {"sel": True}
        assert count_true_matches(matches, "sel") == 1


# ---------------------------------------------------------------------------
# evaluate_wildcard_or_block_count
# ---------------------------------------------------------------------------
class TestEvaluateWildcardOrBlockCount:
    def test_wildcard_count_met(self):
        matches = {"sel_a": True, "sel_b": True}
        assert evaluate_wildcard_or_block_count(matches, "sel_*", 2) is True

    def test_wildcard_count_not_met(self):
        matches = {"sel_a": True, "sel_b": True}
        assert evaluate_wildcard_or_block_count(matches, "sel_*", 1) is False

    def test_single_block_true(self):
        assert evaluate_wildcard_or_block_count({"sel": True}, "sel", 1) is True

    def test_single_block_false(self):
        assert evaluate_wildcard_or_block_count({"sel": False}, "sel", 1) is False


# ---------------------------------------------------------------------------
# parse_item
# ---------------------------------------------------------------------------
class TestParseItem:
    def test_simple_reference(self):
        val, idx = parse_item(["selection"], 0, {"selection": True})
        assert val is True and idx == 1

    def test_not(self):
        val, idx = parse_item(["not", "filter"], 0, {"filter": True})
        assert val is False and idx == 2

    def test_n_of(self):
        matches = {"sel_a": True, "sel_b": True, "sel_c": False}
        val, idx = parse_item(["2", "of", "sel_*"], 0, matches)
        assert val is True and idx == 3

    def test_past_end(self):
        val, idx = parse_item([], 0, {})
        assert val is False and idx == 0


# ---------------------------------------------------------------------------
# evaluate_condition  (integration of tokenizer + parser)
# ---------------------------------------------------------------------------
class TestEvaluateCondition:
    def test_single_selection_true(self):
        assert evaluate_condition("selection", {"selection": True}) is True

    def test_single_selection_false(self):
        assert evaluate_condition("selection", {"selection": False}) is False

    def test_and_both_true(self):
        assert evaluate_condition("sel and filter", {"sel": True, "filter": True}) is True

    def test_and_one_false(self):
        assert evaluate_condition("sel and filter", {"sel": True, "filter": False}) is False

    def test_or_one_true(self):
        assert evaluate_condition("sel or filter", {"sel": False, "filter": True}) is True

    def test_or_both_false(self):
        assert evaluate_condition("sel or filter", {"sel": False, "filter": False}) is False

    def test_not(self):
        assert evaluate_condition("selection and not filter", {"selection": True, "filter": False}) is True

    def test_not_true(self):
        assert evaluate_condition("selection and not filter", {"selection": True, "filter": True}) is False

    def test_empty_expression(self):
        assert evaluate_condition("", {}) is False

    def test_n_of(self):
        matches = {"sel_a": True, "sel_b": True, "sel_c": False}
        assert evaluate_condition("2 of sel_*", matches) is True

    def test_n_of_not_met(self):
        matches = {"sel_a": True, "sel_b": False, "sel_c": False}
        assert evaluate_condition("2 of sel_*", matches) is False


# ---------------------------------------------------------------------------
# matches_sigma_rule  (end-to-end)
# ---------------------------------------------------------------------------
class TestMatchesSigmaRule:
    def test_simple_match(self):
        record = {"eventName": "CreateUser", "userIdentity": {"type": "IAMUser"}}
        rule = {
            "detection": {
                "selection": {"eventName": "CreateUser"},
                "condition": "selection",
            }
        }
        assert matches_sigma_rule(record, rule) is True

    def test_simple_no_match(self):
        record = {"eventName": "DeleteUser"}
        rule = {
            "detection": {
                "selection": {"eventName": "CreateUser"},
                "condition": "selection",
            }
        }
        assert matches_sigma_rule(record, rule) is False

    def test_selection_with_filter(self):
        record = {"eventName": "CreateUser", "sourceIP": "internal"}
        rule = {
            "detection": {
                "selection": {"eventName": "CreateUser"},
                "filter": {"sourceIP": "internal"},
                "condition": "selection and not filter",
            }
        }
        assert matches_sigma_rule(record, rule) is False

    def test_selection_with_filter_not_excluded(self):
        record = {"eventName": "CreateUser", "sourceIP": "external"}
        rule = {
            "detection": {
                "selection": {"eventName": "CreateUser"},
                "filter": {"sourceIP": "internal"},
                "condition": "selection and not filter",
            }
        }
        assert matches_sigma_rule(record, rule) is True

    def test_no_detection_key(self):
        assert matches_sigma_rule({"a": 1}, {}) is False

    def test_non_dict_inputs(self):
        assert matches_sigma_rule("bad", {"detection": {}}) is False
        assert matches_sigma_rule({}, "bad") is False

    def test_default_condition_is_selection(self):
        """If 'condition' is omitted it defaults to 'selection'."""
        record = {"eventName": "CreateUser"}
        rule = {"detection": {"selection": {"eventName": "CreateUser"}}}
        assert matches_sigma_rule(record, rule) is True

    def test_nested_field_match(self):
        record = {"userIdentity": {"type": "Root"}}
        rule = {
            "detection": {
                "selection": {"userIdentity.type": "Root"},
                "condition": "selection",
            }
        }
        assert matches_sigma_rule(record, rule) is True

    def test_multiple_selections_or(self):
        record = {"eventName": "StopInstances"}
        rule = {
            "detection": {
                "sel1": {"eventName": "RunInstances"},
                "sel2": {"eventName": "StopInstances"},
                "condition": "sel1 or sel2",
            }
        }
        assert matches_sigma_rule(record, rule) is True

    def test_list_of_values(self):
        record = {"eventName": "DeleteBucket"}
        rule = {
            "detection": {
                "selection": {"eventName": ["CreateBucket", "DeleteBucket"]},
                "condition": "selection",
            }
        }
        assert matches_sigma_rule(record, rule) is True

    def test_contains_modifier_end_to_end(self):
        record = {"errorMessage": "Access Denied for user admin"}
        rule = {
            "detection": {
                "selection": {"errorMessage|contains": "Access Denied"},
                "condition": "selection",
            }
        }
        assert matches_sigma_rule(record, rule) is True

    def test_startswith_modifier_end_to_end(self):
        record = {"eventName": "CreateAccessKey"}
        rule = {
            "detection": {
                "selection": {"eventName|startswith": "Create"},
                "condition": "selection",
            }
        }
        assert matches_sigma_rule(record, rule) is True

    def test_re_modifier_end_to_end(self):
        record = {"eventName": "Create2024AccessKey"}
        rule = {
            "detection": {
                "selection": {"eventName|re": r"Create\d{4}AccessKey"},
                "condition": "selection",
            }
        }
        assert matches_sigma_rule(record, rule) is True


# ---------------------------------------------------------------------------
# Integration tests — external rule files (original parametrized test)
# ---------------------------------------------------------------------------
def find_rule_test_file(rule_file):
    """
    e.g. rule_file='rules/myrule.yml' => test file='rules/myrule_tests.json'
    If it doesn't exist, return None.
    """
    base, _ = os.path.splitext(rule_file)
    candidate = f"{base}_tests.json"
    if os.path.exists(candidate):
        return candidate
    return None


def load_sigma_rules_from_file(path):
    """
    Suppose each .yml might have a single rule or a list of rules.
    We parse them, returning a list.
    """
    import yaml

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        return [data]
    else:
        return []


def load_json_test_file(path):
    """
    Loads a .json with structure:
      {
        "should_match": [...],
        "should_not_match": [...]
      }
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


_RULE_FILES = (
    glob.glob(os.path.join(os.path.dirname(__file__), "..", "rules", "*.yml"))
    + glob.glob(os.path.join(os.path.dirname(__file__), "..", "rules", "*.yaml"))
    + glob.glob(os.path.join(os.path.dirname(__file__), "..", "rules", "sigma_rules", "*.yml"))
    + glob.glob(os.path.join(os.path.dirname(__file__), "..", "rules", "sigma_rules", "*.yaml"))
)


@pytest.mark.parametrize("rule_file", _RULE_FILES if _RULE_FILES else [pytest.param("__skip__", marks=pytest.mark.skip(reason="No rule files found"))])
def test_each_rule_json(rule_file):
    """
    For every .yml in 'rules/' folder, looks for a matching _tests.json file. If found, loads it
    and verifies the events in "should_match" and "should_not_match" arrays.
    """
    test_file = find_rule_test_file(rule_file)
    if not test_file:
        pytest.skip(f"No JSON test file for {rule_file}")

    rules = load_sigma_rules_from_file(rule_file)
    test_data = load_json_test_file(test_file)

    for rule in rules:
        rule_id = rule.get("id", "no-id")
        for i, record in enumerate(test_data.get("should_match", [])):
            matched = matches_sigma_rule(record, rule)
            assert matched, (
                f"Rule {rule_id} from {rule_file} should MATCH record #{i}, "
                f"but didn't.\nRecord: {record}"
            )
        for i, record in enumerate(test_data.get("should_not_match", [])):
            matched = matches_sigma_rule(record, rule)
            assert not matched, (
                f"Rule {rule_id} from {rule_file} should NOT match record #{i}, "
                f"but did.\nRecord: {record}"
            )

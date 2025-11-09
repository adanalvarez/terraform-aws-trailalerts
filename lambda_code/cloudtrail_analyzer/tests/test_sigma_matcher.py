import pytest
import os
import glob
import json

from TrailAlertsCloudTrailAnalyzer.sigma_matcher import matches_sigma_rule

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

@pytest.mark.parametrize("rule_file", 
                          glob.glob("../rules/*.yml") + 
                          glob.glob("../rules/*.yaml") +
                          glob.glob("../rules/sigma_rules/*.yml") +
                          glob.glob("../rules/sigma_rules/*.yaml"))
def test_each_rule_json(rule_file):
    """
    For every .yml in 'rules/' folder, looks for a matching _tests.json file. If found, loads it
    and verifies the events in "should_match" and "should_not_match" arrays.
    """
    test_file = find_rule_test_file(rule_file)
    if not test_file:
        pytest.skip(f"No JSON test file for {rule_file}")

    # Load the rule(s)
    rules = load_sigma_rules_from_file(rule_file)

    # Load the JSON test data
    test_data = load_json_test_file(test_file)

    for rule in rules:
        rule_id = rule.get("id", "no-id")
        print(f"Testing rule {rule_id} from {rule_file} against {test_file}")
        for i, record in enumerate(test_data.get("should_match", [])):
            matched = matches_sigma_rule(record, rule)
            assert matched, (
                f"Rule {rule_id} from {rule_file} should MATCH test_file {test_file}, record #{i}, "
                f"but didn't.\nRecord: {record}"
            )
            print(f"  Record {i} matched as expected.")
        for i, record in enumerate(test_data.get("should_not_match", [])):
            matched = matches_sigma_rule(record, rule)
            assert not matched, (
                f"Rule {rule_id} from {rule_file} should NOT match test_file {test_file}, record #{i}, "
                f"but did.\nRecord: {record}"
            )
            print(f"  Record {i} did not match as expected.")

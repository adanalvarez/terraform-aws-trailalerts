import re
import logging
from typing import Dict, Any, List, Union, Tuple, Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def matches_sigma_rule(cloudtrail_record: Dict[str, Any], sigma_rule: Dict[str, Any]) -> bool:
    """
    Checks if a CloudTrail record matches a Sigma rule's detection criteria.

    Args:
        cloudtrail_record (Dict[str, Any]): The CloudTrail record to check
        sigma_rule (Dict[str, Any]): The Sigma rule containing detection criteria

    Returns:
        bool: True if the record matches the rule's criteria, False otherwise

    Example:
        >>> record = {"userIdentity": {"type": "IAMUser"}, "eventName": "CreateUser"}
        >>> rule = {
        ...     "detection": {
        ...         "selection": {"userIdentity.type": "IAMUser"},
        ...         "condition": "selection"
        ...     }
        ... }
        >>> matches_sigma_rule(record, rule)
        True
    """
    if not isinstance(cloudtrail_record, dict) or not isinstance(sigma_rule, dict):
        logger.error("Invalid input types: cloudtrail_record and sigma_rule must be dictionaries")
        return False

    detection = sigma_rule.get('detection', {})
    if not detection:
        logger.warning("No detection criteria found in trailalerts rule")
        return False

    condition_expr = detection.get('condition', 'selection')
    
    block_results = {}
    for block_name, block_criteria in detection.items():
        if block_name == 'condition':
            continue
        block_results[block_name] = evaluate_block(cloudtrail_record, block_criteria)
    
    return evaluate_condition(condition_expr, block_results)

def evaluate_block(cloudtrail_record: Dict[str, Any], criteria: Dict[str, Any]) -> bool:
    """
    Evaluates if a record meets all criteria in a detection block.

    Args:
        cloudtrail_record (Dict[str, Any]): The CloudTrail record to check
        criteria (Dict[str, Any]): The criteria to evaluate

    Returns:
        bool: True if all criteria are met, False otherwise

    Example:
        >>> record = {"userIdentity": {"type": "IAMUser"}}
        >>> criteria = {"userIdentity.type": "IAMUser"}
        >>> evaluate_block(record, criteria)
        True
    """
    if not isinstance(criteria, dict):
        logger.warning(f"Invalid criteria type: {type(criteria)}. Expected dict.")
        return False

    try:
        for field, expected_value in criteria.items():
            if '|startswith' in field:
                base_field = field.split('|startswith')[0].rstrip(':').strip()
                record_val = get_nested_value(cloudtrail_record, base_field)
                if not (isinstance(record_val, str) and isinstance(expected_value, str)):
                    return False
                if not record_val.startswith(expected_value):
                    return False

            elif '|endswith' in field:
                base_field = field.split('|endswith')[0].rstrip(':').strip()
                record_val = get_nested_value(cloudtrail_record, base_field)
                if not (isinstance(record_val, str) and isinstance(expected_value, str)):
                    return False
                if not record_val.endswith(expected_value):
                    return False

            elif '|re' in field:
                # support for regex pattern matching
                base_field = field.split('|re')[0].rstrip(':').strip()
                record_val = get_nested_value(cloudtrail_record, base_field)
                
                # Log for debugging
                logger.debug(f"Regex check - Field: {base_field}, Value: {record_val}, Pattern: {expected_value}")
                
                if record_val is None:
                    return False
                    
                # Convert record_val to string if it's not already
                if not isinstance(record_val, str):
                    record_val = str(record_val)
                
                try:
                    # Perform regex match
                    pattern = re.compile(expected_value)
                    if not pattern.search(record_val):
                        return False
                except re.error as e:
                    logger.error(f"Invalid regex pattern {expected_value}: {str(e)}")
                    return False

            elif '|contains' in field:
                base_field = field.split('|contains')[0].rstrip(':').strip()
                record_val = get_nested_value(cloudtrail_record, base_field)
                
                # Add debug logging to help diagnose issues
                logger.debug(f"Contains check - Field: {base_field}, Value: {record_val}, Expected: {expected_value}")
                
                # If expected_value is '*', check if field exists and is not empty
                if expected_value == '*':
                    if record_val is None or record_val == "" or (isinstance(record_val, list) and len(record_val) == 0):
                        return False
                # Check if expected_value is another field reference (contains a dot)
                elif isinstance(expected_value, str) and '.' in expected_value:
                    # Try to get the referenced field's value
                    ref_value = get_nested_value(cloudtrail_record, expected_value)
                    if ref_value is None:
                        return False
                    
                    # Convert both to strings for comparison if needed
                    if not isinstance(record_val, str):
                        record_val = str(record_val)
                    if not isinstance(ref_value, str):
                        ref_value = str(ref_value)
                        
                    if ref_value not in record_val:
                        return False
                # Otherwise, check if the field actually contains the expected value
                elif isinstance(record_val, str) and isinstance(expected_value, str):
                    if expected_value not in record_val:
                        return False
                # Handle the case where record_val is a list
                elif isinstance(record_val, list):
                    if isinstance(expected_value, str):
                        if expected_value not in record_val:
                            return False
                    else:
                        return False
                # Handle complex objects by converting to string for contains check
                elif record_val is not None and isinstance(expected_value, str):
                    # Convert complex objects to string for contains check
                    record_str = str(record_val)
                    if expected_value not in record_str:
                        return False
                else:
                    return False

            elif '|fieldref' in field:
                base_field = field.split('|fieldref')[0].rstrip(':').strip()
                if not check_field_reference(cloudtrail_record, base_field, expected_value):
                    return False

            else:
                record_val = get_nested_value(cloudtrail_record, field)
                
                # Special handling for matching an array against a list of dictionaries
                if isinstance(expected_value, list) and all(isinstance(item, dict) for item in expected_value):
                    if not match_list_of_dicts(record_val, expected_value):
                        return False
                # Standard list containment check
                elif isinstance(expected_value, list) and not isinstance(record_val, list):
                    if record_val not in expected_value:
                        return False
                # Direct equality check
                else:
                    if record_val != expected_value:
                        return False

        return True
    except Exception as e:
        logger.error(f"Error evaluating block: {str(e)}")
        return False

def match_list_of_dicts(record_val: Any, expected_values: List[Dict[str, Any]]) -> bool:
    """
    Checks if a record value matches against a list of expected dictionaries.
    This is used for cases like rules.[{expiration: {days: 1}}] where we need to check
    if any element in the rules array matches the specified criteria.

    Args:
        record_val: The value from the record, could be a single value or a list
        expected_values: List of dictionaries to match against

    Returns:
        bool: True if any element in record_val matches any dictionary in expected_values
    """
    try:
        # If record_val is not a list (could be None), convert to list for uniform handling
        if not isinstance(record_val, list):
            record_val = [record_val] if record_val is not None else []
            
        # If record_val is empty, it can't match
        if not record_val:
            return False
            
        # For each expected dictionary (each represents a set of conditions)
        for expected_dict in expected_values:
            # Check if any item in record_val matches all keys in expected_dict
            for item in record_val:
                if not isinstance(item, dict):
                    continue
                    
                matches_all = True
                for key, value in expected_dict.items():
                    # Handle nested dictionaries recursively
                    if isinstance(value, dict):
                        if key not in item or not isinstance(item[key], dict):
                            matches_all = False
                            break
                        
                        # Check all nested key/values
                        for sub_key, sub_val in value.items():
                            if sub_key not in item[key] or item[key][sub_key] != sub_val:
                                matches_all = False
                                break
                                
                    # Direct comparison for non-dict values
                    elif key not in item or item[key] != value:
                        matches_all = False
                        break
                
                if matches_all:
                    return True
                    
        return False
    except Exception as e:
        logger.error(f"Error matching list of dictionaries: {str(e)}")
        return False

def check_field_reference(cloudtrail_record: Dict[str, Any], left_field: str, right_field: str) -> bool:
    """
    Checks if two fields in the record have matching values.
    For ARN fields, extracts the username part for comparison with a username field.

    Args:
        cloudtrail_record (Dict[str, Any]): The CloudTrail record
        left_field (str): The first field to compare
        right_field (str): The second field to compare

    Returns:
        bool: True if the fields match, False otherwise
    """
    try:
        left_val = get_nested_value(cloudtrail_record, left_field)
        right_val = get_nested_value(cloudtrail_record, right_field)
        
        # If both fields exist and have values
        if left_val is not None and right_val is not None:
            # Special handling for ARN comparison with usernames
            if 'arn:aws:' in str(left_val) and 'user/' in str(left_val):
                # Extract username from ARN (e.g., "arn:aws:iam::123456789012:user/admin" -> "admin")
                if 'user/' in str(left_val):
                    user_from_arn = str(left_val).split('user/')[1].split('/')[0]
                    logger.debug(f"Extracted user from ARN: {user_from_arn}, comparing with: {right_val}")
                    return user_from_arn == right_val
                # Handle role ARNs with assumed-role
                elif 'assumed-role/' in str(left_val):
                    role_from_arn = str(left_val).split('assumed-role/')[1].split('/')[0]
                    logger.debug(f"Extracted role from ARN: {role_from_arn}, comparing with: {right_val}")
                    return role_from_arn == right_val
            
            # Default direct equality check
            return left_val == right_val
        
        # If either value is missing, the reference check fails
        return False
    except Exception as e:
        logger.error(f"Error checking field reference: {str(e)}")
        return False

def get_nested_value(obj: Dict[str, Any], dot_path: str) -> Optional[Any]:
    """
    Safely retrieves a nested value from a dictionary using dot notation.
    Also supports array traversal when an array is encountered.

    Args:
        obj (Dict[str, Any]): The dictionary to search
        dot_path (str): The dot-notation path to the value

    Returns:
        Optional[Any]: The value if found, None otherwise

    Example:
        >>> data = {"a": {"b": {"c": 1}}}
        >>> get_nested_value(data, "a.b.c")
        1
        >>> data = {"a": {"b": [{"c": 1}, {"c": 2}]}}
        >>> get_nested_value(data, "a.b.c")  # Will check if any element in b has c
        [1, 2]
    """
    try:
        parts = dot_path.split('.')
        
        # Handle the last part separately for array traversal
        if len(parts) <= 1:
            return obj.get(dot_path) if isinstance(obj, dict) else None
        
        # Traverse to the second-to-last part
        current = obj
        for i in range(len(parts) - 1):
            p = parts[i]
            if not isinstance(current, dict) or p not in current:
                return None
            current = current[p]
            
        # Handle the last part, which might involve arrays
        last_part = parts[-1]
        
        # If current is an array, check each element
        if isinstance(current, list):
            results = []
            for item in current:
                if isinstance(item, dict) and last_part in item:
                    results.append(item[last_part])
            return results if results else None
        
        # Regular dictionary lookup
        if isinstance(current, dict):
            return current.get(last_part)
            
        return None
    except Exception as e:
        logger.error(f"Error getting nested value: {str(e)}")
        return None

def evaluate_condition(condition_expr: str, block_matches: Dict[str, bool]) -> bool:
    """
    Evaluates a Sigma condition expression against block match results.

    Args:
        condition_expr (str): The condition expression to evaluate
        block_matches (Dict[str, bool]): Dictionary of block match results

    Returns:
        bool: True if the condition is met, False otherwise

    Example:
        >>> matches = {"selection": True, "filter": False}
        >>> evaluate_condition("selection and not filter", matches)
        True
    """
    if not condition_expr:
        return False

    try:
        tokens = tokenize_condition(condition_expr)
        if not tokens:
            return False

        idx = 0
        current_val, idx = parse_item(tokens, idx, block_matches)

        while idx < len(tokens):
            op = tokens[idx].lower()
            if op not in ("and", "or"):
                logger.warning(f"Unexpected operator '{op}' in condition '{condition_expr}'")
                return current_val
            
            idx += 1
            next_val, idx = parse_item(tokens, idx, block_matches)
            
            if op == "and":
                current_val = current_val and next_val
            else:  # op == "or"
                current_val = current_val or next_val

        return current_val
    except Exception as e:
        logger.error(f"Error evaluating condition: {str(e)}")
        return False

def tokenize_condition(condition_expr: str) -> List[str]:
    """
    Splits a condition expression into tokens.

    Args:
        condition_expr (str): The condition expression to tokenize

    Returns:
        List[str]: List of tokens
    """
    return [t.strip() for t in condition_expr.split() if t.strip()]

def parse_item(tokens: List[str], idx: int, block_matches: Dict[str, bool]) -> Tuple[bool, int]:
    """
    Parses a single item from the condition expression.

    Args:
        tokens (List[str]): List of tokens
        idx (int): Current index in tokens
        block_matches (Dict[str, bool]): Dictionary of block match results

    Returns:
        Tuple[bool, int]: The parsed result and new index
    """
    if idx >= len(tokens):
        return (False, idx)

    token = tokens[idx]
    token_lower = token.lower()

    if token_lower == "not":
        next_val, new_idx = parse_item(tokens, idx+1, block_matches)
        return (not next_val, new_idx)

    if token_lower.isdigit():
        n = int(token_lower)
        if idx+1 < len(tokens) and tokens[idx+1].lower() == "of":
            if idx+2 < len(tokens):
                target = tokens[idx+2]
                val = evaluate_wildcard_or_block_count(block_matches, target, n)
                return (val, idx+3)
        return (False, idx+1)

    bool_val = evaluate_reference(block_matches, token)
    return (bool_val, idx+1)

def evaluate_reference(block_matches: Dict[str, bool], token: str) -> bool:
    """
    Evaluates a block reference, supporting wildcards.

    Args:
        block_matches (Dict[str, bool]): Dictionary of block match results
        token (str): The block reference to evaluate

    Returns:
        bool: True if the reference matches, False otherwise
    """
    if '*' in token:
        return count_true_matches(block_matches, token) > 0
    return block_matches.get(token, False)

def evaluate_wildcard_or_block_count(block_matches: Dict[str, bool], token: str, n: int) -> bool:
    """
    Evaluates a count condition with optional wildcard.

    Args:
        block_matches (Dict[str, bool]): Dictionary of block match results
        token (str): The block reference to evaluate
        n (int): The required count

    Returns:
        bool: True if the count condition is met, False otherwise
    """
    if '*' in token:
        return count_true_matches(block_matches, token) == n
    block_val = block_matches.get(token, False)
    return (1 if block_val else 0) == n

def count_true_matches(block_matches: Dict[str, bool], pattern: str) -> int:
    """
    Counts matching blocks that evaluate to True.

    Args:
        block_matches (Dict[str, bool]): Dictionary of block match results
        pattern (str): The pattern to match against

    Returns:
        int: The count of matching True blocks
    """
    try:
        regex = re.compile('^' + re.escape(pattern).replace('\\*', '.*') + '$')
        return sum(1 for name, val in block_matches.items() if val and regex.match(name))
    except Exception as e:
        logger.error(f"Error counting true matches: {str(e)}")
        return 0

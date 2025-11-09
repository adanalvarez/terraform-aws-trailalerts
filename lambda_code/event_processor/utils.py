from typing import Any, Dict, List, Optional

def get_nested_value(dict_obj: Optional[Dict[str, Any]], key_list: List[str]) -> Any:
    """
    Retrieves a nested value from a dictionary based on a list of keys.
    
    Args:
        dict_obj: The dictionary to search (can be None)
        key_list: List of keys to traverse
        
    Returns:
        Any: The value at the nested location or None if not found or if dict_obj is None
    """
    if dict_obj is None:
        return None
        
    current = dict_obj
    for key in key_list:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current
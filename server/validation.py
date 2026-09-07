"""JSON payload complexity validation (DoS protection)."""

from typing import Any, Dict

from .constants import PAYLOAD_LIMITS

def validate_json_complexity(data: Any, current_depth: int = 0) -> Dict[str, Any]:
    """
    Recursively validate JSON complexity to prevent DoS attacks.

    Checks:
    - Maximum nesting depth
    - Maximum number of keys in objects
    - Maximum array length
    - Maximum string length

    Returns:
        Dict with 'valid' (bool) and 'error' (str) if invalid
    """
    # Check depth limit
    if current_depth > PAYLOAD_LIMITS['MAX_JSON_DEPTH']:
        return {
            'valid': False,
            'error': f"JSON nesting depth exceeds maximum of {PAYLOAD_LIMITS['MAX_JSON_DEPTH']}"
        }

    # Validate dictionaries/objects
    if isinstance(data, dict):
        # Check number of keys
        if len(data) > PAYLOAD_LIMITS['MAX_OBJECT_KEYS']:
            return {
                'valid': False,
                'error': f"Object contains {len(data)} keys, exceeds maximum of {PAYLOAD_LIMITS['MAX_OBJECT_KEYS']}"
            }

        # Recursively validate values
        for key, value in data.items():
            # Validate key length
            if isinstance(key, str) and len(key) > PAYLOAD_LIMITS['MAX_STRING_LENGTH']:
                return {
                    'valid': False,
                    'error': f"Object key length exceeds maximum of {PAYLOAD_LIMITS['MAX_STRING_LENGTH']}"
                }

            # Recursively validate value
            result = validate_json_complexity(value, current_depth + 1)
            if not result['valid']:
                return result

    # Validate arrays
    elif isinstance(data, list):
        # Check array length
        if len(data) > PAYLOAD_LIMITS['MAX_ARRAY_LENGTH']:
            return {
                'valid': False,
                'error': f"Array length {len(data)} exceeds maximum of {PAYLOAD_LIMITS['MAX_ARRAY_LENGTH']}"
            }

        # Recursively validate elements
        for item in data:
            result = validate_json_complexity(item, current_depth + 1)
            if not result['valid']:
                return result

    # Validate strings
    elif isinstance(data, str):
        if len(data) > PAYLOAD_LIMITS['MAX_STRING_LENGTH']:
            return {
                'valid': False,
                'error': f"String length {len(data)} exceeds maximum of {PAYLOAD_LIMITS['MAX_STRING_LENGTH']}"
            }

    # Other types (int, float, bool, None) are inherently safe

    return {'valid': True, 'error': None}

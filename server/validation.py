from .constants import PAYLOAD_LIMITS

def validate_json_complexity(data, depth=0):
    if depth > PAYLOAD_LIMITS['MAX_JSON_DEPTH']:
        return {'valid': False, 'error': 'JSON depth exceeded'}

    if isinstance(data, dict):
        if len(data) > PAYLOAD_LIMITS['MAX_OBJECT_KEYS']:
            return {'valid': False, 'error': 'Too many object keys'}
        for v in data.values():
            r = validate_json_complexity(v, depth + 1)
            if not r['valid']:
                return r

    elif isinstance(data, list):
        if len(data) > PAYLOAD_LIMITS['MAX_ARRAY_LENGTH']:
            return {'valid': False, 'error': 'Array too large'}
        for i in data:
            r = validate_json_complexity(i, depth + 1)
            if not r['valid']:
                return r

    elif isinstance(data, str):
        if len(data) > PAYLOAD_LIMITS['MAX_STRING_LENGTH']:
            return {'valid': False, 'error': 'String too long'}

    return {'valid': True, 'error': None}

import sys, uuid, traceback

def sanitize_error(error: Exception, context: str = ""):
    error_id = str(uuid.uuid4())[:8]
    print(f"[ERROR {error_id}] {context}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    return error_id, f"An internal error occurred. Error ID: {error_id}"

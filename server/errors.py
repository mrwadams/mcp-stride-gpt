"""Error sanitisation: generic messages to clients, full detail to server logs."""

import sys
import traceback
import uuid

def sanitize_error(error: Exception, error_context: str = "") -> tuple[str, str]:
    """
    Sanitize error messages to prevent information disclosure.

    Returns:
        tuple: (error_id, sanitized_message) where:
            - error_id: Unique identifier for correlating with server logs
            - sanitized_message: Generic error message safe for client

    Security measures:
        - Logs full error details to server logs (stderr)
        - Returns generic message to client
        - Generates unique error ID for correlation
        - Prevents leakage of: stack traces, file paths, internal implementation details
    """
    # Generate unique error ID for correlation
    error_id = str(uuid.uuid4())[:8]

    # Log detailed error information to server logs (stderr goes to Vercel logs)
    print(f"[ERROR {error_id}] Context: {error_context}", file=sys.stderr)
    print(f"[ERROR {error_id}] Exception Type: {type(error).__name__}", file=sys.stderr)
    print(f"[ERROR {error_id}] Exception Message: {str(error)}", file=sys.stderr)
    print(f"[ERROR {error_id}] Stack Trace:", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)

    # Return generic message safe for client
    sanitized_message = f"An internal error occurred. Error ID: {error_id}"

    return error_id, sanitized_message

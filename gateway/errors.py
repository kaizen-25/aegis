"""Exceptions shared across the gateway."""


class FailClosed(Exception):
    """Validation error, missing context or anything the gateway cannot evaluate safely.

    Raised anywhere before a verdict is reached. The propose wrapper turns it into a
    BLOCK / FAIL_CLOSED Decision, never an HTTP error.
    """


class ToolError(Exception):
    """A tool failed while running (for example a missing file). Becomes EXECUTION_FAILED."""


class ApiError(Exception):
    """A non-2xx response. Rendered as {"error": ..., "code": ...}."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

"""Domain exception classes for SAST Triage Platform."""


class SastTriageError(Exception):
    """Base exception for domain runtime errors in SAST Triage Platform.

    This exception class is used for application flow control.
    It carries a safe message (no secrets, raw source, or tracebacks),
    an error code, and a retryable flag.
    """

    def __init__(
        self, safe_message: str, error_code: str = "GENERIC_ERROR", retryable: bool = False
    ) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.error_code = error_code
        self.retryable = retryable

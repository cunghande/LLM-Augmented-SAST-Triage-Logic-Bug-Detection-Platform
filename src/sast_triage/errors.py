"""Các lớp exception domain cho nền tảng SAST Triage."""


class SastTriageError(Exception):
    """Exception gốc cho lỗi runtime domain của SAST Triage Platform.

    Lớp exception này dùng để điều khiển luồng ứng dụng. Nó mang thông báo
    an toàn (không có secret, mã nguồn thô hoặc traceback), mã lỗi và cờ
    cho biết có thể thử lại.
    """

    def __init__(
        self, safe_message: str, error_code: str = "GENERIC_ERROR", retryable: bool = False
    ) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message
        self.error_code = error_code
        self.retryable = retryable

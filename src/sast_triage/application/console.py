"""Thông báo CLI an toàn và dễ đọc."""

import sys


def configure_console_encoding() -> None:
    """Ưu tiên UTF-8 để PowerShell cũ vẫn in được tiếng Việt."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def show_progress(stage: str, message: str) -> None:
    """In tiến trình, không đưa source hoặc payload ra màn hình."""
    print(f"[{stage}] {message}", flush=True)


def safe_error_message(error_code: str) -> str:
    """Đổi mã lỗi nội bộ thành thông báo tiếng Việt an toàn."""
    exact_messages = {
        "CLI_INVALID_REPOSITORY": "Thư mục repository không tồn tại hoặc không hợp lệ.",
        "CLI_INVALID_ARTIFACT": "Đường dẫn scanner artifact không hợp lệ.",
        "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED": (
            "Modal đã hết credit, quota hoặc tài nguyên; tiến độ đã được lưu."
        ),
        "TRIAGE_PROVIDER_MODAL_AUTH_ERROR": (
            "Chưa xác thực Modal; hãy chạy 'python -m modal setup' một lần."
        ),
        "TRIAGE_PROVIDER_MODAL_TIMEOUT": "Yêu cầu Qwen trên Modal đã quá thời gian chờ.",
        "TRIAGE_PROVIDER_DEPENDENCY_MISSING": (
            "Python hiện tại chưa cài dependency Modal; hãy dùng môi trường dự án hoặc cài extra LLM."
        ),
        "CHECKPOINT_NOT_FOUND": "Không tìm thấy checkpoint để tiếp tục.",
        "CHECKPOINT_BINDING_MISMATCH": (
            "Checkpoint không khớp repository, artifact hoặc phiên bản prompt hiện tại."
        ),
        "CHECKPOINT_INVALID": "Checkpoint không hợp lệ hoặc không thể đọc an toàn.",
    }
    if error_code in exact_messages:
        return exact_messages[error_code]
    if error_code.startswith(("SCANNER", "PARSE")):
        return "Scanner hoặc artifact gặp lỗi; hãy kiểm tra công cụ và file đầu vào."
    if error_code.startswith("REPORT"):
        return "Không thể kiểm tra hoặc ghi báo cáo an toàn."
    if error_code.startswith("TRIAGE_PROVIDER"):
        return "LLM provider gặp lỗi; finding liên quan không bị loại bỏ."
    if error_code.startswith("CHECKPOINT"):
        return "Không thể đọc hoặc ghi checkpoint an toàn."
    return "CLI không thể hoàn tất do lỗi cấu hình hoặc dữ liệu đầu vào."


def show_error(error_code: str) -> None:
    """In lỗi đã được làm sạch ra stderr."""
    print(
        f"LỖI [{error_code}]: {safe_error_message(error_code)}",
        file=sys.stderr,
        flush=True,
    )

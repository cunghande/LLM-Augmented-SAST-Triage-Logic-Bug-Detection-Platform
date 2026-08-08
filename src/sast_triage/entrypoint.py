"""Điểm vào module/console thân thiện, có tóm tắt lần chạy an toàn."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from sast_triage.application.console import configure_console_encoding
from sast_triage.checkpoint import CHECKPOINT_FILENAME, read_checkpoint_summary
from sast_triage.cli import main as run_cli


def _prepare_arguments(arguments: list[str]) -> tuple[list[str], bool]:
    """Giữ nguyên provider CLI; Ollama nay là một lựa chọn độc lập."""
    prepared = list(arguments)
    uses_ollama = any(
        value.lower() == "--provider=ollama"
        or (
            value == "--provider"
            and index + 1 < len(prepared)
            and prepared[index + 1].lower() == "ollama"
        )
        for index, value in enumerate(prepared)
    )
    return prepared, uses_ollama


def _argument_value(arguments: list[str], option: str) -> str | None:
    for index, value in enumerate(arguments):
        if value == option and index + 1 < len(arguments):
            return arguments[index + 1]
        prefix = f"{option}="
        if value.startswith(prefix):
            return value[len(prefix) :]
    return None


def _display_path(path: Path) -> str:
    """Trả về đường dẫn hữu ích mà không để lộ đường dẫn tuyệt đối không cần thiết."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return path.name


def _print_summary(output_dir_text: str | None, exit_code: int) -> None:
    if output_dir_text is None:
        print(f"CLI kết thúc với exit code {exit_code}.", flush=True)
        return
    output_dir = Path(output_dir_text)
    metadata_path = output_dir / "run-metadata.json"
    report_path = output_dir / "report.json"
    if not metadata_path.is_file():
        checkpoint = read_checkpoint_summary(output_dir / CHECKPOINT_FILENAME)
        if checkpoint and checkpoint.get("status") == "resource_exhausted":
            print(
                "Modal đã hết credit/quota/tài nguyên sau khi hoàn thành "
                f"{checkpoint.get('completed_count', 0)}/{checkpoint.get('total_count', 0)} "
                "finding. Tiến độ đã được lưu; hãy chạy lại cùng lệnh với "
                "--provider ollama --resume.",
                file=sys.stderr,
                flush=True,
            )
            return
        print(
            f"CLI thất bại với exit code {exit_code}; chưa tạo được báo cáo.",
            file=sys.stderr,
            flush=True,
        )
        return
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        print(
            f"CLI kết thúc với exit code {exit_code}; không thể đọc metadata báo cáo.",
            file=sys.stderr,
            flush=True,
        )
        return
    total = metadata.get("total_findings_parsed", 0)
    succeeded = metadata.get("findings_triaged_ok", 0)
    failed = metadata.get("findings_with_errors", 0)
    print(
        f"Hoàn tất: đã_parse={total}, triage_thành_công={succeeded}, có_lỗi={failed}, "
        f"exit_code={exit_code}",
        flush=True,
    )
    print(f"Báo cáo JSON: {_display_path(report_path)}", flush=True)
    print(f"Báo cáo Markdown: {_display_path(output_dir / 'report.md')}", flush=True)


def main(argv: list[str] | None = None) -> int:
    """Chạy CLI với mặc định Ollama và trạng thái hiển thị an toàn."""
    configure_console_encoding()
    arguments = list(sys.argv[1:] if argv is None else argv)
    prepared, uses_ollama = _prepare_arguments(arguments)
    command = prepared[0] if prepared else None
    if command == "scan-and-triage":
        selected_provider = _argument_value(prepared, "--provider") or "fake"
        if uses_ollama:
            provider_label = os.getenv("SAST_TRIAGE_LLM_MODEL", "qwen3:8b") + " trên Ollama"
        elif selected_provider == "real":
            provider_label = "Qwen3-14B-AWQ trên Modal"
        else:
            provider_label = "provider giả lập"
        print(
            f"Đang bắt đầu scanner và triage tuần tự bằng {provider_label}. "
            "Repository lớn có thể cần nhiều thời gian.",
            flush=True,
        )
    exit_code = run_cli(prepared)
    _print_summary(_argument_value(prepared, "--output-dir"), exit_code)
    return exit_code

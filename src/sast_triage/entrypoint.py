"""Điểm vào module/console thân thiện, có tóm tắt lần chạy an toàn."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from sast_triage.application.console import configure_console_encoding
from sast_triage.checkpoint import CHECKPOINT_FILENAME, read_checkpoint_summary
from sast_triage.cli import main as run_cli

_COMMANDS = frozenset({"triage", "scan-and-triage", "cache-clear"})
_MODAL_B200_GPU_RATE_USD_PER_HOUR = "6.25"
_DEFAULT_CACHE_TTL_HOURS = "168"


def _automatic_output_dir(repository: Path, timestamp: str | None = None) -> Path:
    """Chọn thư mục run mới cạnh ``target-repos`` cho lệnh quét rút gọn."""
    resolved = repository.resolve()
    if resolved.parent.name.casefold() == "target-repos":
        runs_root = resolved.parent.parent / "triage-runs"
    else:
        runs_root = resolved.parent / "triage-runs"
    run_stamp = timestamp or datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")
    base = runs_root / f"{resolved.name}-qwen14b-{run_stamp}"
    candidate = base
    suffix = 2
    while candidate.exists():
        candidate = Path(f"{base}-{suffix:02d}")
        suffix += 1
    return candidate


def _automatic_cache_dir(repository: Path) -> Path:
    """Choose one stable cache outside the target repository for shortcut runs."""
    resolved = repository.resolve()
    if resolved.parent.name.casefold() == "target-repos":
        cache_root = resolved.parent.parent / "triage-cache"
    else:
        cache_root = resolved.parent / "triage-cache"
    return cache_root / resolved.name


def _has_option(arguments: list[str], option: str) -> bool:
    """Return whether shortcut arguments explicitly configure an option."""
    negative_option = f"--no-{option.removeprefix('--')}"
    return any(
        value in {option, negative_option}
        or value.startswith(f"{option}=")
        for value in arguments
    )


def _expand_repository_shortcut(arguments: list[str]) -> list[str]:
    """Biến ``sast-triage REPO`` thành lần quét Qwen3-14B đầy đủ."""
    if not arguments or arguments[0] in _COMMANDS or arguments[0].startswith("-"):
        return list(arguments)
    repository = Path(arguments[0])
    output_dir = _automatic_output_dir(repository)
    cache_dir = _automatic_cache_dir(repository)
    extra_arguments = arguments[1:]
    full_analysis_options: list[str] = []
    if not _has_option(extra_arguments, "--module2-discovery"):
        full_analysis_options.append("--module2-discovery")
    if not _has_option(extra_arguments, "--logic-detector"):
        full_analysis_options.extend(
            ("--logic-detector", "python-idor-business-logic")
        )
    if not _has_option(extra_arguments, "--decision-cache-dir"):
        full_analysis_options.extend(("--decision-cache-dir", str(cache_dir)))
    if not _has_option(extra_arguments, "--decision-cache-ttl-hours"):
        full_analysis_options.extend(
            ("--decision-cache-ttl-hours", _DEFAULT_CACHE_TTL_HOURS)
        )
    selected_provider = _argument_value(extra_arguments, "--provider") or "real"
    if (
        selected_provider == "real"
        and not _has_option(extra_arguments, "--provider-cost-per-hour-usd")
    ):
        full_analysis_options.extend(
            (
                "--provider-cost-per-hour-usd",
                _MODAL_B200_GPU_RATE_USD_PER_HOUR,
            )
        )
    return [
        "scan-and-triage",
        "--repository",
        str(repository),
        "--output-dir",
        str(output_dir),
        "--provider",
        "real",
        "--semgrep-config",
        "p/python",
        "--semgrep-config",
        "p/security-audit",
        *full_analysis_options,
        *extra_arguments,
    ]


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
    selected: str | None = None
    for index, value in enumerate(arguments):
        if value == option and index + 1 < len(arguments):
            selected = arguments[index + 1]
        prefix = f"{option}="
        if value.startswith(prefix):
            selected = value[len(prefix) :]
    return selected


def _display_path(path: Path) -> str:
    """Trả về đường dẫn hữu ích mà không để lộ đường dẫn tuyệt đối không cần thiết."""
    try:
        return os.path.relpath(path.resolve(), Path.cwd().resolve())
    except (OSError, ValueError):
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
    print(f"Báo cáo HTML: {_display_path(output_dir / 'report.html')}", flush=True)


def main(argv: list[str] | None = None) -> int:
    """Chạy CLI với mặc định Ollama và trạng thái hiển thị an toàn."""
    configure_console_encoding()
    arguments = _expand_repository_shortcut(
        list(sys.argv[1:] if argv is None else argv)
    )
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

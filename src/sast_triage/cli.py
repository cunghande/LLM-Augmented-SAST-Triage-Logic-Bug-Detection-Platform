"""Giao diện dòng lệnh cho SAST Triage."""

import argparse
from pathlib import Path

from sast_triage.application.console import show_error
from sast_triage.application.run import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_PROVIDER_RESOURCE_EXHAUSTED,
    EXIT_REPORT_ERROR,
    EXIT_SCANNER_ERROR,
    EXIT_SUCCESS,
    execute_run,
)
from sast_triage.cache.decision_cache import DecisionCache
from sast_triage.errors import SastTriageError

__all__ = [
    "EXIT_CONFIGURATION_ERROR",
    "EXIT_PROVIDER_RESOURCE_EXHAUSTED",
    "EXIT_REPORT_ERROR",
    "EXIT_SCANNER_ERROR",
    "EXIT_SUCCESS",
    "main",
]


def build_parser() -> argparse.ArgumentParser:
    """Tạo parser cho hai chế độ dùng chung pipeline."""
    parser = argparse.ArgumentParser(
        description="Quét và phân loại finding bảo mật bằng SAST + LLM"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    triage = commands.add_parser(
        "triage", help="Phân loại từ artifact Semgrep/Gitleaks có sẵn"
    )
    _add_common_arguments(triage)
    triage.add_argument(
        "--semgrep-json", "--semgrep-report", dest="semgrep_json", required=True
    )
    triage.add_argument(
        "--gitleaks-json", "--gitleaks-report", dest="gitleaks_json", required=True
    )

    scan = commands.add_parser(
        "scan-and-triage", help="Chạy scanner rồi phân loại kết quả"
    )
    _add_common_arguments(scan)
    cache_clear = commands.add_parser(
        "cache-clear",
        help="Xóa validated decision cache mà không chạy scanner",
    )
    cache_clear.add_argument("--cache-dir", required=True)
    cache_clear.add_argument(
        "--expired-only",
        action="store_true",
        help="Chỉ xóa entry đã hết hạn",
    )
    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repository",
        "--repo-path",
        dest="repository",
        required=True,
        help="Đường dẫn repository Python cần kiểm tra",
    )
    parser.add_argument("--output-dir", required=True, help="Thư mục chứa kết quả")
    parser.add_argument(
        "--provider",
        choices=("fake", "ollama", "real"),
        default="fake",
        help="fake=không LLM, ollama=LLM local, real=Qwen3-14B trên Modal",
    )
    parser.add_argument("--prompt-version", default="triage-prompt-v15")
    parser.add_argument("--output-schema-version", default="triage-decision-v1")
    parser.add_argument("--prompt-type", default="fake.default")
    parser.add_argument("--repository-identifier", default=None)
    parser.add_argument(
        "--semgrep-config",
        action="append",
        default=None,
        help="Repeatable Semgrep registry ruleset or local YAML path (default: p/python)",
    )
    parser.add_argument(
        "--gitleaks-config",
        default=None,
        help="Optional Gitleaks config path; built-in rules are used when omitted",
    )
    parser.add_argument(
        "--module2",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable bounded Python cross-file index and evidence routing (default: enabled)",
    )
    parser.add_argument(
        "--module2-discovery",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "Experimental: add bounded Module 2 findings in addition to scanner "
            "findings (default: disabled)"
        ),
    )
    parser.add_argument(
        "--logic-detector",
        choices=("off", "python-idor-business-logic"),
        default="off",
        help=(
            "Explicit Sprint 2 detector: python-idor-business-logic analyzes "
            "missing authorization/IDOR and business-rule bypass (default: off)"
        ),
    )
    parser.add_argument(
        "--overwrite", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Tiếp tục các finding đã lưu trong checkpoint",
    )
    parser.add_argument(
        "--decision-cache-dir",
        default=None,
        help="Thư mục cache TriageDecision đã validate; bỏ qua để tắt cache",
    )
    parser.add_argument(
        "--decision-cache-ttl-hours",
        type=int,
        default=168,
        help="Thời hạn cache theo giờ (mặc định: 168)",
    )
    parser.add_argument(
        "--provider-cost-per-hour-usd",
        type=float,
        default=None,
        help="Đơn giá provider USD/giờ để ước tính chi phí; mặc định không tính",
    )


def main(argv: list[str] | None = None) -> int:
    """Parse tham số, chạy ứng dụng và trả exit code ổn định."""
    args = build_parser().parse_args(argv)
    try:
        if args.command == "cache-clear":
            cache = DecisionCache(Path(args.cache_dir), ttl_seconds=1)
            removed = cache.clear(expired_only=args.expired_only)
            print(f"Đã xóa {removed} decision cache entr{'y' if removed == 1 else 'ies'}.")
            return EXIT_SUCCESS
        return execute_run(args)
    except SastTriageError as exc:
        show_error(exc.error_code)
        if exc.error_code == "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED":
            return EXIT_PROVIDER_RESOURCE_EXHAUSTED
        if exc.error_code.startswith(("SCANNER", "PARSE")):
            return EXIT_SCANNER_ERROR
        if exc.error_code.startswith("REPORT"):
            return EXIT_REPORT_ERROR
        return EXIT_CONFIGURATION_ERROR
    except OSError:
        show_error("CLI_OS_ERROR")
        return EXIT_REPORT_ERROR

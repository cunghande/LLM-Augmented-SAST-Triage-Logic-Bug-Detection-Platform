"""Giao diện dòng lệnh cho SAST Triage."""

import argparse

from sast_triage.application.console import show_error
from sast_triage.application.run import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_PROVIDER_RESOURCE_EXHAUSTED,
    EXIT_REPORT_ERROR,
    EXIT_SCANNER_ERROR,
    EXIT_SUCCESS,
    execute_run,
)
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
    parser.add_argument("--prompt-version", default="triage-prompt-v11")
    parser.add_argument("--output-schema-version", default="triage-decision-v1")
    parser.add_argument("--prompt-type", default="fake.default")
    parser.add_argument("--repository-identifier", default=None)
    parser.add_argument(
        "--analysis-backend",
        choices=("native", "joern"),
        default="native",
        help="Backend phân tích: native (mặc định) hoặc Joern CPG qua Docker",
    )
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
        choices=("off", "fastapi-missing-authz"),
        default="off",
        help=(
            "Explicit logic detector: fastapi-missing-authz enables the bounded "
            "FastAPI function-level authorization detector (default: off)"
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


def main(argv: list[str] | None = None) -> int:
    """Parse tham số, chạy ứng dụng và trả exit code ổn định."""
    args = build_parser().parse_args(argv)
    try:
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

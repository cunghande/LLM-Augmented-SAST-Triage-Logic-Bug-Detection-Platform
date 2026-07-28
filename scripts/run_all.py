"""
Run Full Pipeline — Quét, Phân tích, Đánh giá rủi ro và Sinh báo cáo cho 1 Repository.
=======================================================================================
Script chạy toàn bộ 6 bước pipeline cho repo mới nhất vừa clone (hoặc repo chỉ định).

Cách dùng:
  python scripts/run_all.py                    # Tự động chọn repo mới nhất
  python scripts/run_all.py --repo CN_WEB      # Chỉ định repo cụ thể
"""

import sys
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
REPOS_DIR = ROOT_DIR / "repos"
SCANS_DIR = ROOT_DIR / "scans"
REPORTS_DIR = ROOT_DIR / "reports"


def detect_latest_repo() -> Path:
    """Tự động phát hiện repo mới nhất trong repos/ theo thời gian modified."""
    repo_dirs = [d for d in REPOS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    if not repo_dirs:
        print("[!] Không tìm thấy repository nào trong repos/")
        sys.exit(1)
    latest = max(repo_dirs, key=lambda d: d.stat().st_mtime)
    return latest


def run_step(step_name: str, cmd: list):
    """Chạy 1 bước trong pipeline và in kết quả."""
    print(f"\n{'='*60}")
    print(f"  {step_name}")
    print(f"{'='*60}")
    print(f"  $ {' '.join(cmd)}\n")

    result = subprocess.run(cmd, cwd=str(ROOT_DIR), encoding="utf-8", errors="replace")
    if result.returncode != 0:
        print(f"  [!] Warning: Step exited with code {result.returncode}")
    return result.returncode


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run full security analysis pipeline on a repository")
    parser.add_argument("--repo", help="Repository folder name (e.g. CN_WEB). Default: auto-detect latest.")
    args = parser.parse_args()

    # Xác định repo mục tiêu
    if args.repo:
        repo_dir = REPOS_DIR / args.repo
        if not repo_dir.exists():
            print(f"[!] Repository {repo_dir} not found!")
            sys.exit(1)
    else:
        repo_dir = detect_latest_repo()

    repo_name = repo_dir.name
    scan_dir = SCANS_DIR / repo_name
    report_dir = REPORTS_DIR / repo_name

    print(f"\n{'#'*60}")
    print(f"  FULL PIPELINE — Repository: {repo_name}")
    print(f"  Repo Path  : {repo_dir}")
    print(f"  Scans Path : {scan_dir}")
    print(f"  Reports Path: {report_dir}")
    print(f"{'#'*60}")

    # ── Step 1: Quét Semgrep + Gitleaks ──────────────────────────────────────
    run_step(
        "STEP 1/6: Quét SAST (Semgrep + Gitleaks)",
        [sys.executable, "scripts/run_scans.py", "--repo", repo_name]
    )

    # ── Step 2: Triage SAST findings bằng LLM Qwen 3:8b ─────────────────────
    triage_output = str(report_dir / "triage_result.json")
    run_step(
        "STEP 2/6: Triage SAST Findings (Agent 1 — Qwen 3:8b)",
        [sys.executable, "-m", "src.cli", "triage",
         "--scans-dir", str(scan_dir),
         "--repo-dir", str(repo_dir),
         "--repo-name", repo_name,
         "--output", triage_output]
    )

    # ── Step 3: Phát hiện Logic Bugs qua CPG (Agent 2) ───────────────────────
    logic_output = str(report_dir / "logic_bugs.json")
    run_step(
        "STEP 3/6: Phát hiện Logic Bugs (Agent 2 — CPG + Qwen 3:8b)",
        [sys.executable, "-m", "src.cli", "detect-logic-bugs",
         "--repo-dir", str(repo_dir),
         "--repo-name", repo_name,
         "--output", logic_output]
    )

    # ── Step 4: Tính điểm Risk Score (Agent 3a) ──────────────────────────────
    risk_output = str(report_dir / "risk_report.json")
    run_step(
        "STEP 4/6: Tính điểm Risk Score (Agent 3a)",
        [sys.executable, "-m", "src.cli", "score-risk",
         "--input", triage_output,
         "--output", risk_output]
    )

    # ── Step 5: Sinh bản vá Code Diff (Agent 3b) ─────────────────────────────
    remediation_output = str(report_dir / "remediation_report.json")
    run_step(
        "STEP 5/6: Sinh bản vá Remediation (Agent 3b)",
        [sys.executable, "-m", "src.cli", "generate-remediation",
         "--input", triage_output,
         "--output", remediation_output]
    )

    # ── Step 6: Sinh Priority Report ──────────────────────────────────────────
    priority_output = str(report_dir / "priority_report.md")
    run_step(
        "STEP 6/6: Sinh Priority Report (Executive Summary)",
        [sys.executable, "-m", "src.cli", "priority-report",
         "--input", triage_output,
         "--repo-name", repo_name,
         "--output", priority_output]
    )

    # ── Tóm tắt kết quả ─────────────────────────────────────────────────────
    print(f"\n{'#'*60}")
    print(f"  ✅ PIPELINE HOÀN TẤT — Repository: {repo_name}")
    print(f"{'#'*60}")
    print(f"  Báo cáo đầu ra:")
    print(f"    ├── {report_dir / 'triage_result.json'}")
    print(f"    ├── {report_dir / 'logic_bugs.json'}")
    print(f"    ├── {report_dir / 'risk_report.json'}")
    print(f"    ├── {report_dir / 'remediation_report.json'}")
    print(f"    └── {report_dir / 'priority_report.md'}")
    print()


if __name__ == "__main__":
    main()

import sys
import argparse
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
REPOS_BASE_DIR = ROOT_DIR / "repos"
SCANS_BASE_DIR = ROOT_DIR / "scans"


def detect_latest_repo() -> Path:
    """
    Tự động phát hiện repository mới nhất trong repos/ dựa trên thời gian sửa đổi.
    ⚠️ QUAN TRỌNG: Sau khi clone repo mới, chạy lệnh không cần chỉ định tên repo.
    """
    repo_dirs = [d for d in REPOS_BASE_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    if not repo_dirs:
        print("[!] Không tìm thấy thư mục repository nào trong repos/")
        sys.exit(1)

    # Sắp xếp theo thời gian sửa đổi giảm dần → repo mới nhất lên đầu
    latest = max(repo_dirs, key=lambda d: d.stat().st_mtime)
    print(f"[*] Auto-detected latest repo: {latest.name}")
    return latest


def run_gitleaks_for_repo(repo_dir: Path, scan_dir: Path):
    scan_dir.mkdir(parents=True, exist_ok=True)
    out_file = scan_dir / "gitleaks.json"
    cmd = ["gitleaks", "detect", "--source", str(repo_dir), "--report-format", "json", "--report-path", str(out_file), "--no-git"]
    print(f"[*] Running Gitleaks on {repo_dir.name}: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(f"[+] Gitleaks exit code: {res.returncode}")
    print(f"[+] Saved output to {out_file}")
    return res.returncode


def run_semgrep_for_repo(repo_dir: Path, scan_dir: Path):
    scan_dir.mkdir(parents=True, exist_ok=True)
    out_json = scan_dir / "semgrep.json"
    out_sarif = scan_dir / "semgrep.sarif"
    
    cmd_json = ["semgrep", "scan", "--config", "auto", "--json", "--output", str(out_json), str(repo_dir)]
    print(f"[*] Running Semgrep JSON on {repo_dir.name}: {' '.join(cmd_json)}")
    res1 = subprocess.run(cmd_json, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(f"[+] Semgrep JSON exit code: {res1.returncode}")
    
    cmd_sarif = ["semgrep", "scan", "--config", "auto", "--sarif", "--output", str(out_sarif), str(repo_dir)]
    print(f"[*] Running Semgrep SARIF on {repo_dir.name}: {' '.join(cmd_sarif)}")
    res2 = subprocess.run(cmd_sarif, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(f"[+] Semgrep SARIF exit code: {res2.returncode}")

    return res1.returncode


def scan_single_repo(repo_dir: Path, skip_existing: bool = False):
    if not repo_dir.exists() or not repo_dir.is_dir():
        print(f"[!] Target repository directory {repo_dir} does not exist.")
        return

    repo_name = repo_dir.name
    scan_dir = SCANS_BASE_DIR / repo_name
    
    gitleaks_file = scan_dir / "gitleaks.json"
    semgrep_file = scan_dir / "semgrep.json"

    if skip_existing and gitleaks_file.exists() and semgrep_file.exists():
        print(f"[*] Skipping {repo_name} (scan files already exist in {scan_dir}).")
        return

    print(f"\n==================================================")
    print(f"=== Scanning Repository: {repo_name} ===")
    print(f"==================================================")
    
    run_gitleaks_for_repo(repo_dir, scan_dir)
    run_semgrep_for_repo(repo_dir, scan_dir)
    print(f"[OK] Finished scanning {repo_name}. Outputs saved in {scan_dir}\n")


def main():
    parser = argparse.ArgumentParser(description="Automated SAST Scan Runner for Repositories")
    parser.add_argument("--repo", help="Specific repository folder name under repos/ (e.g. Sequential-Recommender)")
    parser.add_argument("--latest", action="store_true", help="Auto-detect and scan only the latest cloned repo (newest by modified time)")
    parser.add_argument("--skip-existing", action="store_true", help="Skip repositories that already have scan results")
    args = parser.parse_args()

    if args.latest:
        # Tự động phát hiện repo mới nhất vừa clone
        latest_repo = detect_latest_repo()
        scan_single_repo(latest_repo, skip_existing=args.skip_existing)
    elif args.repo:
        target_dir = REPOS_BASE_DIR / args.repo
        scan_single_repo(target_dir, skip_existing=args.skip_existing)
    else:
        # Discover all subdirectories under repos/
        repo_dirs = [d for d in REPOS_BASE_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
        if not repo_dirs:
            print("[!] No repository directories found under repos/")
            return
        
        for rdir in repo_dirs:
            scan_single_repo(rdir, skip_existing=args.skip_existing)


if __name__ == "__main__":
    main()


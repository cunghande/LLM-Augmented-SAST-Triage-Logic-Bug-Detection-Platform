import json
import hashlib
from typing import List, Union, Dict, Any
from pathlib import Path
from src.core.schema import UnifiedFinding, ScannerType, Severity, FindingStatus


def parse_gitleaks_json(content_or_path: Union[str, Path], repository_name: str = "CN_WEB") -> List[UnifiedFinding]:
    """Parse Gitleaks JSON report into unified finding objects."""
    data = []
    try:
        if isinstance(content_or_path, (str, Path)) and Path(content_or_path).exists():
            content = Path(content_or_path).read_text(encoding="utf-8", errors="replace").strip()
            if content:
                data = json.loads(content)
        elif isinstance(content_or_path, str) and content_or_path.strip():
            data = json.loads(content_or_path)
        elif isinstance(content_or_path, list):
            data = content_or_path
    except Exception as e:
        print(f"[!] Warning: Failed to parse Gitleaks JSON ({e})")
        return []

    if not isinstance(data, list):
        data = []

    findings: List[UnifiedFinding] = []
    for idx, item in enumerate(data):
        rule_id = item.get("RuleID", "gitleaks-secret")
        file_path = item.get("File", "unknown")
        start_line = item.get("StartLine", 1)
        end_line = item.get("EndLine", start_line)
        match_str = item.get("Match", item.get("Secret", ""))
        commit_sha = item.get("Commit", "HEAD")
        
        raw_id = f"GITLEAKS-{repository_name}-{rule_id}-{file_path}-{start_line}-{idx}"
        finding_id = hashlib.md5(raw_id.encode("utf-8")).hexdigest()[:12].upper()

        finding = UnifiedFinding(
            finding_id=f"GL-{finding_id}",
            scanner=ScannerType.GITLEAKS,
            rule_id=rule_id,
            repository=repository_name,
            commit_sha=commit_sha,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=match_str,
            severity=Severity.HIGH,
            metadata={
                "description": item.get("Description", ""),
                "entropy": item.get("Entropy", 0.0),
                "author": item.get("Author", ""),
                "date": item.get("Date", ""),
                "tags": item.get("Tags", []),
                "gitleaks_fingerprint": item.get("Fingerprint", ""),
            },
            status=FindingStatus.NEW
        )
        finding.compute_fingerprint()
        findings.append(finding)

    return findings

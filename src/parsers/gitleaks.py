"""
Gitleaks JSON Parser Module
===========================
Parses Gitleaks scanner JSON output into UnifiedFinding objects, setting the branch
to SAST_TRIAGE_BRANCH and categorizing secrets according to SecretTaxonomy.
"""

import json
import hashlib
from typing import List, Union
from pathlib import Path
from src.core.schema import UnifiedFinding, ScannerType, BranchType, Severity, FindingStatus, SecretTaxonomy


def classify_gitleaks_secret(match_str: str, file_path: str) -> SecretTaxonomy:
    """Apply heuristic secret taxonomy classification to Gitleaks findings."""
    lower_match = match_str.lower()
    lower_path = file_path.lower()

    if any(k in lower_path for k in ["test", "mock", "fixture", "spec", "example", "sample"]):
        return SecretTaxonomy.TEST_CREDENTIAL
    if any(p in lower_match for p in ["your_key", "dummy", "placeholder", "xxx", "123456", "change_me", "example"]):
        return SecretTaxonomy.PLACEHOLDER
    if "ghp_" in match_str or "AKIA" in match_str:
        return SecretTaxonomy.VALID_SECRET
    return SecretTaxonomy.UNKNOWN_VALIDITY


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

        taxonomy = classify_gitleaks_secret(match_str, file_path)

        finding = UnifiedFinding(
            finding_id=f"GL-{finding_id}",
            scanner=ScannerType.GITLEAKS,
            branch_type=BranchType.SAST_TRIAGE_BRANCH,
            rule_id=rule_id,
            repository=repository_name,
            commit_sha=commit_sha,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=match_str,
            severity=Severity.HIGH,
            secret_taxonomy=taxonomy,
            metadata={
                "description": item.get("Description", ""),
                "entropy": item.get("Entropy", 0.0),
                "author": item.get("Author", ""),
                "date": item.get("Date", ""),
                "tags": item.get("Tags", []),
                "gitleaks_fingerprint": item.get("Fingerprint", ""),
                "rule_family": "secret-detection"
            },
            status=FindingStatus.NEW
        )
        finding.compute_fingerprint()
        findings.append(finding)

    return findings

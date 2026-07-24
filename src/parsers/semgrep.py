import json
import hashlib
from typing import List, Union, Dict, Any
from pathlib import Path
from src.core.schema import UnifiedFinding, ScannerType, Severity, FindingStatus


SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def parse_semgrep_json(content_or_path: Union[str, Path], repository_name: str = "CN_WEB") -> List[UnifiedFinding]:
    """Parse Semgrep JSON report into unified finding objects."""
    data = {}
    try:
        if isinstance(content_or_path, (str, Path)) and Path(content_or_path).exists():
            content = Path(content_or_path).read_text(encoding="utf-8", errors="replace").strip()
            if content:
                data = json.loads(content)
        elif isinstance(content_or_path, str) and content_or_path.strip():
            data = json.loads(content_or_path)
        elif isinstance(content_or_path, dict):
            data = content_or_path
    except Exception as e:
        print(f"[!] Warning: Failed to parse Semgrep JSON ({e})")
        return []

    results = data.get("results", []) if isinstance(data, dict) else []
    findings: List[UnifiedFinding] = []

    for idx, item in enumerate(results):
        rule_id = item.get("check_id", "semgrep-finding")
        file_path = item.get("path", "unknown")
        start_info = item.get("start", {})
        end_info = item.get("end", {})
        start_line = start_info.get("line", 1) if isinstance(start_info, dict) else 1
        end_line = end_info.get("line", start_line) if isinstance(end_info, dict) else start_line

        extra = item.get("extra", {})
        message = extra.get("message", "")
        lines = extra.get("lines", "")
        semgrep_sev = extra.get("severity", "WARNING").upper()
        severity = SEMGREP_SEVERITY_MAP.get(semgrep_sev, Severity.MEDIUM)
        meta = extra.get("metadata", {})

        raw_id = f"SEMGREP-{repository_name}-{rule_id}-{file_path}-{start_line}-{idx}"
        finding_id = hashlib.md5(raw_id.encode("utf-8")).hexdigest()[:12].upper()

        finding = UnifiedFinding(
            finding_id=f"SG-{finding_id}",
            scanner=ScannerType.SEMGREP,
            rule_id=rule_id,
            repository=repository_name,
            commit_sha="HEAD",
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            snippet=lines if lines else message,
            severity=severity,
            metadata={
                "message": message,
                "cwe": meta.get("cwe", []),
                "owasp": meta.get("owasp", []),
                "impact": meta.get("impact", ""),
                "confidence": meta.get("confidence", ""),
                "likelihood": meta.get("likelihood", ""),
                "category": meta.get("category", ""),
            },
            status=FindingStatus.NEW
        )
        finding.compute_fingerprint()
        findings.append(finding)

    return findings


def parse_semgrep_sarif(content_or_path: Union[str, Path], repository_name: str = "CN_WEB") -> List[UnifiedFinding]:
    """Parse Semgrep SARIF report into unified finding objects."""
    data = {}
    try:
        if isinstance(content_or_path, (str, Path)) and Path(content_or_path).exists():
            content = Path(content_or_path).read_text(encoding="utf-8", errors="replace").strip()
            if content:
                data = json.loads(content)
        elif isinstance(content_or_path, str) and content_or_path.strip():
            data = json.loads(content_or_path)
        elif isinstance(content_or_path, dict):
            data = content_or_path
    except Exception as e:
        print(f"[!] Warning: Failed to parse Semgrep SARIF ({e})")
        return []

    runs = data.get("runs", []) if isinstance(data, dict) else []
    findings: List[UnifiedFinding] = []

    for run in runs:
        rules_dict = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rules_dict[rule.get("id")] = rule

        results = run.get("results", [])
        for idx, item in enumerate(results):
            rule_id = item.get("ruleId", "semgrep-finding")
            rule_meta = rules_dict.get(rule_id, {})
            
            locations = item.get("locations", [])
            file_path = "unknown"
            start_line = 1
            end_line = 1
            
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "unknown")
                region = phys.get("region", {})
                start_line = region.get("startLine", 1)
                end_line = region.get("endLine", start_line)
                snippet_dict = region.get("snippet", {})
                lines = snippet_dict.get("text", "")
            else:
                lines = ""

            message = item.get("message", {}).get("text", "")
            level = item.get("level", "warning").upper()
            if level == "ERROR":
                severity = Severity.HIGH
            elif level == "WARNING":
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            raw_id = f"SEMGREP-SARIF-{repository_name}-{rule_id}-{file_path}-{start_line}-{idx}"
            finding_id = hashlib.md5(raw_id.encode("utf-8")).hexdigest()[:12].upper()

            finding = UnifiedFinding(
                finding_id=f"SG-{finding_id}",
                scanner=ScannerType.SEMGREP,
                rule_id=rule_id,
                repository=repository_name,
                commit_sha="HEAD",
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                snippet=lines if lines else message,
                severity=severity,
                metadata={
                    "message": message,
                    "help": rule_meta.get("help", {}).get("text", ""),
                    "shortDescription": rule_meta.get("shortDescription", {}).get("text", ""),
                },
                status=FindingStatus.NEW
            )
            finding.compute_fingerprint()
            findings.append(finding)

    return findings

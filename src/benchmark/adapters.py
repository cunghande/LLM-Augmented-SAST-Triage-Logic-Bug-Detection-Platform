"""
Benchmark Ground-Truth Matching Adapters
========================================
Dedicated adapters for benchmark ground-truth matching:
- OWASPBenchmarkJavaAdapter
- OWASPBenchmarkPythonAdapter
- SamsungCredDataAdapter
- RealVulnBenchmarkAdapter

Supports MatchTypes:
- EXACT_LOCATION
- ACCEPTABLE_LOCATION
- SYMBOL_MATCH
- SEMANTIC_MATCH_REQUIRES_REVIEW
- NO_MATCH
"""

from enum import Enum
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

from src.core.schema import UnifiedFinding


class MatchType(str, Enum):
    EXACT_LOCATION = "EXACT_LOCATION"
    ACCEPTABLE_LOCATION = "ACCEPTABLE_LOCATION"
    SYMBOL_MATCH = "SYMBOL_MATCH"
    SEMANTIC_MATCH_REQUIRES_REVIEW = "SEMANTIC_MATCH_REQUIRES_REVIEW"
    NO_MATCH = "NO_MATCH"


class MatchedSample(BaseModel):
    benchmark_name: str
    benchmark_version_or_sha: str = "v1.0"
    repo_id: str
    vulnerable_commit_sha: str = "HEAD"
    normalized_file_path: str
    ground_truth_label: str  # TP or FP
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    rule_family_or_cwe: str = "generic"
    match_type: MatchType = MatchType.EXACT_LOCATION
    source_ground_truth_id: str
    finding: UnifiedFinding
    match_confidence: float = 1.0


class UnmatchedSample(BaseModel):
    ground_truth_id: Optional[str] = None
    finding_id: Optional[str] = None
    repo_id: str = ""
    file_path: str = ""
    line_number: Optional[int] = None
    ground_truth_label: Optional[str] = None
    reason: str = "No matching strategy succeeded"


class AdapterMatchReport(BaseModel):
    benchmark_name: str
    total_findings: int
    matched_count: int
    unmatched_count: int
    matched_samples: List[MatchedSample] = Field(default_factory=list)
    unmatched_findings: List[UnmatchedSample] = Field(default_factory=list)
    unmatched_gt_entries: List[UnmatchedSample] = Field(default_factory=list)
    match_strategy: str = "DEFAULT"
    matching_rate: float = 0.0
    adapter_status: str = "OK"  # OK or ADAPTER_FAILURE


class BaseBenchmarkAdapter:
    def __init__(self, benchmark_name: str, gt_data: List[Dict[str, Any]]):
        self.benchmark_name = benchmark_name
        self.gt_data = gt_data

    def match(self, findings: List[UnifiedFinding]) -> AdapterMatchReport:
        raise NotImplementedError


class OWASPBenchmarkJavaAdapter(BaseBenchmarkAdapter):
    def __init__(self, gt_data: List[Dict[str, Any]], benchmark_version: str = "1.2"):
        super().__init__("OWASP BenchmarkJava", gt_data)
        self.benchmark_version = benchmark_version
        # Map finding_id (e.g. BenchmarkTest00001) to gt entry
        self.gt_by_test_name = {}
        for item in self.gt_data:
            tid = item.get("finding_id")
            if tid:
                self.gt_by_test_name[tid] = item

    def match(self, findings: List[UnifiedFinding]) -> AdapterMatchReport:
        matched_samples = []
        unmatched_findings = []

        for f in findings:
            test_name = f.finding_id
            if not test_name or test_name not in self.gt_by_test_name:
                stem = Path(f.file_path).stem
                if stem in self.gt_by_test_name:
                    test_name = stem
                else:
                    # Search rule_id or snippet if applicable
                    test_name = None

            if test_name and test_name in self.gt_by_test_name:
                gt_item = self.gt_by_test_name[test_name]
                gt_label = gt_item.get("ground_truth_verdict", "TP")
                cwe = gt_item.get("cwe", f.metadata.get("cwe", "generic"))

                sample = MatchedSample(
                    benchmark_name=self.benchmark_name,
                    benchmark_version_or_sha=self.benchmark_version,
                    repo_id="BenchmarkJava",
                    vulnerable_commit_sha="HEAD",
                    normalized_file_path=f.file_path.replace("\\", "/"),
                    ground_truth_label=gt_label,
                    start_line=f.start_line,
                    end_line=f.end_line,
                    rule_family_or_cwe=str(cwe),
                    match_type=MatchType.EXACT_LOCATION if f.finding_id == test_name else MatchType.ACCEPTABLE_LOCATION,
                    source_ground_truth_id=test_name,
                    finding=f,
                    match_confidence=1.0,
                )
                matched_samples.append(sample)
            else:
                unmatched_findings.append(
                    UnmatchedSample(
                        finding_id=f.finding_id,
                        repo_id="BenchmarkJava",
                        file_path=f.file_path,
                        line_number=f.start_line,
                        reason=f"Testcase name '{f.finding_id}' or file stem '{Path(f.file_path).stem}' not found in ground truth map",
                    )
                )

        matched_count = len(matched_samples)
        total_findings = len(findings)
        matching_rate = matched_count / total_findings if total_findings > 0 else 0.0
        status = "OK" if matched_count > 0 else "ADAPTER_FAILURE"

        return AdapterMatchReport(
            benchmark_name=self.benchmark_name,
            total_findings=total_findings,
            matched_count=matched_count,
            unmatched_count=len(unmatched_findings),
            matched_samples=matched_samples,
            unmatched_findings=unmatched_findings,
            match_strategy="EXACT_OR_FILE_STEM_MATCH",
            matching_rate=matching_rate,
            adapter_status=status,
        )


class OWASPBenchmarkPythonAdapter(BaseBenchmarkAdapter):
    def __init__(self, gt_data: List[Dict[str, Any]], benchmark_version: str = "0.1"):
        super().__init__("OWASP BenchmarkPython", gt_data)
        self.benchmark_version = benchmark_version
        self.gt_by_test_name = {}
        for item in self.gt_data:
            tid = item.get("finding_id")
            if tid:
                self.gt_by_test_name[tid] = item

    def match(self, findings: List[UnifiedFinding]) -> AdapterMatchReport:
        matched_samples = []
        unmatched_findings = []

        for f in findings:
            test_name = f.finding_id
            if not test_name or test_name not in self.gt_by_test_name:
                stem = Path(f.file_path).stem
                if stem in self.gt_by_test_name:
                    test_name = stem
                else:
                    test_name = None

            if test_name and test_name in self.gt_by_test_name:
                gt_item = self.gt_by_test_name[test_name]
                gt_label = gt_item.get("ground_truth_verdict", "TP")
                category = gt_item.get("category", "generic")

                sample = MatchedSample(
                    benchmark_name=self.benchmark_name,
                    benchmark_version_or_sha=self.benchmark_version,
                    repo_id="BenchmarkPython",
                    vulnerable_commit_sha="HEAD",
                    normalized_file_path=f.file_path.replace("\\", "/"),
                    ground_truth_label=gt_label,
                    start_line=f.start_line,
                    end_line=f.end_line,
                    rule_family_or_cwe=str(category),
                    match_type=MatchType.EXACT_LOCATION if f.finding_id == test_name else MatchType.ACCEPTABLE_LOCATION,
                    source_ground_truth_id=test_name,
                    finding=f,
                    match_confidence=1.0,
                )
                matched_samples.append(sample)
            else:
                unmatched_findings.append(
                    UnmatchedSample(
                        finding_id=f.finding_id,
                        repo_id="BenchmarkPython",
                        file_path=f.file_path,
                        line_number=f.start_line,
                        reason=f"Python benchmark testcase '{f.finding_id}' or stem '{Path(f.file_path).stem}' not in ground truth",
                    )
                )

        matched_count = len(matched_samples)
        total_findings = len(findings)
        matching_rate = matched_count / total_findings if total_findings > 0 else 0.0
        status = "OK" if matched_count > 0 else "ADAPTER_FAILURE"

        return AdapterMatchReport(
            benchmark_name=self.benchmark_name,
            total_findings=total_findings,
            matched_count=matched_count,
            unmatched_count=len(unmatched_findings),
            matched_samples=matched_samples,
            unmatched_findings=unmatched_findings,
            match_strategy="EXACT_OR_FILE_STEM_MATCH",
            matching_rate=matching_rate,
            adapter_status=status,
        )


class SamsungCredDataAdapter(BaseBenchmarkAdapter):
    def __init__(self, gt_data: List[Dict[str, Any]], benchmark_version: str = "v1.0"):
        super().__init__("Samsung CredData", gt_data)
        self.benchmark_version = benchmark_version

    def match(self, findings: List[UnifiedFinding]) -> AdapterMatchReport:
        """
        Matching strategy for CredData:
        1. Normalize file path (strip repo prefix, Windows separators).
        2. Match GT items by repo_name, file_path / file_id, and line_start (within ±10 line tolerance).
        3. Match secret patterns or category if location matches.
        """
        matched_samples = []
        unmatched_findings = []
        unmatched_gt_entries = []

        # Index GT data by normalized relative path & line
        gt_matched_flags = [False] * len(self.gt_data)

        for f in findings:
            clean_file = f.file_path.replace("\\", "/").lower()
            best_match_idx = -1
            best_match_type = MatchType.NO_MATCH

            for idx, gt in enumerate(self.gt_data):
                if gt_matched_flags[idx]:
                    continue

                gt_repo = str(gt.get("repo_name", "")).lower()
                gt_file = str(gt.get("file_path", "")).replace("\\", "/").lower()
                gt_line = int(gt.get("line_start", 0))

                # Check if repo_name or file_id or path components match
                path_match = False
                if gt_file and (gt_file in clean_file or clean_file in gt_file):
                    path_match = True
                elif gt_repo and gt_repo in clean_file:
                    path_match = True

                if path_match:
                    line_diff = abs(f.start_line - gt_line) if gt_line > 0 else 0
                    if line_diff == 0:
                        best_match_idx = idx
                        best_match_type = MatchType.EXACT_LOCATION
                        break
                    elif line_diff <= 10:
                        best_match_idx = idx
                        best_match_type = MatchType.ACCEPTABLE_LOCATION
                    elif best_match_idx == -1 and line_diff <= 30:
                        best_match_idx = idx
                        best_match_type = MatchType.SYMBOL_MATCH

            if best_match_idx != -1:
                gt_item = self.gt_data[best_match_idx]
                gt_matched_flags[best_match_idx] = True
                gt_label = gt_item.get("ground_truth_verdict", "TP")

                sample = MatchedSample(
                    benchmark_name=self.benchmark_name,
                    benchmark_version_or_sha=self.benchmark_version,
                    repo_id=gt_item.get("repo_name", "CredData"),
                    vulnerable_commit_sha="HEAD",
                    normalized_file_path=f.file_path.replace("\\", "/"),
                    ground_truth_label=gt_label,
                    start_line=f.start_line,
                    end_line=f.end_line,
                    rule_family_or_cwe=gt_item.get("category", "Secret"),
                    match_type=best_match_type,
                    source_ground_truth_id=gt_item.get("finding_id", "CRED-UNKNOWN"),
                    finding=f,
                    match_confidence=0.9 if best_match_type == MatchType.EXACT_LOCATION else 0.7,
                )
                matched_samples.append(sample)
            else:
                unmatched_findings.append(
                    UnmatchedSample(
                        finding_id=f.finding_id,
                        repo_id="CredData",
                        file_path=f.file_path,
                        line_number=f.start_line,
                        reason=f"No CredData ground truth matched file '{f.file_path}:{f.start_line}'",
                    )
                )

        for idx, gt in enumerate(self.gt_data):
            if not gt_matched_flags[idx]:
                unmatched_gt_entries.append(
                    UnmatchedSample(
                        ground_truth_id=gt.get("finding_id"),
                        repo_id=gt.get("repo_name", ""),
                        file_path=gt.get("file_path", ""),
                        line_number=gt.get("line_start"),
                        ground_truth_label=gt.get("ground_truth_verdict"),
                        reason="No scanner finding matched this ground truth entry location",
                    )
                )

        matched_count = len(matched_samples)
        total_findings = len(findings)
        matching_rate = matched_count / total_findings if total_findings > 0 else 0.0
        status = "OK" if matched_count > 0 else "ADAPTER_FAILURE"

        return AdapterMatchReport(
            benchmark_name=self.benchmark_name,
            total_findings=total_findings,
            matched_count=matched_count,
            unmatched_count=len(unmatched_findings),
            matched_samples=matched_samples,
            unmatched_findings=unmatched_findings,
            unmatched_gt_entries=unmatched_gt_entries,
            match_strategy="PATH_AND_LINE_PROXIMITY_MATCH",
            matching_rate=matching_rate,
            adapter_status=status,
        )


class RealVulnBenchmarkAdapter(BaseBenchmarkAdapter):
    def __init__(self, gt_data: List[Dict[str, Any]], benchmark_version: str = "v1.0"):
        super().__init__("Real-Vuln-Benchmark", gt_data)
        self.benchmark_version = benchmark_version

    def match(self, findings: List[UnifiedFinding]) -> AdapterMatchReport:
        """
        Matching strategy for Real-Vuln-Benchmark:
        Matches scanner findings against ground-truth items by:
        1. repo_id in finding file_path / repository.
        2. file_path match.
        3. line proximity (±15 lines) or function symbol match or CWE match.
        """
        matched_samples = []
        unmatched_findings = []
        unmatched_gt_entries = []
        gt_matched_flags = [False] * len(self.gt_data)

        for f in findings:
            clean_file = f.file_path.replace("\\", "/").lower()
            best_match_idx = -1
            best_match_type = MatchType.NO_MATCH

            for idx, gt in enumerate(self.gt_data):
                if gt_matched_flags[idx]:
                    continue

                gt_repo = str(gt.get("repo_id", "")).lower()
                gt_file = str(gt.get("file_path", "")).replace("\\", "/").lower()
                gt_line = int(gt.get("start_line", 0))
                gt_func = str(gt.get("function", "")).lower()

                repo_match = False
                if gt_repo and (gt_repo in clean_file or gt_repo in f.repository.lower()):
                    repo_match = True

                file_match = False
                if gt_file and (gt_file in clean_file or clean_file.endswith(gt_file)):
                    file_match = True

                if repo_match or file_match:
                    line_diff = abs(f.start_line - gt_line) if gt_line > 0 else 0
                    func_in_snippet = gt_func and (gt_func in f.snippet.lower() or (f.context and f.context.enclosing_function and gt_func in f.context.enclosing_function.lower()))

                    if file_match and line_diff <= 5:
                        best_match_idx = idx
                        best_match_type = MatchType.EXACT_LOCATION
                        break
                    elif file_match and line_diff <= 20:
                        best_match_idx = idx
                        best_match_type = MatchType.ACCEPTABLE_LOCATION
                    elif func_in_snippet and file_match:
                        best_match_idx = idx
                        best_match_type = MatchType.SYMBOL_MATCH

            if best_match_idx != -1:
                gt_item = self.gt_data[best_match_idx]
                gt_matched_flags[best_match_idx] = True
                gt_label = gt_item.get("ground_truth_verdict", "TP")
                cwe = gt_item.get("primary_cwe", gt_item.get("vulnerability_class", "generic"))

                sample = MatchedSample(
                    benchmark_name=self.benchmark_name,
                    benchmark_version_or_sha=self.benchmark_version,
                    repo_id=gt_item.get("repo_id", "RealVuln"),
                    vulnerable_commit_sha="HEAD",
                    normalized_file_path=f.file_path.replace("\\", "/"),
                    ground_truth_label=gt_label,
                    start_line=f.start_line,
                    end_line=f.end_line,
                    rule_family_or_cwe=str(cwe),
                    match_type=best_match_type,
                    source_ground_truth_id=gt_item.get("finding_id", "REALVULN-UNKNOWN"),
                    finding=f,
                    match_confidence=0.95 if best_match_type == MatchType.EXACT_LOCATION else 0.75,
                )
                matched_samples.append(sample)
            else:
                unmatched_findings.append(
                    UnmatchedSample(
                        finding_id=f.finding_id,
                        repo_id=f.repository,
                        file_path=f.file_path,
                        line_number=f.start_line,
                        reason=f"No RealVuln ground truth item matched path '{f.file_path}:{f.start_line}'",
                    )
                )

        for idx, gt in enumerate(self.gt_data):
            if not gt_matched_flags[idx]:
                unmatched_gt_entries.append(
                    UnmatchedSample(
                        ground_truth_id=gt.get("finding_id"),
                        repo_id=gt.get("repo_id", ""),
                        file_path=gt.get("file_path", ""),
                        line_number=gt.get("start_line"),
                        ground_truth_label=gt.get("ground_truth_verdict"),
                        reason="No scanner finding matched this ground truth entry location",
                    )
                )

        matched_count = len(matched_samples)
        total_findings = len(findings)
        matching_rate = matched_count / total_findings if total_findings > 0 else 0.0
        status = "OK" if matched_count > 0 else "ADAPTER_FAILURE"

        return AdapterMatchReport(
            benchmark_name=self.benchmark_name,
            total_findings=total_findings,
            matched_count=matched_count,
            unmatched_count=len(unmatched_findings),
            matched_samples=matched_samples,
            unmatched_findings=unmatched_findings,
            unmatched_gt_entries=unmatched_gt_entries,
            match_strategy="REPO_FILE_LINE_SYMBOL_MATCH",
            matching_rate=matching_rate,
            adapter_status=status,
        )


def get_adapter_for_benchmark(benchmark_key: str, gt_data: List[Dict[str, Any]]) -> BaseBenchmarkAdapter:
    key = benchmark_key.lower()
    if "java" in key:
        return OWASPBenchmarkJavaAdapter(gt_data)
    elif "python" in key:
        return OWASPBenchmarkPythonAdapter(gt_data)
    elif "cred" in key:
        return SamsungCredDataAdapter(gt_data)
    elif "real" in key or "vuln" in key:
        return RealVulnBenchmarkAdapter(gt_data)
    else:
        return OWASPBenchmarkJavaAdapter(gt_data)

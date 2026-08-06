"""Category-aware scoring for OWASP Benchmark Python scanner findings."""

import csv
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from sast_triage.errors import SastTriageError
from sast_triage.models import NormalizedFinding, ScannerType

OWASP_RULE_MAPPING_VERSION = "semgrep-python-category-map-v1"

# Ordered, explicit mapping for the Semgrep Python rules used by Sprint 1.
# Callers can supply a different mapping when scanner rules change.
DEFAULT_SEMGREP_RULE_CATEGORY_MAP: dict[str, str] = {
    "use-defused-xml-parse": "xxe",
    "insecure-hash": "hash",
    "raw-html": "xss",
    "subprocess-shell-true": "cmdi",
    "dangerous-subprocess-use": "cmdi",
    "subprocess-injection": "cmdi",
    "avoid-pyyaml-load": "deserialization",
    "insecure-deserialization": "deserialization",
    "path-traversal": "pathtraver",
    "tainted-sql-string": "sqli",
    "xpath": "xpathi",
    "ldap": "ldapi",
    "redirect": "redirect",
    "secure-cookie": "securecookie",
    "weak-random": "weakrand",
    "code-injection": "codeinj",
}

_TEST_NAME = re.compile(r"BenchmarkTest\d{5}")


@dataclass(frozen=True)
class OwaspBenchmarkCase:
    """One safe OWASP expected-result row."""

    test_name: str
    category: str
    vulnerable: bool
    cwe: str


@dataclass(frozen=True)
class OwaspBenchmarkDataset:
    """Validated OWASP expected-results dataset."""

    version: str
    cases: tuple[OwaspBenchmarkCase, ...]


@dataclass(frozen=True)
class OwaspCategoryScore:
    """Confusion-matrix values for one benchmark category."""

    category: str
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int


@dataclass(frozen=True)
class OwaspBenchmarkScore:
    """Category-aware scanner score without raw source or artifact records."""

    benchmark_version: str
    mapping_version: str
    total_cases: int
    mapped_findings: int
    out_of_scope_findings: int
    unique_reported_cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    normalized_score: float
    accuracy: float
    categories: tuple[OwaspCategoryScore, ...]


def load_owasp_expected_results(file_path: Path) -> OwaspBenchmarkDataset:
    """Load OWASP Benchmark expectedresults CSV without source content."""
    try:
        with file_path.open(encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader)
            rows = list(reader)
    except FileNotFoundError:
        raise SastTriageError("OWASP expected-results file does not exist.", "BENCHMARK_FILE_NOT_FOUND") from None
    except (OSError, UnicodeDecodeError, csv.Error):
        raise SastTriageError("OWASP expected-results file could not be read.", "BENCHMARK_FILE_INVALID") from None

    if not header or "Benchmark version:" not in ",".join(header):
        raise SastTriageError("OWASP expected-results header is invalid.", "BENCHMARK_SCHEMA_INVALID")
    version_match = re.search(r"Benchmark version:\s*([^,]+)", ",".join(header))
    version = version_match.group(1).strip() if version_match else "unknown"
    cases: list[OwaspBenchmarkCase] = []
    seen: set[str] = set()
    for index, row in enumerate(rows, start=2):
        if not row or all(not value.strip() for value in row):
            continue
        if len(row) < 4:
            raise SastTriageError("OWASP expected-results row is invalid.", f"BENCHMARK_RECORD_INVALID_{index}")
        test_name, category, raw_vulnerable, cwe = (value.strip() for value in row[:4])
        if not _TEST_NAME.fullmatch(test_name) or not category or not cwe or raw_vulnerable.lower() not in {"true", "false"}:
            raise SastTriageError("OWASP expected-results row is invalid.", f"BENCHMARK_RECORD_INVALID_{index}")
        if test_name in seen:
            raise SastTriageError("OWASP expected-results contains a duplicate test.", "BENCHMARK_DUPLICATE_RECORD")
        seen.add(test_name)
        cases.append(
            OwaspBenchmarkCase(
                test_name=test_name,
                category=category.lower(),
                vulnerable=raw_vulnerable.lower() == "true",
                cwe=cwe,
            )
        )
    if not cases:
        raise SastTriageError("OWASP expected-results contains no test cases.", "BENCHMARK_SCHEMA_INVALID")
    return OwaspBenchmarkDataset(version=version, cases=tuple(cases))


def _finding_category(rule_id: str, mapping: Mapping[str, str]) -> str | None:
    matches = {category for token, category in mapping.items() if token in rule_id}
    if len(matches) != 1:
        return None
    return matches.pop()


def score_owasp_findings(
    dataset: OwaspBenchmarkDataset,
    findings: tuple[NormalizedFinding, ...],
    *,
    rule_category_map: Mapping[str, str] | None = None,
    mapping_version: str = OWASP_RULE_MAPPING_VERSION,
) -> OwaspBenchmarkScore:
    """Score Semgrep findings only when test identity and category both match."""
    mapping = rule_category_map or DEFAULT_SEMGREP_RULE_CATEGORY_MAP
    if not mapping or not mapping_version.strip():
        raise SastTriageError("OWASP rule mapping is invalid.", "BENCHMARK_MAPPING_INVALID")
    case_by_name = {case.test_name: case for case in dataset.cases}
    reported: set[str] = set()
    mapped_findings = 0
    out_of_scope_findings = 0
    for finding in findings:
        if finding.scanner != ScannerType.SEMGREP:
            out_of_scope_findings += 1
            continue
        name_match = _TEST_NAME.search(finding.file_path)
        category = _finding_category(finding.rule_id, mapping)
        case = case_by_name.get(name_match.group(0)) if name_match else None
        if case is None or category is None or category != case.category:
            out_of_scope_findings += 1
            continue
        mapped_findings += 1
        reported.add(case.test_name)

    totals = {category: [0, 0, 0, 0] for category in sorted({case.category for case in dataset.cases})}
    tp = fp = fn = tn = 0
    for case in dataset.cases:
        positive = case.test_name in reported
        if case.vulnerable and positive:
            tp += 1
            totals[case.category][0] += 1
        elif not case.vulnerable and positive:
            fp += 1
            totals[case.category][1] += 1
        elif case.vulnerable:
            fn += 1
            totals[case.category][2] += 1
        else:
            tn += 1
            totals[case.category][3] += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    categories = tuple(
        OwaspCategoryScore(category, values[0], values[1], values[2], values[3])
        for category, values in totals.items()
    )
    return OwaspBenchmarkScore(
        benchmark_version=dataset.version,
        mapping_version=mapping_version,
        total_cases=len(dataset.cases),
        mapped_findings=mapped_findings,
        out_of_scope_findings=out_of_scope_findings,
        unique_reported_cases=len(reported),
        true_positive=tp,
        false_positive=fp,
        false_negative=fn,
        true_negative=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=false_positive_rate,
        normalized_score=recall - false_positive_rate,
        accuracy=(tp + tn) / len(dataset.cases),
        categories=categories,
    )

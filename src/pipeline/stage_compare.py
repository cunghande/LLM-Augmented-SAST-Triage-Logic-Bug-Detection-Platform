"""
Stage 4: COMPARE Stage Module
=============================
Performs relationship-aware finding correlation across scan runs.
Assigns correlation_state: NEW, EXISTING, CHANGED, FIXED, REOPENED.
"""

from typing import List, Dict, Tuple
from src.core.schema import UnifiedFinding, ScanState


class CompareStageRunner:
    """Stage 4: COMPARE runner for relationship-aware finding correlation across scans."""

    def run_stage_compare(self, current_findings: List[UnifiedFinding], baseline_findings: List[UnifiedFinding]) -> Tuple[List[UnifiedFinding], Dict[str, int]]:
        """
        Correlates current scan findings against baseline scan findings.
        Returns: (correlated_findings_list, summary_counts)
        """
        baseline_by_fp: Dict[str, UnifiedFinding] = {f.compute_fingerprint(): f for f in baseline_findings}
        baseline_by_rule_file: Dict[str, UnifiedFinding] = {f"{f.rule_id}:{f.file_path}": f for f in baseline_findings}

        correlated: List[UnifiedFinding] = []
        current_fps = set()

        # Process current scan findings
        for finding in current_findings:
            fp = finding.compute_fingerprint()
            current_fps.add(fp)

            if fp in baseline_by_fp:
                prev = baseline_by_fp[fp]
                if prev.correlation_state == ScanState.FIXED:
                    finding.correlation_state = ScanState.REOPENED
                else:
                    finding.correlation_state = ScanState.EXISTING
            else:
                rule_file_key = f"{finding.rule_id}:{finding.file_path}"
                if rule_file_key in baseline_by_rule_file:
                    finding.correlation_state = ScanState.CHANGED
                else:
                    finding.correlation_state = ScanState.NEW

            correlated.append(finding)

        # Detect FIXED findings (present in baseline but missing in current scan)
        fixed_count = 0
        for fp, base_finding in baseline_by_fp.items():
            if fp not in current_fps and base_finding.correlation_state != ScanState.FIXED:
                fixed_finding = base_finding.model_copy()
                fixed_finding.correlation_state = ScanState.FIXED
                correlated.append(fixed_finding)
                fixed_count += 1

        summary_counts = {
            "NEW": sum(1 for f in correlated if f.correlation_state == ScanState.NEW),
            "EXISTING": sum(1 for f in correlated if f.correlation_state == ScanState.EXISTING),
            "CHANGED": sum(1 for f in correlated if f.correlation_state == ScanState.CHANGED),
            "FIXED": fixed_count,
            "REOPENED": sum(1 for f in correlated if f.correlation_state == ScanState.REOPENED),
        }

        return correlated, summary_counts

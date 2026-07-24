from pathlib import Path
from typing import List
from src.logic_bugs.ast_graph import extract_code_graph, TracePath


def discover_high_risk_routes(repo_dir: Path) -> List[TracePath]:
    """Extract code graph and prioritize high-risk candidates for LLM analysis."""
    all_traces = extract_code_graph(repo_dir)
    high_risk_candidates: List[TracePath] = []

    for trace in all_traces:
        # High-risk condition 1: Sensitive sink with NO auth guard
        if not trace.has_auth_guard:
            high_risk_candidates.append(trace)
        # High-risk condition 2: Potential IDOR or Mass Assignment indicator
        elif trace.potential_vulnerability:
            high_risk_candidates.append(trace)

    # If no specific high-risk traces found, return all discovered traces
    return high_risk_candidates if high_risk_candidates else all_traces

"""Các parser output scanner cho SAST Triage Platform."""

from sast_triage.parsers.gitleaks import parse_gitleaks_json
from sast_triage.parsers.semgrep import parse_semgrep_json

__all__ = ["parse_gitleaks_json", "parse_semgrep_json"]

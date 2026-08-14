"""Tests for bounded Module 2 cross-file and monorepo behavior."""

import json
from pathlib import Path

from sast_triage.context.repository_index import build_repository_index
from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    PolicyAction,
    ScannerParseResult,
    ScannerType,
    Severity,
    TriageDecision,
    TriageInput,
)
from sast_triage.pipeline.batch import triage_batch
from sast_triage.pipeline.finding import triage_finding
from sast_triage.triage.fake_provider import FakeTriageProvider


def _monorepo(tmp_path: Path) -> Path:
    root = tmp_path / "mono"
    shared = root / "packages" / "shared"
    web = root / "packages" / "web"
    (shared / "src" / "shared").mkdir(parents=True)
    (web / "src" / "web").mkdir(parents=True)
    (shared / "pyproject.toml").write_text("[project]\nname='shared'\n", encoding="utf-8")
    (web / "pyproject.toml").write_text("[project]\nname='web'\n", encoding="utf-8")
    (shared / "src" / "shared" / "danger.py").write_text(
        "import subprocess\n\ndef run_command(value):\n    subprocess.run(value, shell=True)\n",
        encoding="utf-8",
    )
    (web / "src" / "web" / "routes.py").write_text(
        "from shared.danger import run_command\n\ndef handler():\n"
        "    command = request.args.get('cmd')\n    run_command(command)\n",
        encoding="utf-8",
    )
    return root


def test_monorepo_index_discovers_explicit_cross_component_path(tmp_path: Path) -> None:
    repo = _monorepo(tmp_path)
    index = build_repository_index(repo, "example/mono")

    assert {item.identifier for item in index.components} >= {
        "packages/shared",
        "packages/web",
    }
    findings = index.discover_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == ScannerType.MODULE2
    assert finding.file_path == "packages/shared/src/shared/danger.py"
    trace = index.trace_for_finding(finding)
    assert trace is not None
    assert trace.source_file == "packages/web/src/web/routes.py"
    assert trace.sink_file == finding.file_path
    summary = index.summary_for("shared.danger.run_command")
    assert summary is not None
    assert summary.parameter_to_sinks == (("value", "command_execution"),)


def test_module2_finding_uses_same_sequential_triage_pipeline(tmp_path: Path) -> None:
    repo = _monorepo(tmp_path)
    index = build_repository_index(repo, "example/mono")
    finding = index.discover_findings()[0]

    batch = triage_batch(
        repo,
        FakeTriageProvider(),
        module2_result=ScannerParseResult(findings=(finding,)),
        repository_index=index,
        repository_identifier="example/mono",
        prompt_type="fake.tp.high",
    )

    assert batch.run_metadata.scanners_attempted == [ScannerType.MODULE2]
    assert batch.results[0].policy_decision.action == PolicyAction.MANUAL_REVIEW


def test_repository_index_does_not_retain_source_canary(tmp_path: Path) -> None:
    repo = _monorepo(tmp_path)
    canary = "MONOREPO_INDEX_SECRET_CANARY"
    source = repo / "packages" / "web" / "src" / "web" / "extra.py"
    source.write_text(f"TOKEN = '{canary}'\n", encoding="utf-8")

    index = build_repository_index(repo, "example/mono")
    serialized_shape = json.dumps(
        {
            "components": [item.identifier for item in index.components],
            "functions": [item.qualified_name for item in index.functions],
            "calls": [item.callee for item in index.calls],
        }
    )
    assert canary not in repr(index)
    assert canary not in serialized_shape


def test_framework_entrypoint_and_function_summary_support_cross_file_trace(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "service").mkdir(parents=True)
    (repo / "api").mkdir(parents=True)
    (repo / "service" / "danger.py").write_text(
        "import subprocess\n\ndef run(value):\n    subprocess.run(value, shell=True)\n",
        encoding="utf-8",
    )
    (repo / "api" / "routes.py").write_text(
        "from service.danger import run\n\n@app.get('/run')\ndef handler(command):\n    run(command)\n",
        encoding="utf-8",
    )

    index = build_repository_index(repo, "example/fastapi")
    findings = index.discover_findings()

    assert len(findings) == 1
    trace = index.trace_for_finding(findings[0])
    assert trace is not None
    assert trace.source_type == "http_route_parameter"
    assert trace.source_file == "api/routes.py"
    route_summary = index.summary_for("api.routes.handler")
    assert route_summary is not None
    assert route_summary.returned_parameters == ()


def test_function_summary_records_return_and_control_without_source_text(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import html\n\ndef transform(value):\n    safe = html.escape(value)\n    return value\n",
        encoding="utf-8",
    )

    index = build_repository_index(repo, "example/summaries")
    summary = index.summary_for("app.transform")

    assert summary is not None
    assert summary.returned_parameters == ("value",)
    assert summary.security_controls == ("output_encoding",)
    assert "html.escape" not in repr(summary)


def test_intrinsic_usage_rule_is_not_fp_candidate_from_non_tainted_source(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import hashlib\n\ndef digest(value):\n    return hashlib.md5(value).hexdigest()\n",
        encoding="utf-8",
    )
    finding = NormalizedFinding(
        finding_instance_id="hash-finding",
        scanner=ScannerType.SEMGREP,
        finding_type=FindingType.SAST,
        rule_id="python.lang.security.insecure-hash-algorithms-md5",
        file_path="app.py",
        start_line=4,
        end_line=4,
        severity=Severity.MEDIUM,
        message="Insecure hash usage requires review.",
    )

    class CapturingProvider(FakeTriageProvider):
        captured: TriageInput | None = None

        def triage(self, triage_input: TriageInput) -> TriageDecision:
            self.captured = triage_input
            return super().triage(triage_input)

    provider = CapturingProvider()
    result = triage_finding(
        finding,
        repo,
        provider,
        prompt_type="fake.fp.high",
    )
    assert result.policy_decision.action == PolicyAction.MANUAL_REVIEW
    assert result.policy_decision.escalated is True
    assert provider.captured is not None
    evidence = json.loads(provider.captured.context.sanitized_snippet or "{}")
    verification = evidence["deterministic_verification"]
    assert verification["unsafe_primitive_observed"] is True
    assert verification["source_user_controlled"] is None
    assert verification["source_reaches_sink"] is None
    assert verification["has_evidence_conflict"] is False

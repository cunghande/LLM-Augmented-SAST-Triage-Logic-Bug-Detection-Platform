"""Offline CLI integration tests using existing scanner artifacts and Fake provider."""

import json
from contextlib import contextmanager
from pathlib import Path

import pytest

from sast_triage.analysis.base import AnalysisIdentity, GraphEvidence
from sast_triage.cli import (
    EXIT_PROVIDER_RESOURCE_EXHAUSTED,
    EXIT_SUCCESS,
    build_parser,
    main,
)
from sast_triage.errors import SastTriageError
from sast_triage.logic.index import build_logic_index
from sast_triage.models import NormalizedFinding, ScannerType, TriageInput
from sast_triage.runners.scanners import ScannerRunResult
from sast_triage.triage.fake_provider import FakeTriageProvider


@pytest.fixture(autouse=True)
def offline_joern_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace Docker startup with a source-free Joern contract test double."""

    class OfflineJoernBackend:
        def __init__(
            self,
            repository: Path,
            repository_identifier: str,
            logic_detector: str,
        ) -> None:
            self.identity = AnalysisIdentity(
                "joern", "test", "joern-offline-test", "complete", 0.0
            )
            self.logic_index = (
                build_logic_index(repository)
                if logic_detector != "off"
                else None
            )

        def discover_findings(
            self, existing: tuple[NormalizedFinding, ...]
        ) -> tuple[NormalizedFinding, ...]:
            return ()

        def discover_logic_findings(
            self,
            detector: str,
            existing: tuple[NormalizedFinding, ...],
        ) -> tuple[NormalizedFinding, ...]:
            if detector == "off" or self.logic_index is None:
                return ()
            return self.logic_index.discover_findings(existing)

        def initial_evidence(self, finding: NormalizedFinding) -> GraphEvidence:
            return GraphEvidence(
                limitations=("JOERN_OFFLINE_TEST_DOUBLE",),
                provenance=("JOERN_CPG",),
            )

        def run_tool(
            self,
            tool_name: str,
            finding: NormalizedFinding,
            evidence: GraphEvidence,
            *,
            max_depth: int,
            max_paths: int,
            max_nodes: int,
        ) -> GraphEvidence:
            return evidence

    @contextmanager
    def session(
        repository: Path,
        repository_identifier: str,
        *,
        module2_enabled: bool,
        logic_detector: str = "off",
    ):
        del module2_enabled
        yield OfflineJoernBackend(repository, repository_identifier, logic_detector)

    monkeypatch.setattr("sast_triage.application.run.analysis_backend_session", session)


def test_triage_cli_writes_all_reports_and_metadata(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(
        json.dumps({"results": [{"check_id": "r", "path": "app.py", "start": {"line": 1}, "extra": {"message": "msg", "lines": "x = 1"}}]}),
        encoding="utf-8",
    )
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")
    output = tmp_path / "output"
    exit_code = main(["triage", "--repository", str(repo), "--semgrep-json", str(semgrep), "--gitleaks-json", str(gitleaks), "--output-dir", str(output), "--provider", "fake"])
    assert exit_code == EXIT_SUCCESS
    assert (output / "report.json").is_file()
    assert (output / "report.md").is_file()
    assert (output / "report.html").is_file()
    assert (output / "run-metadata.json").is_file()
    assert "x = 1" not in (output / "report.json").read_text(encoding="utf-8")
    progress = capsys.readouterr().out
    assert "[1/7] Đang kiểm tra repository" in progress
    assert "[3/7] Đã parse 1 finding" in progress
    assert "[5/7] Tiến độ triage 1/1" in progress
    assert "[7/7] Đã ghi báo cáo và metadata thành công" in progress


def test_cli_prints_safe_operational_error(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "scan-and-triage",
            "--repository",
            str(tmp_path / "missing-repository"),
            "--output-dir",
            str(tmp_path / "output"),
            "--provider",
            "fake",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code != EXIT_SUCCESS
    assert "LỖI [CLI_INVALID_REPOSITORY]" in captured.err
    assert "Traceback" not in captured.err


def test_cli_help_is_available() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["triage", "--help"])
    assert exc_info.value.code == 0


def test_module2_discovery_is_explicitly_opt_in() -> None:
    parser = build_parser()
    common = [
        "triage",
        "--repository",
        "repo",
        "--semgrep-json",
        "semgrep.json",
        "--gitleaks-json",
        "gitleaks.json",
        "--output-dir",
        "output",
    ]

    default_args = parser.parse_args(common)
    enabled_args = parser.parse_args([*common, "--module2-discovery"])

    assert default_args.module2 is True
    assert default_args.module2_discovery is False
    assert enabled_args.module2_discovery is True


def test_focused_logic_detector_is_explicit_and_uses_prompt_v13() -> None:
    parser = build_parser()
    common = [
        "triage",
        "--repository",
        "repo",
        "--semgrep-json",
        "semgrep.json",
        "--gitleaks-json",
        "gitleaks.json",
        "--output-dir",
        "output",
    ]

    default_args = parser.parse_args(common)
    enabled_args = parser.parse_args(
        [*common, "--logic-detector", "python-idor-business-logic"]
    )

    assert default_args.logic_detector == "off"
    assert default_args.prompt_version == "triage-prompt-v14"
    assert enabled_args.logic_detector == "python-idor-business-logic"


def test_scan_and_triage_cli_reuses_shared_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(json.dumps({"results": []}), encoding="utf-8")
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(
        "sast_triage.application.artifacts.SemgrepRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(ScannerType.SEMGREP, semgrep, (), True, 0),
    )
    monkeypatch.setattr(
        "sast_triage.application.artifacts.GitleaksRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(ScannerType.GITLEAKS, gitleaks, (), True, 0),
    )

    assert main(["scan-and-triage", "--repository", str(repo), "--output-dir", str(output), "--provider", "fake"]) == EXIT_SUCCESS
    metadata = json.loads((output / "run-metadata.json").read_text(encoding="utf-8"))
    assert metadata["cli_mode"] == "scan-and-triage"
    assert json.loads((output / "report.json").read_text(encoding="utf-8"))["results"] == []


def test_scan_and_triage_emits_only_focused_logic_classes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        """
@app.get('/objects/<object_id>')
def object_detail(object_id, current_user, db):
    return db.query(Object).get(object_id)

@app.post('/cart')
def calculate_cart(request, db):
    payload = request.get_json()
    price = payload.get('price')
    quantity = payload.get('quantity')
    return db.create(total=price * quantity)

@app.get('/admin/users')
def list_users(db):
    return db.query(User).all()
""",
        encoding="utf-8",
    )
    output = tmp_path / "output"
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(json.dumps({"results": []}), encoding="utf-8")
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        "sast_triage.application.artifacts.SemgrepRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(
            ScannerType.SEMGREP, semgrep, (), True, 0
        ),
    )
    monkeypatch.setattr(
        "sast_triage.application.artifacts.GitleaksRunner.run",
        lambda self, repository_root, output_dir: ScannerRunResult(
            ScannerType.GITLEAKS, gitleaks, (), True, 0
        ),
    )

    exit_code = main(
        [
            "scan-and-triage",
            "--repository",
            str(repo),
            "--output-dir",
            str(output),
            "--module2",
            "--logic-detector",
            "python-idor-business-logic",
            "--provider",
            "fake",
        ]
    )

    assert exit_code == EXIT_SUCCESS
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    classes = {
        item["finding"]["metadata"]["logic_class"] for item in report["results"]
    }
    assert classes == {
        "missing_authz_idor",
        "business_rule_bypass",
    }
    assert all(not item["processing_errors"] for item in report["results"])


def test_cli_checkpoints_modal_exhaustion_and_resumes_with_ollama(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "r1",
                        "path": "app.py",
                        "start": {"line": 1},
                        "extra": {"message": "one", "lines": "x = 1"},
                    },
                    {
                        "check_id": "r2",
                        "path": "app.py",
                        "start": {"line": 2},
                        "extra": {"message": "two", "lines": "y = 2"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    gitleaks = tmp_path / "gitleaks.json"
    gitleaks.write_text("[]", encoding="utf-8")
    output = tmp_path / "output"
    calls = {"modal": 0, "ollama": 0}

    class ExhaustingProvider:
        provider_name = "real-modal-qwen"
        model_version = "Qwen/Qwen3-14B-AWQ"

        def __init__(self) -> None:
            self._fake = FakeTriageProvider()

        def triage(self, triage_input: TriageInput):
            calls["modal"] += 1
            if calls["modal"] == 2:
                raise SastTriageError(
                    "Modal quota exhausted.",
                    "TRIAGE_PROVIDER_RESOURCE_EXHAUSTED",
                    retryable=True,
                )
            return self._fake.triage(triage_input)

    class CountingOllamaProvider:
        provider_name = "ollama"
        model_version = "qwen3:8b"

        def __init__(self) -> None:
            self._fake = FakeTriageProvider()

        def triage(self, triage_input: TriageInput):
            calls["ollama"] += 1
            return self._fake.triage(triage_input)

    @contextmanager
    def provider_session(provider_name):
        if provider_name == "real":
            yield ExhaustingProvider()
        else:
            yield CountingOllamaProvider()

    monkeypatch.setattr("sast_triage.application.run.provider_session", provider_session)
    base_args = [
        "triage",
        "--repository",
        str(repo),
        "--semgrep-json",
        str(semgrep),
        "--gitleaks-json",
        str(gitleaks),
        "--output-dir",
        str(output),
    ]

    assert main([*base_args, "--provider", "real"]) == EXIT_PROVIDER_RESOURCE_EXHAUSTED
    checkpoint = json.loads((output / "triage-checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["status"] == "resource_exhausted"
    assert checkpoint["completed_count"] == 1
    assert "x = 1" not in json.dumps(checkpoint)

    assert main([*base_args, "--provider", "ollama", "--resume"]) == EXIT_SUCCESS
    assert calls == {"modal": 2, "ollama": 1}
    assert not (output / "triage-checkpoint.json").exists()
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert len(report["results"]) == 2
    assert report["run_metadata"]["triage_provider"] == "real-modal-qwen -> ollama"

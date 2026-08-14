"""Docker-backed Joern CPG analysis with source-free query projections."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import socket
import subprocess
import time
import uuid
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Self

from sast_triage.analysis.base import (
    AnalysisIdentity,
    GraphControl,
    GraphEvidence,
    GraphStep,
)
from sast_triage.errors import SastTriageError
from sast_triage.models import (
    FindingType,
    NormalizedFinding,
    ScannerType,
    Severity,
)

JOERN_VERSION = "4.0.600"
JOERN_IMAGE = "sast-triage-joern:4.0.600"
JOERN_CONFIG_ID = "joern-pysrc2cpg-v4.0.600-evidence-v2"
_CONTAINER_REPOSITORY = "/workspace/repository"
_SOURCE_CALL_REGEX = (
    "(?i)(input|read|recv|get|getlist|get_all|get_json|get_data|keys|"
    "get_form_parameter|get_query_parameter|get_header|get_cookie|"
    "<operator>\\.fieldAccess)"
)
_SINK_CALL_REGEX = (
    "(?i)(eval|exec|system|run|call|popen|execute|executemany|open|loads?|load|"
    "fromstring|parse|render_template_string|mark_safe|xpath)"
)
_CONTROL_CALL_REGEX = (
    "(?i)(sanitize|clean|escape|quote|validate|allow|safe|basename|normpath|"
    "resolve|literal_eval)"
)
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

_SOURCE_RECEIVER_REGEX = (
    "(?i)(request|req|wrapped|scr|form|args|headers|cookies|files|"
    "query_params|os|environ|sys|argv)"
)
_SPECIFIC_SOURCE_NAMES = (
    "get_form_parameter",
    "get_query_parameter",
    "get_header",
    "get_cookie",
)


def _scala_string(value: str) -> str:
    """Encode a validated value as a Scala-compatible quoted string."""
    return json.dumps(value, ensure_ascii=True)


def _sink_type(finding: NormalizedFinding) -> str:
    """Classify the target rule without reading source text."""
    text = f"{finding.rule_id} {finding.rule_name or ''} {finding.message}".lower()
    mappings = (
        (("command", "subprocess", "os-system"), "command_execution"),
        (("sql",), "sql_query"),
        (("path", "travers"), "file_access"),
        (("deserial", "pickle", "yaml"), "deserialization"),
        (("xxe", "xml"), "xml_parsing"),
        (("xpath",), "xpath_query"),
        (("xss", "html", "template"), "html_rendering"),
        (("hash", "md5", "sha1"), "weak_cryptography"),
        (("random",), "weak_randomness"),
    )
    for tokens, value in mappings:
        if any(token in text for token in tokens):
            return value
    return "rule_specific_sink"


def _intrinsic_usage(finding: NormalizedFinding) -> bool:
    rule = finding.rule_id.lower()
    return any(token in rule for token in ("insecure-hash", "weak-random", "secure-cookie"))


def _sink_call_regex(finding: NormalizedFinding) -> str:
    """Return a rule-scoped sink regex instead of the global sink universe."""
    sink_type = _sink_type(finding)
    mapping = {
        "command_execution": "(?i)(system|run|call|popen)",
        "sql_query": "(?i)(execute|executemany)",
        "file_access": "(?i)(open)",
        "deserialization": "(?i)(load|loads|unsafe_load|full_load)",
        "xml_parsing": "(?i)(fromstring|parse)",
        "xpath_query": "(?i)(xpath)",
        "html_rendering": "(?i)(render_template_string|mark_safe|Markup)",
        "weak_cryptography": "(?i)(md5|sha1|new)",
        "weak_randomness": "(?i)(random|randint|randrange|choice)",
    }
    return mapping.get(sink_type, _SINK_CALL_REGEX)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _extract_json(stdout: str) -> Any:
    """Extract only a JSON value emitted by ``toJsonPretty``."""
    clean = _ANSI_ESCAPE.sub("", stdout)
    triple = re.findall(r'"""([\s\S]*?)"""', clean)
    if not triple:
        raise ValueError("Joern query did not return a JSON projection.")
    return json.loads(triple[-1])


def _relative_cpg_path(value: object) -> str:
    """Project a Joern filename to a contained repository-relative path."""
    normalized = str(value or "").replace("\\", "/")
    prefix = f"{_CONTAINER_REPOSITORY}/"
    normalized = normalized.removeprefix(prefix)
    candidate = PurePosixPath(normalized)
    if (
        not normalized
        or candidate.is_absolute()
        or ".." in candidate.parts
        or any(part in {"", "."} for part in candidate.parts)
    ):
        raise ValueError("Joern returned a path outside the repository projection.")
    return candidate.as_posix()


class _CpgqlClient:
    """Small timeout-aware client for Joern's CPGQL server protocol."""

    def __init__(
        self,
        endpoint: str,
        username: str,
        password: str,
        *,
        timeout_seconds: float,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._auth = (username, password)
        self._timeout = timeout_seconds

    async def _execute(self, query: str) -> dict[str, Any]:
        import requests
        import websockets

        async with websockets.connect(
            f"ws://{self._endpoint}/connect",
            open_timeout=min(self._timeout, 10),
            # Joern can be CPU-bound while importing a large repository and
            # may not answer protocol pings. asyncio.wait_for below remains
            # the authoritative wall-clock timeout on loopback.
            ping_interval=None,
        ) as connection:
            connected = await asyncio.wait_for(connection.recv(), timeout=10)
            if connected != "connected":
                raise RuntimeError("Joern server returned an invalid handshake.")
            response = await asyncio.to_thread(
                requests.post,
                f"http://{self._endpoint}/query",
                json={"query": query},
                auth=self._auth,
                timeout=10,
            )
            response.raise_for_status()
            query_id = response.json()["uuid"]
            await asyncio.wait_for(connection.recv(), timeout=self._timeout)
            result = await asyncio.to_thread(
                requests.get,
                f"http://{self._endpoint}/result/{query_id}",
                auth=self._auth,
                timeout=10,
            )
            result.raise_for_status()
            payload = result.json()
            if not isinstance(payload, dict):
                raise TypeError("Joern response must be an object.")
            return payload

    def execute(self, query: str) -> dict[str, Any]:
        """Execute one fixed query with a wall-clock timeout."""
        return asyncio.run(self._execute(query))


class JoernAnalysisBackend:
    """Own one Joern container and one imported CPG for a complete CLI run."""

    repository_index = None

    def __init__(
        self,
        repository: Path,
        repository_identifier: str,
        *,
        module2_enabled: bool,
        image: str = JOERN_IMAGE,
        query_timeout_seconds: float = 30.0,
        build_timeout_seconds: float = 600.0,
    ) -> None:
        self._repository = repository.resolve()
        self._module2_enabled = module2_enabled
        self._image = image
        self._container_name = f"sast-triage-joern-{uuid.uuid4().hex[:12]}"
        self._username = "sast-triage"
        self._password = secrets.token_urlsafe(24)
        self._port = _free_loopback_port()
        self._client = _CpgqlClient(
            f"127.0.0.1:{self._port}",
            self._username,
            self._password,
            timeout_seconds=query_timeout_seconds,
        )
        self._build_client = _CpgqlClient(
            f"127.0.0.1:{self._port}",
            self._username,
            self._password,
            timeout_seconds=build_timeout_seconds,
        )
        self._closed = False
        self._query_durations: list[float] = []
        self._tool_counts: Counter[str] = Counter()
        started = time.perf_counter()
        failure_stage = "preflight"
        try:
            self._preflight()
            failure_stage = "container_start"
            self._start_container()
            failure_stage = "server_readiness"
            self._wait_until_ready()
            failure_stage = "cpg_import"
            project = "repo_" + hashlib.sha256(
                repository_identifier.encode("utf-8")
            ).hexdigest()[:16]
            result = self._build_client.execute(
                "importCode(inputPath="
                f"{_scala_string(_CONTAINER_REPOSITORY)}, projectName={_scala_string(project)}, "
                'language="PYTHONSRC")'
            )
            if result.get("success") is not True:
                raise RuntimeError("Joern could not import the Python repository.")
        except Exception as exc:
            self.close()
            if isinstance(exc, SastTriageError):
                raise
            raise SastTriageError(
                safe_message=f"Joern failed during safe stage: {failure_stage}.",
                error_code=f"ANALYSIS_JOERN_{failure_stage.upper()}_FAILED",
                retryable=True,
            ) from None
        self.identity = AnalysisIdentity(
            backend="joern",
            version=JOERN_VERSION,
            config_id=JOERN_CONFIG_ID,
            build_status="complete",
            build_seconds=round(time.perf_counter() - started, 6),
        )

    def _docker(self, *arguments: str, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ("docker", *arguments),
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except FileNotFoundError:
            raise SastTriageError(
                safe_message="Docker CLI is required for the Joern analysis backend.",
                error_code="ANALYSIS_JOERN_DOCKER_UNAVAILABLE",
                retryable=False,
            ) from None
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise SastTriageError(
                safe_message="Docker could not start or inspect the Joern backend.",
                error_code="ANALYSIS_JOERN_DOCKER_UNAVAILABLE",
                retryable=True,
            ) from None

    def _preflight(self) -> None:
        self._docker("info", "--format", "{{.ServerVersion}}", timeout=20)
        try:
            self._docker("image", "inspect", self._image, timeout=20)
        except SastTriageError:
            raise SastTriageError(
                safe_message=(
                    "The pinned Joern image is missing. Build docker/joern/Dockerfile first."
                ),
                error_code="ANALYSIS_JOERN_IMAGE_MISSING",
                retryable=False,
            ) from None

    def _start_container(self) -> None:
        mount = f"type=bind,source={self._repository},target={_CONTAINER_REPOSITORY},readonly"
        self._docker(
            "run",
            "--detach",
            "--rm",
            "--name",
            self._container_name,
            "--publish",
            f"127.0.0.1:{self._port}:8080",
            "--mount",
            mount,
            self._image,
            "--server",
            "--server-host",
            "0.0.0.0",
            "--server-port",
            "8080",
            "--server-auth-username",
            self._username,
            "--server-auth-password",
            self._password,
        )

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                result = self._client.execute("workspace")
                if result.get("success") is True:
                    return
            except Exception:  # noqa: BLE001 - third-party protocol boundary
                time.sleep(2)
        raise RuntimeError("Joern server readiness timeout.")

    def close(self) -> None:
        """Stop the ephemeral container and remove its in-container CPG workspace."""
        if self._closed:
            return
        self._closed = True
        try:
            subprocess.run(
                ("docker", "rm", "--force", self._container_name),
                check=False,
                capture_output=True,
                timeout=30,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _target_expression(finding: NormalizedFinding) -> str:
        path = _scala_string(finding.file_path.replace("\\", "/"))
        end_line = finding.end_line or finding.start_line
        return (
            f"cpg.call.name({_scala_string(_sink_call_regex(finding))}).filter(c => "
            f"c.lineNumber.exists(l => l >= {finding.start_line} && l <= {end_line}) && "
            f"c.file.name.headOption.exists(n => n.replace('\\\\', '/').endsWith({path})))"
        )

    @staticmethod
    def _source_expression(
        finding: NormalizedFinding | None,
        *,
        same_file: bool,
    ) -> str:
        """Build a receiver-aware source traversal without exporting call code."""
        specific_names = ", ".join(_scala_string(name) for name in _SPECIFIC_SOURCE_NAMES)
        file_filter = ""
        if same_file:
            if finding is None:
                raise ValueError("A finding is required for same-file source selection.")
            path = _scala_string(finding.file_path.replace("\\", "/"))
            file_filter = (
                ".filter(c => c.file.name.headOption.exists(n => "
                f"n.replace('\\\\', '/').endsWith({path})))"
            )
        return (
            f"cpg.call.name({_scala_string(_SOURCE_CALL_REGEX)}).filter(c => {{ "
            "val lowered=c.name.toLowerCase; "
            f"Set({specific_names}).contains(lowered) || "
            'Set("input","read","recv").contains(lowered) || '
            f"c.ast.isIdentifier.name({_scala_string(_SOURCE_RECEIVER_REGEX)}).nonEmpty "
            f"}}){file_filter}"
        )

    def _query_json(self, query: str) -> Any:
        started = time.perf_counter()
        try:
            result = self._client.execute(query)
        finally:
            self._query_durations.append(time.perf_counter() - started)
        if result.get("success") is not True:
            raise RuntimeError("Joern query failed.")
        return _extract_json(str(result.get("stdout", "")))

    @staticmethod
    def _parse_steps(raw: Any, *, max_nodes: int) -> tuple[tuple[GraphStep, ...], ...]:
        paths: list[tuple[GraphStep, ...]] = []
        if not isinstance(raw, list):
            return ()
        for raw_path in raw:
            if not isinstance(raw_path, list):
                continue
            steps: list[GraphStep] = []
            for item in raw_path[:max_nodes]:
                if not isinstance(item, dict):
                    continue
                file_path = _relative_cpg_path(item.get("file"))
                line = item.get("line")
                steps.append(
                    GraphStep(
                        kind=str(item.get("label", "unknown")).lower(),
                        symbol=str(item.get("symbol", "unknown")),
                        file_path=file_path,
                        line=line if isinstance(line, int) and line > 0 else None,
                    )
                )
            if steps:
                paths.append(tuple(steps))
        return tuple(paths)

    def _sink_evidence(self, finding: NormalizedFinding) -> GraphEvidence:
        target = self._target_expression(finding)
        query = (
            f"val targets={target}; targets.take(10).map(c => Map("
            '"symbol" -> c.name, "line" -> c.lineNumber.getOrElse(-1), '
            '"file" -> c.file.name.headOption.getOrElse(""))).toJsonPretty'
        )
        raw = self._query_json(query)
        first = raw[0] if isinstance(raw, list) and raw and isinstance(raw[0], dict) else None
        if first is None:
            return GraphEvidence(
                sink_type=_sink_type(finding),
                limitations=("JOERN_TARGET_CALL_NOT_FOUND",),
                provenance=("JOERN_CPG",),
            )
        line = first.get("line")
        return GraphEvidence(
            sink_type=_sink_type(finding),
            sink_symbol=str(first.get("symbol", "unknown")),
            sink_file=_relative_cpg_path(first.get("file", finding.file_path)),
            sink_line=line if isinstance(line, int) and line > 0 else finding.start_line,
            provenance=("JOERN_CPG", "JOERN_AST"),
        )

    def _trace(self, finding: NormalizedFinding, *, same_file: bool, max_paths: int, max_nodes: int) -> GraphEvidence:
        target = self._target_expression(finding)
        sources = self._source_expression(finding, same_file=same_file)
        query = (
            "import io.joern.dataflowengineoss.language.*; "
            "import io.shiftleft.codepropertygraph.generated.nodes; "
            f"val targets={target}; val sources={sources}; "
            f"targets.reachableByFlows(sources).take({max_paths}).map(p => "
            "p.elements.filter(n => Set(\"CALL\",\"IDENTIFIER\",\"METHOD_PARAMETER_IN\","
            "\"METHOD_RETURN\").contains(n.label)).take("
            f"{max_nodes}).map(n => Map(\"label\" -> n.label, \"symbol\" -> (n match {{ "
            "case x: nodes.Call => x.name; case x: nodes.Identifier => x.name; "
            "case x: nodes.MethodParameterIn => x.name; case _ => n.label }), "
            '"line" -> n.lineNumber.getOrElse(-1), "file" -> '
            'n.file.name.headOption.getOrElse("")))).toJsonPretty'
        )
        paths = self._parse_steps(self._query_json(query), max_nodes=max_nodes)
        if not paths:
            return GraphEvidence(
                source_reaches_sink=None,
                path_complete=False,
                limitations=(("JOERN_LOCAL_FLOW_NOT_FOUND" if same_file else "JOERN_CROSS_FILE_FLOW_NOT_FOUND"),),
                provenance=("JOERN_CPG", "JOERN_DATAFLOW"),
            )
        first = paths[0]
        source = first[0]
        return GraphEvidence(
            source_type="user_controlled_call",
            source_file=source.file_path,
            source_line=source.line,
            source_user_controlled=True,
            paths=paths,
            source_reaches_sink=True,
            path_complete=True,
            # Dataflow alone does not prove that a caller/entrypoint can reach
            # the target method. The dedicated reachability tool resolves it.
            reachability_resolved=False,
            provenance=("JOERN_CPG", "JOERN_DATAFLOW"),
        )

    def _reachability(self, finding: NormalizedFinding, *, max_depth: int) -> GraphEvidence:
        target = self._target_expression(finding)
        query = (
            f"val targets={target}; targets.method.repeat(_.caller)(_.emit.maxDepth({max_depth}))"
            ".map(m => Map(\"name\" -> m.name, \"line\" -> m.lineNumber.getOrElse(-1), "
            '"file" -> m.file.name.headOption.getOrElse(""))).dedup.toJsonPretty'
        )
        raw = self._query_json(query)
        callers: list[GraphStep] = []
        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue
                line = item.get("line")
                callers.append(
                    GraphStep(
                        kind="caller",
                        symbol=str(item.get("name", "unknown")),
                        file_path=_relative_cpg_path(item.get("file")),
                        line=line if isinstance(line, int) and line > 0 else None,
                    )
                )
        return GraphEvidence(
            callers=tuple(callers),
            reachability_resolved=bool(callers),
            limitations=(() if callers else ("JOERN_ENTRYPOINT_NOT_RESOLVED",)),
            provenance=("JOERN_CPG", "JOERN_CALL_GRAPH"),
        )

    def _controls(self, finding: NormalizedFinding, evidence: GraphEvidence) -> GraphEvidence:
        target = self._target_expression(finding)
        query = (
            f"val targets={target}; targets.method.ast.isCall.name({_scala_string(_CONTROL_CALL_REGEX)})"
            ".take(20).map(c => Map(\"symbol\" -> c.name, "
            '"line" -> c.lineNumber.getOrElse(-1), "file" -> '
            'c.file.name.headOption.getOrElse(""))).toJsonPretty'
        )
        raw = self._query_json(query)
        path_symbols = {step.symbol for path in evidence.paths for step in path}
        controls: list[GraphControl] = []
        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue
                symbol = str(item.get("symbol", "unknown"))
                on_path = symbol in path_symbols
                controls.append(
                    GraphControl(
                        symbol=symbol,
                        control_type="custom_security_control",
                        on_path=on_path,
                        # A matching name is only a candidate; it is not proof
                        # that the control protects this particular flow.
                        effective=None,
                    )
                )
        return GraphEvidence(
            controls=tuple(controls),
            limitations=(() if controls else ("JOERN_SECURITY_CONTROL_NOT_FOUND",)),
            provenance=("JOERN_CPG", "JOERN_CONTROL_FLOW"),
        )

    def initial_evidence(self, finding: NormalizedFinding) -> GraphEvidence:
        """Query the target and same-file dataflow without using native analysis."""
        try:
            evidence = self._sink_evidence(finding)
            if _intrinsic_usage(finding) and evidence.sink_symbol is not None:
                return evidence.merge(
                    GraphEvidence(
                        path_complete=True,
                        reachability_resolved=True,
                        provenance=("JOERN_INTRINSIC_USAGE",),
                    )
                )
            return evidence.merge(
                self._trace(finding, same_file=True, max_paths=10, max_nodes=500)
            )
        except Exception:  # noqa: BLE001 - fail closed at the backend boundary
            return GraphEvidence(
                sink_type=_sink_type(finding),
                limitations=("JOERN_INITIAL_QUERY_FAILED",),
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
        """Execute one of the three allowlisted CPG queries."""
        if tool_name not in {
            "trace_dataflow",
            "find_reachability",
            "inspect_security_control",
        }:
            raise ValueError("Unsupported Joern evidence tool.")
        self._tool_counts[tool_name] += 1
        try:
            if tool_name == "trace_dataflow":
                return self._trace(
                    finding,
                    same_file=False,
                    max_paths=max_paths,
                    max_nodes=max_nodes,
                )
            if tool_name == "find_reachability":
                return self._reachability(finding, max_depth=max_depth)
            if tool_name == "inspect_security_control":
                return self._controls(finding, evidence)
        except Exception:  # noqa: BLE001 - fail closed at the backend boundary
            return GraphEvidence(
                limitations=(f"JOERN_{tool_name.upper()}_FAILED",),
                provenance=("JOERN_CPG",),
            )
        raise RuntimeError("Allowlisted Joern tool returned no result.")

    def safe_stats(self) -> dict[str, object]:
        """Return aggregate timing/count metadata without query text or source."""
        durations = self._query_durations
        total = sum(durations)
        return {
            "query_count": len(durations),
            "query_latency_seconds_total": round(total, 6),
            "query_latency_seconds_mean": (
                round(total / len(durations), 6) if durations else 0.0
            ),
            "query_latency_seconds_max": round(max(durations), 6) if durations else 0.0,
            "tool_call_distribution": dict(sorted(self._tool_counts.items())),
        }

    def discover_findings(
        self,
        existing: tuple[NormalizedFinding, ...],
    ) -> tuple[NormalizedFinding, ...]:
        """Discover bounded source-to-sink flows not already reported at the sink."""
        if not self._module2_enabled:
            return ()
        sources = self._source_expression(None, same_file=False)
        query = (
            "import io.joern.dataflowengineoss.language.*; "
            f"val sources={sources}; "
            f"val sinks=cpg.call.name({_scala_string(_SINK_CALL_REGEX)}); "
            "sinks.reachableByFlows(sources).take(1000).map(p => Map("
            '"sourceFile" -> p.elements.head.file.name.headOption.getOrElse(""), '
            '"sinkFile" -> p.elements.last.file.name.headOption.getOrElse(""), '
            '"sinkLine" -> p.elements.last.lineNumber.getOrElse(-1), '
            '"sinkSymbol" -> (p.elements.last match { case c: '
            'io.shiftleft.codepropertygraph.generated.nodes.Call => c.name; case _ => "unknown" })'
            ")).toJsonPretty"
        )
        try:
            raw = self._query_json(query)
        except Exception:  # noqa: BLE001 - discovery is optional and bounded
            return ()
        occupied = {(item.file_path, item.start_line) for item in existing}
        findings: list[NormalizedFinding] = []
        if not isinstance(raw, list):
            return ()
        for item in raw:
            if not isinstance(item, dict):
                continue
            try:
                source_file = _relative_cpg_path(item.get("sourceFile"))
                sink_file = _relative_cpg_path(item.get("sinkFile"))
            except ValueError:
                continue
            sink_line = item.get("sinkLine")
            if (
                not source_file
                or not sink_file
                or source_file == sink_file
                or not isinstance(sink_line, int)
                or sink_line <= 0
                or (sink_file, sink_line) in occupied
            ):
                continue
            symbol = str(item.get("sinkSymbol", "unknown"))
            digest = hashlib.sha256(
                f"JOERN:{sink_file}:{sink_line}:{symbol}".encode()
            ).hexdigest()
            findings.append(
                NormalizedFinding(
                    finding_instance_id=digest,
                    scanner=ScannerType.MODULE2,
                    finding_type=FindingType.SAST,
                    rule_id=f"module2.joern.cross-file.{symbol}",
                    rule_name="Joern cross-file source-to-sink path",
                    file_path=sink_file,
                    start_line=sink_line,
                    end_line=sink_line,
                    severity=Severity.HIGH,
                    message="Joern found a bounded cross-file source-to-sink path.",
                    metadata={"analysis_scope": "cross_file", "analysis_backend": "joern"},
                )
            )
            occupied.add((sink_file, sink_line))
        return tuple(findings)

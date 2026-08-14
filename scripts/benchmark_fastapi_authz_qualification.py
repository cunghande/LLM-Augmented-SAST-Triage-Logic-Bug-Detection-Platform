"""Run the 80-case RealVuln plus controlled-mutation authz qualification."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sast_triage.context.repository_index import build_repository_index
from sast_triage.evaluation.logic_authz import (
    LogicAuthzCase,
    LogicAuthzDataset,
    evaluate_logic_authz_dataset,
    load_logic_authz_dataset,
)

ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "api_route"}


def _route_decorator(function: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call:
    """Return the FastAPI route decorator for one benchmark handler."""
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
            continue
        if decorator.func.attr in ROUTE_METHODS:
            return decorator
    raise ValueError("Benchmark handler has no supported FastAPI decorator.")


def _target_function(tree: ast.Module, route_line: int) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """Resolve a direct route by its frozen decorator line."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(getattr(decorator, "lineno", -1) == route_line for decorator in node.decorator_list):
            return node
    raise ValueError(f"Route line {route_line} was not found.")


def _depends_name(node: ast.AST | None) -> str | None:
    """Extract a simple dependency name from Depends(name)."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, (ast.Name, ast.Attribute)):
        return None
    leaf = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
    if leaf.lower() not in {"depends", "security"} or not node.args:
        return None
    argument = node.args[0]
    if isinstance(argument, ast.Name):
        return argument.id
    if isinstance(argument, ast.Attribute):
        return argument.attr
    return None


def _direct_dependencies(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return simple dependency functions needed by the extracted handler."""
    names: set[str] = set()
    for default in (*function.args.defaults, *function.args.kw_defaults):
        name = _depends_name(default)
        if name:
            names.add(name)
    decorator = _route_decorator(function)
    for keyword in decorator.keywords:
        if keyword.arg != "dependencies":
            continue
        for item in ast.walk(keyword.value):
            name = _depends_name(item)
            if name:
                names.add(name)
    return names


def _standalone_module(source: str, case: LogicAuthzCase) -> tuple[ast.Module, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Extract a real route and its direct local dependencies into a parse-only module."""
    original = ast.parse(source)
    original_target = _target_function(original, case.route_line)
    dependency_names = _direct_dependencies(original_target)
    helpers = [
        copy.deepcopy(node)
        for node in original.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in dependency_names
        and node is not original_target
    ]
    target = copy.deepcopy(original_target)
    decorator = _route_decorator(target)
    decorator.func = ast.Attribute(value=ast.Name(id="app", ctx=ast.Load()), attr=decorator.func.attr, ctx=ast.Load())
    target.decorator_list = [decorator]
    scaffold = ast.parse("from fastapi import FastAPI, Depends, Security\napp = FastAPI()\n")
    module = ast.Module(body=[*scaffold.body, *helpers, target], type_ignores=[])
    return module, target


def _replace_dependency_defaults(function: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
    """Remove dependency execution from a guard-removal mutation."""
    function.args.defaults = [
        ast.Constant(value=None) if _depends_name(default) else default
        for default in function.args.defaults
    ]
    function.args.kw_defaults = [
        ast.Constant(value=None) if _depends_name(default) else default
        for default in function.args.kw_defaults
    ]
    decorator = _route_decorator(function)
    decorator.keywords = [keyword for keyword in decorator.keywords if keyword.arg != "dependencies"]


def _add_guard(module: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef, guard: str, style: str) -> None:
    """Add a deterministic handler- or decorator-level authorization dependency."""
    guard_function = ast.FunctionDef(
        name=guard,
        args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=[ast.Return(value=ast.Constant(value=None))],
        decorator_list=[],
    )
    module.body.insert(-1, guard_function)
    depends = ast.Call(func=ast.Name(id="Depends", ctx=ast.Load()), args=[ast.Name(id=guard, ctx=ast.Load())], keywords=[])
    if style == "handler_dependency":
        function.args.kwonlyargs.append(ast.arg(arg=f"authz_{guard}"))
        function.args.kw_defaults.append(depends)
        return
    decorator = _route_decorator(function)
    decorator.keywords.append(ast.keyword(arg="dependencies", value=ast.List(elts=[depends], ctx=ast.Load())))


def _materialize_mutation(
    temporary_root: Path,
    base: LogicAuthzCase,
    mutation_id: str,
    expected_state: str,
    mutation_type: str,
) -> tuple[LogicAuthzCase, tuple[Any, ...], dict[str, Any]]:
    """Create, index and describe one source-local controlled mutation."""
    source_path = Path(base.repository_root) / base.file_path
    source = source_path.read_text(encoding="utf-8")
    module, target = _standalone_module(source, base)
    target.name = f"{target.name}_{mutation_id.replace('-', '_')}"
    if mutation_type == "guard_removed":
        _replace_dependency_defaults(target)
        route = _route_decorator(target)
        route.args = [ast.Constant(value=f"/accounts/{{resource_id}}/{mutation_id}")]
        target.body = [
            ast.Return(
                value=ast.Dict(
                    keys=[ast.Constant(value="account_balance"), ast.Constant(value="owner_contact")],
                    values=[ast.Constant(value=100), ast.Constant(value="restricted")],
                )
            )
        ]
    elif mutation_type in {"handler_dependency", "router_dependency"}:
        _add_guard(module, target, f"require_permission_{mutation_id.replace('-', '_')}", mutation_type)
    elif mutation_type != "positive_reformat":
        raise ValueError(f"Unsupported mutation type: {mutation_type}")
    ast.fix_missing_locations(module)
    repository_identifier = f"controlled-{mutation_id}"
    repo_root = temporary_root / repository_identifier
    repo_root.mkdir()
    mutated_path = repo_root / "app.py"
    mutated_path.write_text(ast.unparse(module) + "\n", encoding="utf-8")
    endpoints = build_repository_index(repo_root, repository_identifier).analyze_fastapi_authorization()
    endpoint = next(item for item in endpoints if item.handler.endswith(target.name))
    case = LogicAuthzCase(
        case_id=f"{repository_identifier}:{target.name}",
        repository_identifier=repository_identifier,
        repository_root="temp://controlled-mutation",
        file_path="app.py",
        route_line=endpoint.route_line,
        expected_state=expected_state,
        split=base.split,
        case_type=f"controlled_{mutation_type}",
        theme=base.theme,
        negative_control_type=(mutation_type if expected_state == "PROTECTED" else None),
        reviewer_ids=(),
        adjudication_status="UNREVIEWED",
    )
    provenance = {
        "case_id": case.case_id,
        "base_case_id": base.case_id,
        "base_repository": base.repository_identifier,
        "base_file": base.file_path,
        "base_route_line": base.route_line,
        "mutation_type": mutation_type,
        "expected_state": expected_state,
        "split": base.split,
        "theme": base.theme,
        "source_persisted": False,
    }
    return case, tuple(endpoints), provenance


def _natural_predictions(dataset: LogicAuthzDataset) -> tuple[Any, ...]:
    """Analyze every natural repository once."""
    roots = {case.repository_identifier: Path(case.repository_root) for case in dataset.cases}
    endpoints: list[Any] = []
    for identifier, root in sorted(roots.items()):
        index = build_repository_index(root.resolve(), identifier)
        endpoints.extend(index.analyze_fastapi_authorization())
    return tuple(endpoints)


def main() -> int:
    """Build 45 temporary mutations and evaluate the frozen 80-case dataset."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-name", required=True)
    args = parser.parse_args()
    natural = load_logic_authz_dataset(args.manifest)
    positives = [case for case in natural.cases if case.expected_state == "MISSING_AUTHZ"]
    negatives = [case for case in natural.cases if case.expected_state == "PROTECTED"]
    mutation_cases: list[LogicAuthzCase] = []
    mutation_predictions: list[Any] = []
    provenance: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="sast-triage-authz-") as temp:
        temporary_root = Path(temp)
        specifications: list[tuple[LogicAuthzCase, str, str, str]] = []
        for index, base in enumerate(positives[:16], start=1):
            specifications.append((base, f"positive-reformat-{index:02d}", "MISSING_AUTHZ", "positive_reformat"))
        for index, base in enumerate(negatives[:5], start=1):
            specifications.append((base, f"guard-removed-{index:02d}", "MISSING_AUTHZ", "guard_removed"))
        for index, base in enumerate(positives[:12], start=1):
            specifications.append((base, f"handler-guard-{index:02d}", "PROTECTED", "handler_dependency"))
            specifications.append((base, f"router-guard-{index:02d}", "PROTECTED", "router_dependency"))
        for base, mutation_id, expected, mutation_type in specifications:
            case, endpoints, record = _materialize_mutation(
                temporary_root, base, mutation_id, expected, mutation_type
            )
            mutation_cases.append(case)
            mutation_predictions.extend(endpoints)
            provenance.append(record)
        qualified = LogicAuthzDataset(
            version="realvuln-v2-fastapi-authz-qualification-v2",
            cases=(*natural.cases, *mutation_cases),
            dataset_kind="realvuln_controlled_unreviewed",
            held_out_frozen=True,
            ground_truth_sha256=natural.ground_truth_sha256,
        )
        result = evaluate_logic_authz_dataset(
            qualified,
            (*_natural_predictions(natural), *mutation_predictions),
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    result["controlled_mutation_count"] = len(mutation_cases)
    result["natural_case_count"] = len(natural.cases)
    result["mutation_spec_sha256"] = hashlib.sha256(
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    result_path = args.output_dir / f"{args.run_name}.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "dataset-manifest.json").write_text(
        json.dumps(
            {
                "version": qualified.version,
                "ground_truth_sha256": qualified.ground_truth_sha256,
                "natural_manifest": args.manifest.as_posix(),
                "natural_case_count": len(natural.cases),
                "controlled_mutation_count": len(mutation_cases),
                "positive_count": result["positive_count"],
                "negative_count": result["negative_count"],
                "cases": [
                    {
                        "case_id": case.case_id,
                        "repository_identifier": case.repository_identifier,
                        "file_path": case.file_path,
                        "route_line": case.route_line,
                        "expected_state": case.expected_state,
                        "split": case.split,
                        "case_type": case.case_type,
                        "theme": case.theme,
                    }
                    for case in qualified.cases
                ],
                "mutations": provenance,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    mutation_by_case = {record["case_id"]: record for record in provenance}
    audit_cases = []
    for case in qualified.cases:
        audit_cases.append(
            {
                "case_id": case.case_id,
                "repository_identifier": case.repository_identifier,
                "file_path": case.file_path,
                "route_line": case.route_line,
                "expected_state": case.expected_state,
                "split": case.split,
                "case_type": case.case_type,
                "theme": case.theme,
                "ground_truth_source": (
                    "controlled_mutation" if case.case_id in mutation_by_case else "realvuln_v2_official"
                ),
                "mutation_provenance": mutation_by_case.get(case.case_id),
                "reviewer_ids": list(case.reviewer_ids),
                "reviewer_rationale": None,
                "adjudication_status": case.adjudication_status,
                "dispute_notes": None,
            }
        )
    (args.output_dir / "ground-truth-audit.json").write_text(
        json.dumps(
            {
                "status": "PENDING_INDEPENDENT_REVIEW",
                "required_reviewers_per_binary_case": 2,
                "cases": audit_cases,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    held_out = result["metrics_by_split"]["held_out"]
    print(
        f"Qualification: cases={result['case_count']} positives={result['positive_count']} "
        f"negatives={result['negative_count']} precision={held_out['precision']:.3f} "
        f"recall={held_out['recall']:.3f} f1={held_out['f1']:.3f} "
        f"gate={'PASS' if result['quality_gate']['passed'] else 'FAIL'}"
    )
    return 0 if result["quality_gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

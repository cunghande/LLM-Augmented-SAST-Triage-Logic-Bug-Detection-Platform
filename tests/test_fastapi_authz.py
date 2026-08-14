"""Tests for the bounded FastAPI missing authorization detector."""

import json
from pathlib import Path

from sast_triage.context.repository_index import (
    _classify_control,
    build_repository_index,
)
from sast_triage.evaluation.logic_authz import (
    evaluate_logic_authz_dataset,
    load_logic_authz_dataset,
)
from sast_triage.models import ScannerType


def test_fastapi_detector_separates_authentication_from_authorization() -> None:
    index = build_repository_index(Path("tests/fixtures/fastapi_authz"), "fastapi-fixture")
    endpoints = index.analyze_fastapi_authorization()
    remove = next(item for item in endpoints if item.handler.endswith("remove_user"))
    guarded = next(item for item in endpoints if item.handler.endswith("admin_remove_user"))

    assert remove.analysis_state == "MISSING_AUTHZ_CANDIDATE"
    assert remove.authentication_controls == ("get_current_user",)
    assert remove.authorization_controls == ()
    assert guarded.analysis_state == "PROTECTED"
    assert guarded.authorization_controls == ("require_admin",)

    findings = index.discover_fastapi_authorization_findings()
    assert len(findings) == 1
    assert findings[0].scanner == ScannerType.MODULE2
    assert findings[0].rule_id == "module2.fastapi.missing-function-authz"
    assert findings[0].metadata["context_completeness"] == "COMPLETE"
    assert "get_current_user" in findings[0].metadata["authentication_controls"]
    assert _classify_control("get_access_token") == ("authentication", "get_access_token")


def test_fastapi_router_dependency_is_protected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "def require_role(): return None\n"
        "router = APIRouter(dependencies=[Depends(require_role)])\n"
        "@router.delete('/records/{record_id}')\n"
        "def remove(record_id: int): return record_id\n",
        encoding="utf-8",
    )
    index = build_repository_index(repo, "router-fixture")
    endpoint = index.analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "PROTECTED"
    assert endpoint.authorization_controls == ("require_role",)
    assert index.discover_fastapi_authorization_findings() == ()


def test_fastapi_dynamic_dependency_is_unknown_not_missing_authz(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import FastAPI, Depends\n"
        "app = FastAPI()\n"
        "@app.delete('/records/{record_id}', dependencies=[Depends(lambda: None)])\n"
        "def remove(record_id: int): return record_id\n",
        encoding="utf-8",
    )
    index = build_repository_index(repo, "dynamic-fixture")
    endpoint = index.analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "UNKNOWN"
    assert endpoint.completeness == "PARTIAL"
    assert index.discover_fastapi_authorization_findings() == ()


def test_fastapi_include_router_dependency_is_inherited(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.delete('/records/{record_id}')\n"
        "def remove(record_id: int): return record_id\n",
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        "from fastapi import Depends, FastAPI\n"
        "from routes import router\n"
        "def require_tenant(): return None\n"
        "app = FastAPI()\n"
        "app.include_router(router, dependencies=[Depends(require_tenant)])\n",
        encoding="utf-8",
    )
    index = build_repository_index(repo, "include-fixture")
    endpoint = next(item for item in index.analyze_fastapi_authorization() if item.handler.endswith("remove"))
    assert endpoint.analysis_state == "PROTECTED"
    assert endpoint.authorization_controls == ("require_tenant",)


def test_fastapi_inline_role_check_counts_as_authorization(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.delete('/users/{user_id}')\n"
        "def remove(user_id: int, current_user):\n"
        "    if current_user.role != 'admin': raise PermissionError()\n"
        "    return user_id\n",
        encoding="utf-8",
    )
    index = build_repository_index(repo, "inline-guard-fixture")
    endpoint = index.analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "PROTECTED"
    assert endpoint.authorization_controls


def test_sensitive_get_response_becomes_candidate_without_authz(tmp_path: Path) -> None:
    """Sensitive response semantics make a GET endpoint authorization-relevant."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/ops')\n"
        "@router.get('/summary')\n"
        "def summary():\n"
        "    return {'account_balance': 100, 'owner_contact': 'hidden'}\n",
        encoding="utf-8",
    )
    endpoint = build_repository_index(repo, "sensitive-get").analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "MISSING_AUTHZ_CANDIDATE"
    assert "sensitive_response_or_branch" in endpoint.sensitivity_reasons


def test_client_asserted_badge_is_not_server_authorization(tmp_path: Path) -> None:
    """A privilege claim read from a client-controlled cookie is not authz proof."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import FastAPI, Request\n"
        "app = FastAPI()\n"
        "@app.get('/panel')\n"
        "def panel(request: Request):\n"
        "    badge = request.cookies.get('ops_badge')\n"
        "    if badge == 'lead':\n"
        "        return {'payroll': 'full'}\n"
        "    return {'payroll': 'limited'}\n",
        encoding="utf-8",
    )
    endpoint = build_repository_index(repo, "badge-get").analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "MISSING_AUTHZ_CANDIDATE"
    assert endpoint.authorization_controls == ()


def test_role_reference_without_enforcement_is_not_authz(tmp_path: Path) -> None:
    """Merely returning a role does not prove that access was enforced."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/admin/profile')\n"
        "def profile(current_user):\n"
        "    return {'role': current_user.role, 'email': current_user.email}\n",
        encoding="utf-8",
    )
    endpoint = build_repository_index(repo, "role-reference").analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "MISSING_AUTHZ_CANDIDATE"
    assert endpoint.authorization_controls == ()


def test_concrete_guard_wins_over_unresolved_middleware(tmp_path: Path) -> None:
    """Dynamic middleware cannot invalidate a route-local authorization proof."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "app.add_middleware(object)\n"
        "def require_permission(): return None\n"
        "@app.get('/accounts/{account_id}')\n"
        "def account(account_id: int):\n"
        "    require_permission()\n"
        "    return {'account_id': account_id}\n",
        encoding="utf-8",
    )
    endpoint = build_repository_index(repo, "middleware-guard").analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "PROTECTED"


def test_router_and_include_prefix_are_projected_into_safe_route(tmp_path: Path) -> None:
    """Router prefixes contribute to sensitivity without leaking arbitrary paths."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/admin')\n"
        "@router.get('/panel')\n"
        "def panel(): return {'ok': True}\n",
        encoding="utf-8",
    )
    (repo / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "from routes import router\n"
        "app = FastAPI()\n"
        "app.include_router(router, prefix='/v1')\n",
        encoding="utf-8",
    )
    endpoint = build_repository_index(repo, "prefix-fixture").analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "MISSING_AUTHZ_CANDIDATE"
    assert "/admin/" in endpoint.route_path


def test_authz_proof_keeps_otherwise_nonsensitive_get_in_inventory(tmp_path: Path) -> None:
    """A proven guard remains auditable even when route sensitivity is subtle."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def can_view(subject, resource): return True\n"
        "@app.get('/applications/status')\n"
        "def status(subject, resource):\n"
        "    if not can_view(subject, resource): raise PermissionError()\n"
        "    return {'state': 'open'}\n",
        encoding="utf-8",
    )
    endpoint = build_repository_index(repo, "guard-inventory").analyze_fastapi_authorization()[0]
    assert endpoint.analysis_state == "PROTECTED"
    assert endpoint.sensitivity_reasons == ("authorization_control_present",)


def test_public_catalog_with_contact_text_is_not_reported(tmp_path: Path) -> None:
    """An explicit public route remains exempt from sensitive literal signals."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/public/catalog')\n"
        "def catalog(): return {'contact': 'sales@example.invalid'}\n",
        encoding="utf-8",
    )
    index = build_repository_index(repo, "public-catalog")
    assert index.analyze_fastapi_authorization() == ()
    assert index.discover_fastapi_authorization_findings() == ()


def test_handler_with_multiple_route_decorators_indexes_each_route(tmp_path: Path) -> None:
    """A shared handler must retain every distinct FastAPI endpoint."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/process/youtube')\n"
        "@app.post('/process/web')\n"
        "def process_resource(resource_id: str):\n"
        "    return {'private_contact': resource_id}\n",
        encoding="utf-8",
    )

    endpoints = build_repository_index(repo, "multi-route").analyze_fastapi_authorization()

    assert len(endpoints) == 2
    assert {endpoint.route_line for endpoint in endpoints} == {3, 4}
    assert all(endpoint.analysis_state == "MISSING_AUTHZ_CANDIDATE" for endpoint in endpoints)


def test_annotated_dependency_wrapper_proves_ownership(tmp_path: Path) -> None:
    """Depends inside Annotated must be resolved like a default dependency."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "from typing import Annotated\n"
        "from fastapi import Depends, FastAPI, HTTPException\n"
        "app = FastAPI()\n"
        "def get_flow(flow_id: str, current_user):\n"
        "    flow = load_flow(flow_id)\n"
        "    if flow.user_id != current_user.id:\n"
        "        raise HTTPException(status_code=404)\n"
        "    return flow\n"
        "@app.get('/files/images/{flow_id}/{file_name}')\n"
        "def download_image(flow: Annotated[object, Depends(get_flow)]):\n"
        "    return flow\n",
        encoding="utf-8",
    )

    endpoint = build_repository_index(repo, "annotated-owner").analyze_fastapi_authorization()[0]

    assert endpoint.analysis_state == "PROTECTED"
    assert "get_flow" in endpoint.dependencies


def test_logic_authz_metrics_are_separate_and_unknown_is_not_binary(tmp_path: Path) -> None:
    manifest = tmp_path / "logic.json"
    manifest.write_text(
        json.dumps(
            {
                "version": "test-v1",
                "held_out_frozen": True,
                "cases": [
                    {
                        "case_id": "positive",
                        "repository_identifier": "fastapi-fixture",
                        "repository_root": "tests/fixtures/fastapi_authz",
                        "file_path": "app.py",
                        "route_line": 24,
                        "expected_state": "MISSING_AUTHZ",
                        "split": "held_out",
                    },
                    {
                        "case_id": "protected",
                        "repository_identifier": "fastapi-fixture",
                        "repository_root": "tests/fixtures/fastapi_authz",
                        "file_path": "app.py",
                        "route_line": 29,
                        "expected_state": "PROTECTED",
                        "split": "held_out",
                    },
                    {
                        "case_id": "unknown",
                        "repository_identifier": "fastapi-fixture",
                        "repository_root": "tests/fixtures/fastapi_authz",
                        "file_path": "missing.py",
                        "route_line": 1,
                        "expected_state": "UNKNOWN",
                        "split": "held_out",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    dataset = load_logic_authz_dataset(manifest)
    index = build_repository_index(Path("tests/fixtures/fastapi_authz"), "fastapi-fixture")
    result = evaluate_logic_authz_dataset(dataset, index.analyze_fastapi_authorization())
    held_out = result["metrics_by_split"]["held_out"]
    assert held_out["tp"] == 1
    assert held_out["fp"] == 0
    assert held_out["fn"] == 0
    assert held_out["unknown_cases"] == 1
    assert result["quality_gate"]["case_count_min"] == 80
    assert result["positive_count"] == 1
    assert result["negative_count"] == 1
    assert result["quality_gate"]["passed"] is False
    assert result["quality_claim_supported"] is False


def test_known_positive_predicted_unknown_counts_as_false_negative(tmp_path: Path) -> None:
    """An abstention on a known vulnerability must reduce detector recall."""
    manifest = tmp_path / "logic-authz-positive-unknown.json"
    manifest.write_text(
        json.dumps(
            {
                "version": "positive-unknown-v1",
                "cases": [
                    {
                        "case_id": "missed-positive",
                        "repository_identifier": "fastapi-fixture",
                        "repository_root": "tests/fixtures/fastapi_authz",
                        "file_path": "missing.py",
                        "route_line": 1,
                        "expected_state": "MISSING_AUTHZ",
                        "split": "held_out",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    dataset = load_logic_authz_dataset(manifest)
    result = evaluate_logic_authz_dataset(dataset, ())
    held_out = result["metrics_by_split"]["held_out"]
    assert held_out["predicted_unknown"] == 1
    assert held_out["fn"] == 1
    assert held_out["recall"] == 0.0

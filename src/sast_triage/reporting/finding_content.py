"""Build source-free, reviewer-oriented prose shared by report formats."""

from __future__ import annotations

from typing import Any

from sast_triage.models import NormalizedFinding, TriageResult


def _location(step: dict[str, Any]) -> str:
    """Return a compact relative location for one safe evidence step."""
    return f"{step.get('file_path', '?')}:{step.get('line', '?')}"


def _representative_steps(result: TriageResult) -> tuple[dict[str, Any], ...]:
    """Return the first complete-looking source-to-sink path, when available."""
    details = result.evidence_details
    if not isinstance(details, dict):
        return ()
    paths = details.get("paths")
    if not isinstance(paths, list):
        return ()
    for path in paths:
        if not isinstance(path, dict) or not isinstance(path.get("steps"), list):
            continue
        steps = tuple(step for step in path["steps"] if isinstance(step, dict))
        if steps:
            return steps
    return ()


def evidence_overview(result: TriageResult) -> dict[str, str]:
    """Project the most useful evidence facts into the finding status table."""
    metadata = result.finding.metadata
    steps = _representative_steps(result)
    source = "Chưa xác định"
    sink = "Chưa xác định"
    if steps:
        source = f"{steps[0].get('symbol', 'unknown')} — {_location(steps[0])}"
        sink = f"{steps[-1].get('symbol', 'unknown')} — {_location(steps[-1])}"
    else:
        if metadata.get("source_kind") is not None:
            source = str(metadata["source_kind"])
        if metadata.get("sink_kind") is not None:
            sink = str(metadata["sink_kind"])

    controls = "Không tìm thấy control hiệu quả trong evidence"
    details = result.evidence_details
    if isinstance(details, dict) and isinstance(details.get("controls"), list):
        names = [
            str(item.get("symbol", "unknown"))
            for item in details["controls"]
            if isinstance(item, dict) and item.get("effective") is True
        ]
        if names:
            controls = ", ".join(names)
    elif metadata.get("guards"):
        guards = metadata["guards"]
        if isinstance(guards, (list, tuple)):
            controls = ", ".join(str(item) for item in guards)

    completeness = "Chưa xác định"
    if isinstance(details, dict) and isinstance(details.get("completeness"), dict):
        completeness = str(details["completeness"].get("status", "Chưa xác định"))
    return {
        "source": source,
        "sink": sink,
        "controls": controls,
        "completeness": completeness,
    }


def finding_description(result: TriageResult) -> str:
    """Describe the concrete code location, flow and review conclusion."""
    finding = result.finding
    metadata = finding.metadata
    line = (
        str(finding.start_line)
        if finding.end_line in {None, finding.start_line}
        else f"{finding.start_line}-{finding.end_line}"
    )
    parts = [f"Finding nằm tại {finding.file_path}:{line}"]
    entrypoint = metadata.get("entrypoint")
    if entrypoint:
        parts[0] += f", trong luồng bắt đầu từ `{entrypoint}`"
    parts[0] += "."

    overview = evidence_overview(result)
    if overview["source"] != "Chưa xác định" or overview["sink"] != "Chưa xác định":
        parts.append(
            f"Dữ liệu được theo dõi từ {overview['source']} đến thao tác nhạy cảm "
            f"{overview['sink']}; {overview['controls'].lower()}."
        )
    if result.triage_decision is not None:
        parts.append(result.triage_decision.summary.strip())
    else:
        parts.append(
            "Không có kết luận LLM hợp lệ, vì vậy finding phải được xác minh trực tiếp "
            "trước khi quyết định xử lý."
        )
    return " ".join(parts)


def finding_impact(finding: NormalizedFinding) -> str:
    """Return a mechanism-specific impact warning without numeric risk factors."""
    text = " ".join(
        (finding.rule_id, finding.rule_name or "", str(finding.metadata.get("cwe", "")))
    ).lower()
    if finding.finding_type.value == "SECRET":
        return (
            "Nếu credential còn hiệu lực, người có quyền đọc repository hoặc artifact có "
            "thể chiếm quyền dịch vụ liên quan, truy cập dữ liệu trái phép và tiếp tục di "
            "chuyển sang các hệ thống dùng chung credential."
        )
    if any(token in text for token in ("urllib", "urlopen", "ssrf", "dynamic-url")):
        return (
            "Nếu kẻ tấn công kiểm soát được URL, máy chủ có thể bị ép gửi yêu cầu tới dịch "
            "vụ nội bộ, địa chỉ loopback, cloud metadata hoặc tài nguyên cục bộ qua scheme "
            "không mong muốn. Hậu quả có thể gồm lộ credential và dữ liệu nội bộ, dò quét "
            "mạng từ vị trí tin cậy của ứng dụng, hoặc làm cạn kết nối/bộ nhớ khi tải phản "
            "hồi lớn hay chậm. Mức ảnh hưởng thực tế phụ thuộc scheme được phép, redirect, "
            "quyền mạng và việc caller có nhận dữ liệu phản hồi hay không."
        )
    if any(token in text for token in ("sql", "injection")):
        return (
            "Dữ liệu không tin cậy đi vào câu lệnh SQL có thể cho phép đọc hoặc sửa dữ liệu "
            "trái phép, vượt qua kiểm soát truy cập và trong một số cấu hình gây mất toàn "
            "vẹn hoặc gián đoạn cơ sở dữ liệu."
        )
    if any(token in text for token in ("command", "subprocess", "popen")):
        return (
            "Khai thác thành công có thể cho phép thực thi lệnh với quyền của tiến trình ứng "
            "dụng, dẫn tới đánh cắp dữ liệu, sửa đổi hệ thống hoặc chiếm quyền máy chủ."
        )
    if any(token in text for token in ("path", "file", "traversal")):
        return (
            "Kẻ tấn công có thể đọc hoặc ghi ngoài phạm vi tài nguyên dự kiến, làm lộ file "
            "cấu hình/credential, ghi đè dữ liệu hoặc phá vỡ hoạt động của ứng dụng."
        )
    if any(token in text for token in ("idor", "authorization", "authz", "cwe-639")):
        return (
            "Người dùng đã đăng nhập có thể truy cập hoặc thay đổi đối tượng không thuộc "
            "quyền của mình, gây lộ dữ liệu giữa người dùng/tenant và mất toàn vẹn nghiệp vụ."
        )
    if "mass-assignment" in text or "mass_assignment" in text:
        return (
            "Các trường nhạy cảm ngoài dự kiến có thể bị sửa, chẳng hạn vai trò, trạng thái "
            "hoặc thuộc tính sở hữu, từ đó dẫn tới leo thang đặc quyền hoặc phá vỡ dữ liệu."
        )
    return (
        "Nếu dữ liệu không tin cậy thực sự đi tới thao tác nhạy cảm mà không có control hiệu "
        "quả, finding có thể gây lộ, sửa đổi hoặc gián đoạn dữ liệu/chức năng liên quan. "
        "Security reviewer cần xác nhận điều kiện khai thác trên toàn bộ luồng trước khi chốt mức độ."
    )

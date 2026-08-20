# Luồng hệ thống hiện tại

Tài liệu luồng cũ dựa trên native AST evidence engine đã được thay thế khi dự
án chuyển sang Joern-only.

## Luồng chính

```text
Semgrep/Gitleaks
    -> parser và NormalizedFinding
    -> SafeContextService đọc, giới hạn và redact source
    -> Joern CPG truy vấn source/sink, dataflow, caller và control cho SAST
    -> EvidencePackage source-free
    -> TriageInput
    -> provider
    -> policy bảo thủ
    -> JSON/Markdown/HTML report
```

Gitleaks không gửi bí mật thô vào Joern hoặc provider. Detector
`python-idor-business-logic` là detector semantic riêng cho IDOR và
business-rule bypass; finding của nó vẫn đi qua pipeline triage chung.

## Ranh giới an toàn

- Repository được mount read-only vào container Joern.
- Projection Joern chỉ chứa symbol, file tương đối, dòng, source/sink/control,
  trạng thái đầy đủ và provenance.
- Query transcript, literal và raw source không rời backend.
- Thiếu Docker, image hoặc evidence không làm mất finding; pipeline fail closed
  hoặc chuyển finding sang review theo policy.

Chi tiết implementation nằm tại `analysis/joern.py`,
`context/evidence_agent.py`, `context/evidence_service.py` và
`application/run.py`.

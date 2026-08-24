# Sprint 2 — Focused IDOR and business-rule detection

## Mục tiêu

Sprint 2 tập trung detector Python vào đúng hai lớp:

1. missing authorization / IDOR (`missing_authz_idor`, `CWE-639`);
2. business-rule bypass (`business_rule_bypass`, `CWE-840`).

Detector phải được bật tường minh bằng
`--logic-detector python-idor-business-logic` và yêu cầu Module 2. Finding mới
vẫn đi qua Safe Context, provider, policy và ba reporter
chung; không có pipeline hoặc cơ chế tự suppress riêng.

## Use case ưu tiên

### Tính tiền giỏ hàng

Detector theo dõi `price`, `unit_price`, `discount`, `subtotal`, `total`,
`quantity` và các alias lấy từ request. Candidate được tạo khi:

- giá hoặc tổng do client kiểm soát đi tới kết quả hay mutation;
- số lượng/domain value đi tới operation mà không có bound phía server.

Counter-example an toàn cần có quantity dương và có upper bound, đồng thời giá
được load từ nguồn phía server thay vì dùng giá do client gửi.

### Truy cập tài liệu khác chủ sở hữu

Detector theo dõi identifier từ route/query/body tới object lookup. Candidate
được loại khi query đã scope theo owner/user/tenant/share ACL hoặc có guard
authorization bảo vệ đúng object.

### Pagination/limit gây resource exhaustion

Detector tạo business-rule candidate khi page/limit do request kiểm soát được
đưa vào query mà không có lower/upper bound phù hợp, hoặc endpoint dạng list
gọi `all()`/`fetchall()` mà không có `limit`, `slice` hay `paginate`.

Đây là projection vào lớp `business_rule_bypass` của dự án. Tác động kỹ thuật
cụ thể có thể đồng thời được reviewer gắn `CWE-400` (uncontrolled resource
consumption); detector không đổi taxonomy public ngoài hai lớp đã chốt.

## Chạy demo

Khi `.venv` đã kích hoạt và PowerShell đang ở `D:\Code\target-repos`:

```powershell
python -m sast_triage scan-and-triage --repository .\<TEN_REPO> --output-dir ..\triage-runs\<TEN_REPO>-sprint2 --module2 --logic-detector python-idor-business-logic --provider fake
```

Đổi `fake` thành `real` sau khi Modal đã được cấu hình nếu cần benchmark LLM.

## Benchmark

Lệnh tái lập detector benchmark:

```powershell
python scripts\benchmark_logic_bugs.py --ground-truth-root benchmarks\Real-Vuln-Benchmark\ground-truth --repos-root benchmarks\Real-Vuln-Benchmark\repos --output benchmarks\BenchmarkOutput\sprint2-idor-business\realvuln-focused-v5.json
```

Benchmark focused gán split ổn định ở cấp repository và báo cáo metric riêng
cho `development`, `calibration`, `held_out`. Split hiện tại được tạo sau quá
trình phát triển detector nên chỉ phục vụ tái lập và kiểm soát leakage; không
được dùng để tuyên bố một kết quả held-out mới.

Lệnh kiểm chứng Joern đầy đủ, dùng image ứng dụng đã pin Semgrep/Gitleaks:

```powershell
python scripts\benchmark_realvuln_joern.py --benchmark-root benchmarks\Real-Vuln-Benchmark --output-root benchmarks\BenchmarkOutput\realvuln-v2-joern --provider fake --runtime docker
```

Focused result mới nhất được ghi tại
[`sprint-2-status.md`](sprint-2-status.md). Fake provider chỉ xác minh pipeline,
không hỗ trợ tuyên bố chất lượng model.

Lượt kiểm chứng real-provider gần nhất dùng Qwen3-14B-AWQ trên Modal và Joern
4.0.600, có evidence source–sink chi tiết và cross-file, được lưu tại
`benchmarks/BenchmarkOutput/sprint2-idor-business/demo-real-llm-full-cross-file-final/`.
Xem trạng thái Sprint 2 để biết coverage và giới hạn diễn giải.

## Điều kiện kết thúc

- CLI chỉ sinh hai logic class đã chốt.
- Guard object/tenant/share hợp lệ chặn candidate IDOR.
- Giá client, quantity thiếu bound, pagination thiếu cap và collection query
  không giới hạn có regression test.
- Giá server với quantity bounded và pagination bounded có negative test.
- Full test, Ruff và benchmark artifact tái lập đạt.
- AppSec/service owner vẫn phải review trên service thật trước formal acceptance.

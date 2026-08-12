# Joern CPG backend (thử nghiệm)

Joern `v4.0.600` là backend phân tích tùy chọn. `native` vẫn là mặc định cho tới
khi benchmark A/B chứng minh Joern cải thiện chất lượng và demo Docker ổn định.
Trong một run, hệ thống chỉ dùng đúng một backend; không trộn evidence native và
Joern.

## 1. Cài đặt

Yêu cầu Docker Desktop đang chạy, Linux containers và khoảng 4 GB dung lượng
trống. Cài dependency tùy chọn:

```powershell
cd "D:\Code\AI security"
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,joern]"
```

Build image đã pin. Dockerfile tải release Linux x86_64 chính thức và kiểm tra
SHA-256 `5463a7cb3462cc95b76656d614001e95a4c5bddb3563b021e5ec4cecbed536ba`:

```powershell
docker build `
  --tag sast-triage-joern:4.0.600 `
  --file docker/joern/Dockerfile `
  .
docker image inspect sast-triage-joern:4.0.600
```

Lần build đầu tải khoảng 1,83 GB. CLI không tự tải image và không tự fallback
sang native; thiếu Docker/image sẽ trả lỗi cấu hình an toàn.

## 2. Chạy

Lệnh rút gọn từ thư mục `target-repos`:

```powershell
python -m sast_triage Sequential-Recommender --analysis-backend joern
```

Lệnh đầy đủ với fake provider để smoke test không tốn GPU:

```powershell
python -m sast_triage scan-and-triage `
  --repository "D:\Code\target-repos\Sequential-Recommender" `
  --output-dir "D:\Code\triage-runs\joern-smoke" `
  --provider fake `
  --analysis-backend joern `
  --module2
```

Để chạy backend cũ, bỏ option hoặc dùng `--analysis-backend native`.

## 3. Luồng và ranh giới an toàn

Joern tạo một CPG cho toàn repository. Module 1 truy vấn AST/CFG/call/dataflow
quanh finding; Evidence Agent chỉ mở rộng cross-file bằng ba tool cố định:
`trace_dataflow`, `find_reachability`, `inspect_security_control`. Agent chạy tối
đa 5 vòng, 5 tool call, depth 5, 10 path, 500 node và 60 giây/finding.

Repository được mount read-only. Server chỉ publish trên `127.0.0.1`, có thông
tin xác thực ngẫu nhiên theo session. Container và workspace CPG trong container
bị xóa khi run kết thúc. Projection đưa ra khỏi backend chỉ có identifier, đường
dẫn tương đối, dòng, source/sink/control, completeness và provenance; không có
source code, literal hoặc query transcript.

Gitleaks không dùng CPG và tiếp tục đi qua nhánh redaction hiện tại.

## 4. Đọc báo cáo và xử lý lỗi

`run-metadata.json` và `report.md` ghi backend, version/config ID, trạng thái và
thời gian build CPG. Checkpoint được bind với các giá trị này; resume bằng backend
hoặc version khác sẽ bị từ chối.

- `ANALYSIS_JOERN_DOCKER_UNAVAILABLE`: mở Docker Desktop, chạy `docker info`.
- `ANALYSIS_JOERN_IMAGE_MISSING`: build đúng image/tag ở bước 1.
- `ANALYSIS_JOERN_BUILD_FAILED`: kiểm tra target là repository Python đọc được và
  Docker còn đủ RAM/disk.
- Evidence `PARTIAL`: Agent đã timeout, không tiến triển hoặc hết budget; policy
  giữ finding ở `MANUAL_REVIEW` nếu thiếu evidence quan trọng.


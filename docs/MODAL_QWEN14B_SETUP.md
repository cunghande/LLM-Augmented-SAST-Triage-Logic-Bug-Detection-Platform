# Chạy Qwen3-14B-AWQ độc lập trên Modal

Tài liệu này mô tả backend đóng gói tại
`src/sast_triage/triage/qwen14b_modal_app.py`. File
`modal_apps/qwen14b_modal.py` là entrypoint tương thích cho các lệnh Modal. Backend được tích
hợp vào CLI qua `--provider real`; script prompt và benchmark riêng vẫn được giữ
để chẩn đoán và đánh giá.

Luồng dữ liệu:

```text
Laptop chạy Modal CLI
  -> CPU Modal tải Qwen/Qwen3-14B-AWQ từ Hugging Face
  -> qwen3-14b-hf-cache lưu model
  -> GPU Modal đọc model và qwen3-14b-vllm-cache
  -> kết quả cuối cùng trở về terminal laptop
```

Model weights không được tải xuống ổ đĩa laptop. `snapshot_download()` chạy
trong container CPU của Modal và ghi vào Modal Volume.

## Cấu hình đã khóa

- Model: `Qwen/Qwen3-14B-AWQ`.
- Modal SDK được đối chiếu với API 1.5.3 hiện hành; hãy cài bản ổn định mới nhất ở
  máy local bằng lệnh bên dưới.
- Image GPU: CUDA 12.9, Python 3.12.
- Dependency trong image: `vllm==0.26.0` và
  `huggingface-hub==1.24.0`.
- GPU mặc định: một `B200`; có thể chọn `H100`, `H200`, `L40S` hoặc `L4` bằng
  `MODAL_GPU`. Benchmark thực tế phải tách cold start khỏi latency steady-state vì
  GPU mạnh hơn không bảo đảm tổng thời gian ngắn hơn cho batch tuần tự nhỏ.
- `max_containers=1`, `min_containers=0`, `scaledown_window=300` giây.
- Timeout GPU: 1200 giây.
- `max_model_len=4096`, `max_num_seqs=1`,
  `gpu_memory_utilization=0.90`.
- Mỗi container chỉ xử lý một input tại một thời điểm.
- `thinking=false`, `max_tokens=256`, `temperature=0.1` theo mặc định.

Các lựa chọn này dựa trên API Modal hiện hành cho
[GPU](https://modal.com/docs/guide/gpu),
[autoscaling](https://modal.com/docs/guide/scale),
[class lifecycle](https://modal.com/docs/sdk/py/latest/modal.enter) và
[Volume](https://modal.com/docs/guide/volumes). vLLM 0.26.0 hỗ trợ
`Qwen3ForCausalLM`, AWQ trên L4/L40S/H100, `LLM.chat()` và
`chat_template_kwargs`; Qwen hướng dẫn dùng `enable_thinking` để chuyển chế độ
thinking. Xem [vLLM supported models](https://docs.vllm.ai/en/latest/models/supported_models/),
[vLLM quantization](https://docs.vllm.ai/en/stable/features/quantization/) và
[model card Qwen3-14B-AWQ](https://huggingface.co/Qwen/Qwen3-14B-AWQ).

## 1. Cài và đăng nhập Modal trên Windows

Mở PowerShell tại thư mục gốc repository:

```powershell
py -m pip install --upgrade modal
python -m modal setup
```

Nếu máy không có Python Launcher `py`, thay `py` bằng `python` trong toàn bộ
các lệnh của tài liệu.

`modal setup` mở luồng xác thực và lưu credential Modal trên máy. Nếu lệnh chạy
báo chưa xác thực, chạy lại `python -m modal setup` và xác nhận đúng Workspace.

## 2. Kiểm tra plan, credit và budget trước khi chạy

Trong Modal Dashboard, mở **Workspace Settings -> Usage & Billing**:

1. Xác nhận Workspace đang ở Starter plan. Tại thời điểm tài liệu này được
   kiểm tra, Starter có 30 USD compute credit mỗi tháng; luôn tin số đang hiển
   thị trên Dashboard vì pricing có thể thay đổi.
2. Xem credit còn lại và phương thức thanh toán.
3. Đặt Workspace Budget khoảng 28 hoặc 29 USD nếu muốn chừa biên dưới mức
   credit 30 USD. Không đặt budget cao hơn credit hiện có nếu không muốn phần
   vượt mức có thể được tính vào thẻ.
4. Budget là giới hạn chi tiêu, không phải dự toán VRAM. Modal áp dụng Workspace
   budget như hard cap cho toàn Workspace.

Tham khảo [Modal Pricing](https://modal.com/pricing),
[Billing](https://modal.com/docs/guide/billing) và
[Budgets](https://modal.com/docs/guide/budgets).

## 3. Tải model vào Modal Volume bằng CPU

Chạy đúng entrypoint từ thư mục gốc repository:

```powershell
python -m modal run modal_apps/qwen14b_modal.py::download_model
```

Lệnh này build image CPU nhỏ, tạo Volume nếu chưa có, gọi
`huggingface_hub.snapshot_download()`, rồi commit dữ liệu vào
`qwen3-14b-hf-cache`. Lần đầu có thể lâu vì toàn bộ AWQ snapshot được tải trực
tiếp từ Hugging Face vào hạ tầng Modal. Các lần sau tái sử dụng cache.

Model này là public nên không bắt buộc `HF_TOKEN`. File hiện tại không cấu hình
token hay Modal Secret và không hardcode bất kỳ secret nào.

Nếu tải lỗi:

- kiểm tra kết nối, credit/budget và trạng thái Modal;
- xác nhận model ID vẫn là `Qwen/Qwen3-14B-AWQ`;
- chạy lại chính lệnh `download_model`;
- xem log để phân biệt lỗi Hugging Face với timeout.

Không chạy inference trước khi lệnh này hoàn tất và in thông báo model đã được
lưu trong Volume.

## 4. Chạy prompt thử

```powershell
python -m modal run modal_apps/qwen14b_modal.py
```

Local entrypoint gửi prompt mẫu bằng `.remote()`, chờ GPU trả kết quả, rồi in
plain string trong terminal. Đây là ephemeral App, không tạo HTTP API và không
cần `modal deploy`.

Prompt riêng:

```powershell
python -m modal run modal_apps/qwen14b_modal.py --prompt "Analyze this Python code"
```

Bật thinking có giới hạn:

```powershell
python -m modal run modal_apps/qwen14b_modal.py --thinking --max-tokens 512 --prompt "Analyze this complex data flow"
```

`thinking=false` truyền `enable_thinking=False` qua Qwen chat template. Khi bật
thinking, ứng dụng vẫn loại bỏ block `<think>...</think>` và chỉ trả final text;
reasoning không được lưu hoặc trả về terminal. `max_tokens` luôn phải từ 1 đến
1536. Modal SDK hiện tại biểu diễn tham số `bool` mặc định `False` bằng flag
`--thinking` (không thêm giá trị `true`).

Xem các option do Modal sinh tự động:

```powershell
python -m modal run modal_apps/qwen14b_modal.py --help
```

## 5. Cấu hình qua biến môi trường PowerShell

Không cần file `.env`. Đặt biến trong session PowerShell trước khi chạy Modal:

```powershell
$env:MODAL_MODEL_ID = "Qwen/Qwen3-14B-AWQ"
$env:MODAL_GPU = "B200"
$env:MODAL_MAX_MODEL_LEN = "4096"
$env:MODAL_MAX_TOKENS = "256"
$env:MODAL_THINKING = "false"
$env:MODAL_SCALEDOWN_WINDOW = "300"
```

Các giá trị được đọc khi Modal import file. GPU chấp nhận `L4`, `L40S`, `A100`,
`H100`, `H200` hoặc `B200`; context bị giới hạn tối đa 4096 trong app độc lập này.

## 6. Hai Volume và vòng đời container

- `qwen3-14b-hf-cache` mount tại `/vol/huggingface`: chứa snapshot model. GPU
  mount Volume này read-only và chỉ load local snapshot đã hoàn chỉnh.
- `qwen3-14b-vllm-cache` mount tại `/vol/vllm`: chứa cache biên dịch của vLLM.

`download_model` dùng CPU, không yêu cầu GPU. GPU chỉ bật khi `Qwen14B.chat()`
được gọi. `@modal.enter()` load engine đúng một lần khi GPU container khởi động.
Sau khi input kết thúc, container có thể idle tối đa khoảng 300 giây trước khi
scale về 0; model weights vẫn còn trong Volume. `max_containers=1` ngăn app bật
nhiều GPU container, còn `min_containers=0` không giữ GPU chạy 24/7.

Volume vẫn phát sinh phí lưu trữ theo pricing hiện hành. GPU và CPU được tính
theo thời gian sử dụng. Theo dõi credit trên Dashboard; với Modal SDK 1.5.3 trở
lên cũng có thể xem tóm tắt tháng bằng:

```powershell
python -m modal billing summary
```

## 7. Xử lý CUDA Out Of Memory

Không chuyển GPU đắt hơn ngay. Thử theo thứ tự:

1. Giảm context 4096 xuống 2048:

   ```powershell
   $env:MODAL_MAX_MODEL_LEN = "2048"
   ```

2. Giữ nguyên `max_num_seqs=1` (đã khóa trong file).
3. Giảm output, ví dụ `--max-tokens 128`.
4. Nếu đang chủ động dùng L4 và vẫn OOM, đổi rõ ràng sang L40S rồi chạy lại:

   ```powershell
   $env:MODAL_GPU = "L40S"
   python -m modal run modal_apps/qwen14b_modal.py --max-tokens 128 --prompt "Test after OOM"
   ```

App không tự động fallback từ L4 sang L40S. Nếu lỗi không phải OOM, kiểm tra
log vLLM, snapshot Volume và phiên bản dependency trước khi đổi GPU.

## 8. Log, container và dừng app

Mở Dashboard bằng CLI:

```powershell
python -m modal dashboard
```

Trong Dashboard, chọn app `qwen3-14b-awq` để xem Functions, Containers, Logs,
GPU metrics và thời gian chạy. Với app còn xuất hiện theo tên, có thể dùng:

```powershell
python -m modal app logs qwen3-14b-awq
python -m modal app dashboard qwen3-14b-awq
```

`modal run` tạo ephemeral App và bình thường tự dừng khi lệnh local kết thúc.
Nếu một run đang treo, nhấn `Ctrl+C`, kiểm tra Apps/Containers trên Dashboard,
rồi dừng app đang chạy nếu cần:

```powershell
python -m modal app stop qwen3-14b-awq
```

Lệnh stop chấm dứt container đang chạy nhưng không xóa hai Volume. Không xóa
Volume nếu còn muốn tái sử dụng model cache.

## 9. Lỗi thường gặp

- **Modal chưa setup / AuthError:** chạy `python -m modal setup`, kiểm tra Workspace
  đang active.
- **Model chưa tải:** chạy `::download_model` và đợi thông báo commit thành
  công.
- **Hugging Face download lỗi:** kiểm tra network/Hub/model ID rồi chạy lại hàm
  CPU; model public không cần token trong điều kiện bình thường.
- **CUDA OOM:** làm đúng thứ tự tại mục 7.
- **vLLM không load model:** xác nhận image vẫn dùng `vllm==0.26.0`, snapshot đầy
  đủ, rồi xem traceback trong Modal log.
- **Timeout:** xem log để biết image build, cold start hay inference bị kẹt; kiểm
  tra credit/budget trước khi retry.
- **Prompt rỗng / max token sai:** truyền prompt có nội dung và giá trị từ 1 đến
  1536.
- **Output rỗng:** tắt thinking hoặc tăng `--max-tokens` nhưng không vượt 1536.

## Giới hạn xác minh

Cấu hình đã được kiểm tra tĩnh theo API/tài liệu Modal, Hugging Face và vLLM
hiện hành. Chưa tải model thật, chưa build image trên Modal, chưa cấp phát L4,
chưa chạy inference, và vì vậy chưa xác minh VRAM thực tế của
`Qwen/Qwen3-14B-AWQ` với context 4096 trên L4. Hai Volume cũng chỉ được tạo khi
người dùng chạy lệnh Modal lần đầu.

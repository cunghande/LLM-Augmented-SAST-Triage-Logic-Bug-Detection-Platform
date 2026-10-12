# Nhật Ký Tiến Độ Thực Hiện Dự Án (Project Progress Log)

> Ghi nhận tiến độ sau mỗi bước: Công việc đã làm, file thay đổi, kết quả kiểm thử (test pass/fail), số liệu đã đo thật, và các điểm cần lưu ý.

---

## [Bước 0] Kiểm toán Hiện trạng & Khởi tạo Khung Báo cáo (Audit & Paper Scaffold)
- **Công việc đã làm:**
  - Đọc và kiểm toán toàn bộ mã nguồn hiện tại liên quan đến các hạng mục A, B, C, D.
  - Tạo `docs/audit.md` phân loại hiện trạng từng mục (đã cài + có test, đã cài chưa test, chưa có) kèm theo dẫn chứng file:dòng cụ thể.
  - Lập danh sách các tuyên bố sai lệch trong tài liệu (AUTO_SUPPRESS_FP -> FP_CANDIDATE, GraphEvidenceExpansionAgent là workflow tất định, xóa tuyên bố token/hallucination chưa có bằng chứng).
  - Khởi tạo thư mục `docs/paper/` gồm `docs/paper/claims.md` (Sổ tuyên bố) và `docs/paper/paper.md` (Khung bài báo rút gọn 9 phần).
  - Khởi tạo nhật ký tiến độ `docs/progress.md`.
- **File tạo mới / thay đổi:**
  - `docs/audit.md`
  - `docs/paper/claims.md`
  - `docs/paper/paper.md`
  - `docs/progress.md`
- **Kết quả kiểm thử:**
  - Chạy `pytest`: 495 passed, 2 skipped (100% xanh).
- **Số liệu đã đo:** Chưa có (bước kiểm toán và lập khung).
- **Trạng thái:** Hoàn thành Bước 0. Sẵn sàng sang Bước 1 (Nhóm P0 theo thứ tự: B1, B2 -> C5, C4 -> C2, C3, C1 -> B3, B4, B5 -> D1, D2).

# Bài báo theo mẫu ACL

Mở `main.tex` làm tài liệu chính. Bài viết dùng mẫu ACL người dùng cung cấp: A4, 11 pt, hai cột, tóm tắt, tác giả, bảng/hình và tài liệu tham khảo. Nội dung được biên soạn từ dự án AI security và báo cáo của Đỗ Văn Cung; không sao chép nội dung đề tài customer churn.

## Biên dịch

Tải toàn bộ thư mục này lên Overleaf, chọn compiler **pdfLaTeX**, main document **main.tex**, rồi Recompile. Hoặc chạy trong thư mục này với bản TeX có hỗ trợ tiếng Việt T5:

```text
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

Sơ đồ được vẽ bằng TikZ, không cần ảnh ngoài. `acl.sty` và `acl_natbib.bst` được sao chép nguyên bản từ mẫu. References được nhúng trực tiếp trong `main.tex` và đánh số [1], [2], [3]; không cần chạy BibTeX. `custom.bib` được giữ làm dữ liệu tham khảo. Thông tin tác giả/lớp lấy từ báo cáo hiện có; không suy đoán mã sinh viên hoặc trường.

Tên đề tài giữ nguyên theo bản người dùng gửi: **LLM Augmented SAST**. Sau References là Lời cảm ơn, Lời tuyên bố sử dụng AI và Mục lục theo thứ tự yêu cầu. Tiêu đề tóm tắt là Abstract. Checklist đã đánh Yes ở mục 1, 2, 4 và No ở mục 3 theo xác nhận của tác giả. Tỷ lệ 70% là đề xuất ước tính sơ bộ, cần tác giả rà soát trước khi nộp. Trong mã LaTeX, đổi `\unchecked` thành `\checked` ở lựa chọn phù hợp.

## Phạm vi số liệu

- Số lượng và phân bố nhãn lấy từ `benchmarks/curated_benchmark.json`; nhãn chưa được tái thẩm định độc lập trong lần biên soạn này.
- Không dùng baseline sinh bằng hàm băm, tổng đếm gán sẵn hoặc token ước lượng trên mã tổng hợp như kết quả đo LLM thực tế.
- Phần giao thức thực nghiệm là đề xuất, không trình bày như thí nghiệm đã hoàn tất.
- Chưa biên dịch hoặc kiểm tra bố cục PDF vì môi trường hiện tại không tìm thấy trình biên dịch LaTeX. Cần kiểm tra PDF sau khi Recompile trên Overleaf.



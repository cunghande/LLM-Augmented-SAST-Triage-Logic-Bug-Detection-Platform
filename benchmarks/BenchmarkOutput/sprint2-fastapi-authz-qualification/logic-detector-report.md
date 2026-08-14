# FastAPI missing function-level authorization — qualification v2

- Dataset: 80 cases, gồm 35 natural RealVuln v2 và 45 controlled mutations.
- Balance: 40 positive / 40 negative.
- Kết quả: TP=40, FP=0, FN=0, TN=39, UNKNOWN=1.
- Precision=100%, Recall=100%, F1=100%, FPR=0%.
- Held-out: 38 cases, TP=20, FP=0, FN=0, TN=18, UNKNOWN=0.
- Ba lần chạy tạo JSON giống hệt từng byte.
- Metric gate: PASS.
- Qualification claim: PENDING vì 80/80 case chưa có audit độc lập hai reviewer.

Case UNKNOWN duy nhất là một negative IDOR control có ownership constraint mà
static analysis chưa chứng minh đủ chắc chắn. Finding không bị tự động xác nhận.

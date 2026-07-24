# S2-04 Manual Security Review Report — CN_WEB (3 Services)

**Reviewer**: Manual AppSec Review  
**Date**: 2026-07-24  
**Repository**: CN_WEB (E-commerce Web Application)  
**Scope**: 3 Service chính rủi ro cao nhất — Order Service, Coupon Service, Auth Service

---

## Tóm Tắt Kết Quả Review Thủ Công

| Finding ID | Service | Entrypoint | Bug Type | Verdict | Mức Ưu Tiên |
|---|---|---|---|:---:|:---:|
| LB-MANUAL-001 | Order Service | `GET /api/orders/:id` | IDOR | **FP** | - |
| LB-MANUAL-002 | Coupon Service | `POST /api/coupons/:id/claim` | BUSINESS_RULE_BYPASS | **NEEDS_REVIEW** | 🔶 MEDIUM |
| LB-MANUAL-003 | Auth Service | `POST /api/auth/register` | MASS_ASSIGNMENT | **FP** | - |
| **LB-MANUAL-004** | **Auth Service** | **`POST /api/auth/login`** | **INSECURE_WORKFLOW** | **TP** | 🔴 **HIGH** |

---

## Chi Tiết Root-Cause Analysis

### 1. LB-MANUAL-004 — **True Positive: Plain-Text Password Comparison**

**File**: [`backend/src/controllers/auth.controller.js`](file:///d:/Code/AI%20security/repos/CN_WEB/backend/src/controllers/auth.controller.js) (Dòng 148–151)

**Đoạn Code Nguy Hiểm**:
```javascript
const isBcryptPassword = user.password?.startsWith('$2a$') || user.password?.startsWith('$2b$');
const isMatch = isBcryptPassword
  ? await bcrypt.compare(password, user.password)
  : password === user.password;  // ← NGUY HIỂM: So sánh plain text!
```

**Root Cause**: Logic migration tạm thời cho phép so sánh mật khẩu dạng **plain text** với nhân viên hoặc user cũ được tạo trước khi hệ thống migrate sang bcrypt. Kẻ tấn công có thể đăng nhập vào tài khoản cũ này mà không cần crack bcrypt hash.

**PoC (An toàn, không tác động production)**:
```bash
# 1. Xác định user trong DB có password không có prefix $2a$/$2b$ (kiểm tra nội bộ)
SELECT id, email, LEFT(password, 4) as pwd_prefix FROM users WHERE password NOT LIKE '$2%';

# 2. Thử đăng nhập với plain text password
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@example.com", "password": "plaintext_password"}'

# 3. Kết quả: HTTP 200 OK với JWT token -> Xác nhận lỗi
```

**Remediation Ticket — SEC-TICKET-001**:
- [ ] Chạy script migrate mật khẩu plain text sang bcrypt hash cho toàn bộ user trong DB.
- [ ] Sau khi migrate xong, xóa nhánh `password === user.password` (dòng 151).
- [ ] Chỉ giữ lại `await bcrypt.compare(password, user.password)`.

---

### 2. LB-MANUAL-001 — **False Positive: IDOR (Ownership Check Tồn Tại)**

**File**: [`backend/src/controllers/order.controller.js`](file:///d:/Code/AI%20security/repos/CN_WEB/backend/src/controllers/order.controller.js) (Dòng 113)

**Đoạn Code An Toàn**:
```javascript
if (req.user.role !== 'admin' && order.user_id !== req.user.id) {
  return sendResponse(res, 403, false, 'Bạn không có quyền xem đơn hàng này');
}
```
**Nhận xét**: Đã có kiểm tra Ownership đầy đủ. CPG phát hiện luồng nghi vấn nhưng LLM Qwen 3:8b xác nhận là an toàn — đây là **False Positive** của Agent.

---

### 3. LB-MANUAL-002 — **Needs Review: Coupon Claim Logic**

**File**: [`backend/src/controllers/coupon.controller.js`](file:///d:/Code/AI%20security/repos/CN_WEB/backend/src/controllers/coupon.controller.js) (Dòng 57–63)

**Vấn đề cần xem xét thêm**: Toàn bộ logic kiểm tra claim limit nằm trong `Coupon.claim()` ở tầng Model. Cần review thêm file `backend/src/models/Coupon.model.js` để xác nhận DB query có kiểm tra điều kiện `claim_limit` và `user_coupon` history đúng cách không.

---

### 4. LB-MANUAL-003 — **False Positive: Mass Assignment (Role bị hardcode)**

**File**: [`backend/src/controllers/auth.controller.js`](file:///d:/Code/AI%20security/repos/CN_WEB/backend/src/controllers/auth.controller.js) (Dòng 106, 123)

**Đoạn Code An Toàn**:
```javascript
const { full_name, email, password } = req.body;  // Chỉ lấy 3 trường
...
await User.create({ ..., role: 'customer' });       // Role hardcoded server-side
```
**Nhận xét**: Role được gán cứng là `'customer'` phía server — không có Mass Assignment.

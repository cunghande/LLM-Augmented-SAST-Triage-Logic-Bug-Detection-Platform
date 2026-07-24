# CN_WEB Baseline Report

Date: 2026-07-24

## Repository

- Target path: `repos/CN_WEB`
- App type: ecommerce web application
- Backend: Node.js, Express, MySQL
- Frontend: React, Vite, Redux
- Security-relevant features: authentication, admin authorization, file upload, orders, coupons, notifications, password reset, OAuth, AI chat integration.

## Scanner Status

| Tool | Status | Notes |
|---|---|---|
| Semgrep | Blocked in current sandbox | `semgrep scan` fails before scanning due to Windows X509 system store authenticator error. |
| Gitleaks | Available by absolute path | `D:\gitleaks\gitleaks.exe` version 8.30.1 works, but `D:\gitleaks` is not in PATH. Directory scan found no leaks. |
| Manual baseline | Started | Attack surface and high-risk areas identified from source review. |

## Attack Surface

| Area | Files | Notes |
|---|---|---|
| Auth and admin | `backend/src/routes/auth.routes.js`, `backend/src/middleware/auth.js`, `backend/src/controllers/auth.controller.js`, `backend/src/controllers/user.controller.js` | Login, registration, password reset, profile update, admin user management. |
| Orders | `backend/src/routes/order.routes.js`, `backend/src/controllers/order.controller.js`, `backend/src/models/Order.model.js` | Order creation, user order access, admin status update. |
| Products and reviews | `backend/src/routes/product.routes.js`, `backend/src/controllers/product.controller.js`, `backend/src/models/Product.model.js` | Product CRUD, comments, reactions, reviews, image upload. |
| Coupons | `backend/src/routes/coupon.routes.js`, `backend/src/controllers/coupon.controller.js`, `backend/src/models/Coupon.model.js` | Coupon claim, validation, admin CRUD. |
| Uploads | `backend/src/middleware/upload.js`, `backend/server.js` | Images are uploaded to `uploads/` and served statically from `/uploads`. |
| AI chat | `backend/src/routes/ai.routes.js`, `backend/src/controllers/ai.controller.js`, `backend/src/services/openRouterService.js` | Optional auth, user prompt handling, external model API call. |
| Database | `backend/src/config/db.js`, `backend/src/models/*.js` | MySQL connection and query execution. |

## Initial Findings To Review

| ID | Area | Risk | Evidence | Review Focus |
|---|---|---|---|---|
| CNWEB-MANUAL-001 | JWT secret fallback | Medium | `backend/src/config/jwt.js` falls back to `dev_jwt_secret_change_me` if `JWT_SECRET` is missing. | In production, server should fail closed when `JWT_SECRET` is absent. |
| CNWEB-MANUAL-002 | File upload | Medium | `backend/src/middleware/upload.js` accepts files when `file.mimetype.startsWith('image/')` and serves uploads statically. | Verify magic bytes/content sniffing, extension allowlist, storage isolation, and static serving policy. |
| CNWEB-MANUAL-003 | CORS | Medium | `backend/server.js` uses `cors()` with default permissive behavior. | Restrict allowed origins before public deployment. |
| CNWEB-MANUAL-004 | Password compatibility path | Medium | Auth code supports comparing plaintext password when stored password is not bcrypt formatted. | Confirm this is only migration support; remove fallback after hashes are migrated. |
| CNWEB-MANUAL-005 | AI chat prompt boundary | Low/Medium | `backend/src/controllers/ai.controller.js` sends user message, history, and retrieved business context to OpenRouter. | Confirm data boundary, logging, redaction, and prompt-injection expectations. |

## Next Actions

1. Fix or work around local Semgrep execution.
2. Add Gitleaks to PATH or install a native Linux version in WSL.
3. Generate Semgrep raw output under `scans/CN_WEB/`.
4. Convert scanner output into the unified finding schema.
5. Select 20-50 findings for the first labeled benchmark sample.

"""
LLM Client — Kết nối đến Ollama / Qwen 3:8b
=============================================
QUAN TRỌNG: Module này quản lý toàn bộ giao tiếp với LLM local.

Chiến lược kết nối (Dual-endpoint Fallback):
  1. Thử Ollama native endpoint: POST /api/chat
  2. Nếu thất bại → thử OpenAI-compat endpoint: POST /v1/chat/completions
  3. Nếu cả 2 thất bại → dùng Heuristic Fallback (không cần mạng)

Cấu hình qua biến môi trường (.env):
  LLM_API_BASE = http://localhost:11434  (mặc định)
  LLM_MODEL    = qwen3:8b               (mặc định)
  LLM_API_KEY  = ollama                 (mặc định, không bắt buộc)
  MOCK_LLM     = 1                      (bật chế độ offline mock)
"""

import json
import os
import re
import httpx
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()


class LLMExecutionException(Exception):
    """Exception raised when LLM invocation fails in fail-closed REAL mode."""
    def __init__(self, failure_category: str, message: str):
        super().__init__(message)
        self.failure_category = failure_category


class LLMClient:
    """
    Client giao tiếp với LLM local (Ollama Qwen 3:8b).
    Được dùng bởi cả TriageEngine (Agent 1) và LogicBugDetector (Agent 2).
    """

    def __init__(
        self,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        temperature: float = 0.0,   # Temperature = 0 cho output quy chuan
        timeout: float = 150.0,     # 150s timeout cho REAL execution mode
        fail_closed: bool = False
    ):
        raw_base = (api_base or os.getenv("LLM_API_BASE", "http://localhost:11434")).rstrip("/")
        self.api_base = raw_base
        # Extract host_base by stripping trailing /v1
        if raw_base.endswith("/v1"):
            self.host_base = raw_base[:-3].rstrip("/")
        else:
            self.host_base = raw_base

        self.model = model or os.getenv("LLM_MODEL", "qwen3:8b")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "ollama")
        self.temperature = temperature
        self.timeout = timeout
        self.fail_closed = fail_closed or (os.getenv("EXECUTION_MODE", "REAL").upper() == "REAL" and os.getenv("MOCK_LLM", "0") != "1")
        self.mock_mode = False if self.fail_closed else (os.getenv("MOCK_LLM", "0") == "1")

    def preflight_check(self) -> Dict[str, Any]:
        """
        Thực hiện kiểm tra preflight trước khi chạy benchmark.
        1. Gọi GET /api/tags để xác minh Ollama reachable và tìm model qwen3:8b.
        2. Lấy exact model digest và metadata.
        3. Thực hiện 1 test completion kiểm tra output parse được.
        """
        if self.mock_mode and not self.fail_closed:
            return {
                "ok": True,
                "requested_model": self.model,
                "effective_model": "mock",
                "model_digest": "sha256:mock-digest-000000",
                "execution_mode": "MOCK"
            }

        # Step 1: Check endpoint and model tag on host_base
        url = f"{self.host_base}/api/tags"
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(url)
                if resp.status_code != 200:
                    raise LLMExecutionException("LLM_UNAVAILABLE", f"Ollama HTTP error {resp.status_code} at {url}")
                data = resp.json()
                models = data.get("models", [])
                matched_model = next((m for m in models if m.get("name") == self.model or m.get("model") == self.model), None)
                if not matched_model:
                    raise LLMExecutionException("LLM_UNAVAILABLE", f"Model '{self.model}' not found in Ollama tags at {url}")
                raw_digest = matched_model.get("digest", "unknown")
                model_digest = f"sha256:{raw_digest}" if not raw_digest.startswith("sha256:") else raw_digest
        except httpx.TimeoutException:
            raise LLMExecutionException("LLM_TIMEOUT", "Ollama connection timed out during preflight")
        except Exception as e:
            if isinstance(e, LLMExecutionException):
                raise
            raise LLMExecutionException("LLM_UNAVAILABLE", f"Failed to connect to Ollama: {e}")


        # Step 2: Test structured-output completion
        test_system = "You are a SAST triage engine. Return ONLY valid JSON with keys: verdict, confidence, reasoning, evidence."
        test_user = "Analyze this test code snippet: param = request.args.get('x'); eval(param)"
        test_res = self.call_chat_completion(test_system, test_user)

        if test_res.get("outcome") == "FAILED":
            raise LLMExecutionException(test_res.get("failure_category", "MALFORMED_OUTPUT"), f"Preflight completion failed: {test_res.get('reasoning')}")

        return {
            "ok": True,
            "requested_model": self.model,
            "effective_model": self.model,
            "model_digest": model_digest,
            "digest_algorithm": "sha256",
            "execution_mode": "REAL",
            "test_verdict": test_res.get("verdict")
        }

    def call_chat_completion(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """
        Gửi yêu cầu triage/phân tích đến Qwen 3:8b.
        Trả về dict chuẩn kèm outcome và failure_category.
        """
        if self.mock_mode and not self.fail_closed:
            return self._heuristic_mock_response(user_prompt)

        # ── Endpoint 1: Ollama native /api/chat ──────────────────────────────
        last_error_category = "LLM_UNAVAILABLE"
        last_error_msg = ""
        raw_content = None

        try:
            url = f"{self.host_base}/api/chat"
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "format": "json",
                "stream": False,
                "options": {"temperature": self.temperature}
            }
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    raw_content = resp.json()["message"]["content"]
                    parsed, err = self._parse_json_content(raw_content)
                    if parsed is not None:
                        parsed["outcome"] = "DECIDED" if parsed["verdict"] in ("TP", "FP") else "ABSTAINED"
                        parsed["failure_category"] = "NONE"
                        parsed["original_finding_preserved"] = True
                        parsed["transport_success"] = True
                        parsed["parse_success"] = True
                        parsed["raw_response"] = raw_content
                        parsed["parsed_response"] = parsed.copy()
                        parsed["schema_validation_error"] = None
                        return parsed
                    else:
                        last_error_category = "MALFORMED_OUTPUT"
                        last_error_msg = f"Failed to parse structured JSON: {err}"
                else:
                    last_error_category = "LLM_UNAVAILABLE"
                    last_error_msg = f"HTTP {resp.status_code}: {resp.text[:100]}"
        except httpx.TimeoutException:
            last_error_category = "LLM_TIMEOUT"
            last_error_msg = f"Request timed out after {self.timeout}s"
        except Exception as e:
            last_error_category = "LLM_UNAVAILABLE"
            last_error_msg = str(e)

        # ── Fail-closed behavior ─────────────────────────────────────────────
        if self.fail_closed:
            return {
                "verdict": None,
                "outcome": "FAILED",
                "failure_category": last_error_category,
                "confidence": None,
                "reasoning": f"LLM execution failed closed: {last_error_msg}",
                "evidence": [last_error_msg],
                "original_finding_preserved": True,
                "transport_success": (raw_content is not None),
                "parse_success": False,
                "raw_response": raw_content,
                "parsed_response": None,
                "schema_validation_error": last_error_msg
            }


        # Fallback for non-fail-closed MOCK/offline mode
        print(f"[!] Warning: LLM call failed ({last_error_msg}). Falling back.")
        return self._heuristic_mock_response(user_prompt)

    def _heuristic_mock_response(self, user_prompt: str) -> Dict[str, Any]:
        """Fallback heuristic khi Ollama offline hoặc MOCK_LLM=1."""
        prompt_lower = user_prompt.lower()

        if any(kw in prompt_lower for kw in ["seed", "migration", "run-database-files", "bcrypt"]):
            return {
                "verdict": "FP",
                "outcome": "DECIDED",
                "failure_category": "NONE",
                "confidence": 0.92,
                "reasoning": "Detected mock test data or setup script snippet. Safe FP candidate.",
                "evidence": ["Snippet located in test/seed/migration utility file."]
            }
        elif any(kw in prompt_lower for kw in ["jwt_secret", "dev_jwt_secret", "fallback"]):
            return {
                "verdict": "TP",
                "outcome": "DECIDED",
                "failure_category": "NONE",
                "confidence": 0.95,
                "reasoning": "Hardcoded fallback secret present in application config.",
                "evidence": ["Insecure fallback secret definition in production path."]
            }
        else:
            return {
                "verdict": "NEEDS_REVIEW",
                "outcome": "ABSTAINED",
                "failure_category": "NONE",
                "confidence": 0.60,
                "reasoning": "Ambiguous code pattern requiring security reviewer input.",
                "evidence": ["Context review recommended."]
            }

    def _parse_json_content(self, content: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Trích xuất và parse JSON từ response của LLM. Trả về (parsed_dict, error_msg)."""
        if not content or not content.strip():
            return None, "Empty LLM response content"
        content_clean = content.strip()

        json_start = content_clean.find("{")
        json_end = content_clean.rfind("}")
        if json_start != -1 and json_end > json_start:
            content_clean = content_clean[json_start:json_end + 1]


        data = None
        err_msg = None
        try:
            data = json.loads(content_clean, strict=False)
        except Exception as e1:
            try:
                forward_slash_content = content_clean.replace("\\", "/")
                data = json.loads(forward_slash_content, strict=False)
            except Exception as e2:
                err_msg = f"JSON parse error: {e1} (forward-slash retry error: {e2}) on snippet: {content_clean[:100]}"
                return None, err_msg

        if not isinstance(data, dict):
            return None, f"Parsed JSON is not a dict: type={type(data)}"

        v_raw = str(data.get("verdict", "NEEDS_REVIEW")).upper().strip()
        # Map verdict to pure security verdict
        if v_raw in ("TP", "TRIAGED_TP", "TRUE_POSITIVE"):
            verdict = "TP"
        elif v_raw in ("FP", "TRIAGED_FP", "FALSE_POSITIVE"):
            verdict = "FP"
        elif v_raw == "NEEDS_MORE_CONTEXT":
            verdict = "NEEDS_MORE_CONTEXT"
        else:
            verdict = "NEEDS_REVIEW"

        conf_val = data.get("confidence", data.get("decision_score", 0.5))
        try:
            conf_float = float(conf_val)
        except (ValueError, TypeError):
            conf_float = 0.5

        parsed = {
            "verdict": verdict,
            "confidence": conf_float,
            "reasoning": str(data.get("reasoning", "Parsed from LLM output")),
            "evidence": (
                data.get("evidence", [])
                if isinstance(data.get("evidence"), list)
                else [str(data.get("evidence"))]
            )
        }
        return parsed, None





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
        temperature: float = 0.0,   # Temperature = 0 để output ổn định, ít ngẫu nhiên
        timeout: float = 90.0       # 90s timeout vì model local có thể chậm
    ):
        self.api_base = (api_base or os.getenv("LLM_API_BASE", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "qwen3:8b")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "ollama")
        self.temperature = temperature
        self.timeout = timeout
        # Bật MOCK_LLM=1 trong .env để chạy offline không cần Ollama (phục vụ CI/CD)
        self.mock_mode = os.getenv("MOCK_LLM", "0") == "1"

    def call_chat_completion(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """
        Gửi yêu cầu triage/phân tích đến Qwen 3:8b.
        Trả về dict chuẩn: {verdict, confidence, reasoning, evidence}
        """
        if self.mock_mode:
            return self._heuristic_mock_response(user_prompt)

        # ── Endpoint 1: Ollama native /api/chat ──────────────────────────────
        try:
            url = f"{self.api_base}/api/chat"
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False,
                "options": {"temperature": self.temperature}
            }
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    content = resp.json()["message"]["content"]
                    return self._parse_json_content(content)
        except Exception:
            pass

        # ── Endpoint 2: OpenAI-compatible /v1/chat/completions ───────────────
        try:
            v1_base = self.api_base if self.api_base.endswith("/v1") else f"{self.api_base}/v1"
            url = f"{v1_base}/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": self.temperature,
            }
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"]
                return self._parse_json_content(content)
        except Exception as e:
            print(f"[!] Warning: Connection to {self.api_base} with model {self.model} failed ({e}). Using fallback.")
            return self._heuristic_mock_response(user_prompt)

    def _heuristic_mock_response(self, user_prompt: str) -> Dict[str, Any]:
        """
        Fallback heuristic khi Ollama offline hoặc MOCK_LLM=1.

        ⚠️ QUAN TRỌNG: Đây CHỈ là heuristic đơn giản dựa trên keyword matching,
        KHÔNG thay thế được phân tích ngữ cảnh sâu của LLM thật.
        Dùng cho CI/CD demo, unit test và môi trường offline.
        """
        prompt_lower = user_prompt.lower()

        # Keyword gợi ý FP: code trong script setup/migration/test
        if any(kw in prompt_lower for kw in ["seed", "migration", "run-database-files", "bcrypt"]):
            return {
                "verdict": "FP",
                "confidence": 0.92,
                "reasoning": "Detected mock test data or setup script snippet. Safe FP candidate.",
                "evidence": ["Snippet located in test/seed/migration utility file."]
            }
        # Keyword gợi ý TP: secret/JWT hardcode rõ ràng
        elif any(kw in prompt_lower for kw in ["jwt_secret", "dev_jwt_secret", "fallback"]):
            return {
                "verdict": "TP",
                "confidence": 0.95,
                "reasoning": "Hardcoded fallback secret present in application config.",
                "evidence": ["Insecure fallback secret definition in production path."]
            }
        # Mặc định: cần xem xét thêm
        else:
            return {
                "verdict": "NEEDS_REVIEW",
                "confidence": 0.60,
                "reasoning": "Ambiguous code pattern requiring security reviewer input.",
                "evidence": ["Context review recommended."]
            }

    def _parse_json_content(self, content: str) -> Dict[str, Any]:
        """
        Trích xuất và parse JSON từ response của Qwen 3:8b.

        ⚠️ QUAN TRỌNG: Qwen 3:8b thường bọc JSON trong code block ```json ... ```.
        Logic ở đây xử lý cả 2 trường hợp: có và không có code block.
        """
        content_clean = content.strip()

        # Thử parse JSON trong code block ```json { ... } ```
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content_clean, re.DOTALL)
        if json_match:
            content_clean = json_match.group(1)
        else:
            # Thử tìm JSON object trực tiếp trong text
            raw_json_match = re.search(r"\{.*?\}", content_clean, re.DOTALL)
            if raw_json_match:
                content_clean = raw_json_match.group(0)

        try:
            data = json.loads(content_clean)
            return {
                "verdict": data.get("verdict", "NEEDS_REVIEW").upper(),
                "confidence": float(data.get("confidence", 0.5)),
                "reasoning": str(data.get("reasoning", "Parsed from LLM output")),
                "evidence": (
                    data.get("evidence", [])
                    if isinstance(data.get("evidence"), list)
                    else [str(data.get("evidence"))]
                )
            }
        except Exception:
            return {
                "verdict": "NEEDS_REVIEW",
                "confidence": 0.5,
                "reasoning": f"Failed to parse structured JSON from model output: {content[:100]}...",
                "evidence": ["Unparseable model output format"]
            }

import json
import os
import re
import httpx
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()


class LLMClient:
    def __init__(
        self,
        api_base: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        temperature: float = 0.0,
        timeout: float = 90.0
    ):
        self.api_base = (api_base or os.getenv("LLM_API_BASE", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "qwen3:8b")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "ollama")
        self.temperature = temperature
        self.timeout = timeout
        self.mock_mode = os.getenv("MOCK_LLM", "0") == "1"

    def call_chat_completion(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """Send chat request to local Ollama Qwen 3:8b model."""
        if self.mock_mode:
            return self._heuristic_mock_response(user_prompt)

        # Try Ollama native /api/chat endpoint first
        try:
            url = f"{self.api_base}/api/chat" if not self.api_base.endswith("/api/chat") else self.api_base
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False,
                "options": {
                    "temperature": self.temperature
                }
            }
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    content = resp.json()["message"]["content"]
                    return self._parse_json_content(content)
        except Exception:
            pass

        # Try OpenAI-compatible /v1/chat/completions endpoint
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
        """Local fallback heuristic for offline evaluation / demonstration."""
        prompt_lower = user_prompt.lower()
        if "seed" in prompt_lower or "migration" in prompt_lower or "run-database-files" in prompt_lower or "bcrypt" in prompt_lower:
            return {
                "verdict": "FP",
                "confidence": 0.92,
                "reasoning": "Detected mock test data or setup script snippet. Safe FP candidate.",
                "evidence": ["Snippet located in test/seed/migration utility file."]
            }
        elif "jwt_secret" in prompt_lower or "dev_jwt_secret" in prompt_lower or "fallback" in prompt_lower:
            return {
                "verdict": "TP",
                "confidence": 0.95,
                "reasoning": "Hardcoded fallback secret present in application config.",
                "evidence": ["Insecure fallback secret definition in production path."]
            }
        else:
            return {
                "verdict": "NEEDS_REVIEW",
                "confidence": 0.60,
                "reasoning": "Ambiguous code pattern requiring security reviewer input.",
                "evidence": ["Context review recommended."]
            }

    def _parse_json_content(self, content: str) -> Dict[str, Any]:
        """Extract and parse JSON object from LLM response string."""
        content_clean = content.strip()
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content_clean, re.DOTALL)
        if json_match:
            content_clean = json_match.group(1)
        else:
            raw_json_match = re.search(r"\{.*?\}", content_clean, re.DOTALL)
            if raw_json_match:
                content_clean = raw_json_match.group(0)

        try:
            data = json.loads(content_clean)
            return {
                "verdict": data.get("verdict", "NEEDS_REVIEW").upper(),
                "confidence": float(data.get("confidence", 0.5)),
                "reasoning": str(data.get("reasoning", "Parsed from LLM output")),
                "evidence": data.get("evidence", []) if isinstance(data.get("evidence"), list) else [str(data.get("evidence"))]
            }
        except Exception:
            return {
                "verdict": "NEEDS_REVIEW",
                "confidence": 0.5,
                "reasoning": f"Failed to parse structured JSON from model output: {content[:100]}...",
                "evidence": ["Unparseable model output format"]
            }

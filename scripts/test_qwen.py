import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.triage.llm_client import LLMClient
from src.triage.prompts import SYSTEM_TRIAGE_PROMPT

client = LLMClient(timeout=30.0)
print(f"[*] Connecting to {client.api_base} with model {client.model}...")

user_prompt = """Target Repository: CN_WEB
File: backend/src/config/jwt.js (Line 15)
Scanner: gitleaks
Rule ID: jwt-secret
Severity: HIGH

Raw Match/Snippet:
```
const secret = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
```
Analyze this finding and output the classification JSON.
"""

res = client.call_chat_completion(SYSTEM_TRIAGE_PROMPT, user_prompt)
print("\n[OK] Live Qwen 3:8b Response:")
print(json.dumps(res, indent=2))

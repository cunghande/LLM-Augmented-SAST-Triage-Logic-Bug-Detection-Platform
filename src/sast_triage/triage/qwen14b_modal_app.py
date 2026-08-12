"""Chạy Qwen3-14B-AWQ như ứng dụng Modal độc lập, tự co về không tài nguyên."""

from __future__ import annotations

import json
import os

import modal

APP_NAME = "qwen3-14b-awq"
MODEL_ID = os.getenv("MODAL_MODEL_ID", "Qwen/Qwen3-14B-AWQ")
GPU = os.getenv("MODAL_GPU", "B200").upper()
MAX_MODEL_LEN = int(os.getenv("MODAL_MAX_MODEL_LEN", "4096"))
DEFAULT_MAX_TOKENS = int(os.getenv("MODAL_MAX_TOKENS", "256"))
SCALEDOWN_WINDOW = int(os.getenv("MODAL_SCALEDOWN_WINDOW", "300"))
DEFAULT_THINKING = os.getenv("MODAL_THINKING", "false").strip().lower() in {
    "1",
    "true",
    "yes",
}

HF_CACHE_ROOT = "/vol/huggingface"
HF_HUB_CACHE = f"{HF_CACHE_ROOT}/hub"
VLLM_CACHE_ROOT = "/vol/vllm"

VLLM_VERSION = "0.26.0"
HUGGINGFACE_HUB_VERSION = "1.24.0"


def _validate_configuration() -> None:
    """Dừng sớm khi giá trị cấu hình cục bộ không an toàn hoặc không được hỗ trợ."""
    if GPU not in {"L4", "L40S", "A100", "H100", "H200", "B200"}:
        raise ValueError(
            "MODAL_GPU must be L4, L40S, A100, H100, H200, or B200; "
            "the default is B200."
        )
    if not 1 <= MAX_MODEL_LEN <= 4096:
        raise ValueError("MODAL_MAX_MODEL_LEN must be between 1 and 4096.")
    if not 1 <= DEFAULT_MAX_TOKENS <= 1536:
        raise ValueError("MODAL_MAX_TOKENS must be between 1 and 1536.")
    if SCALEDOWN_WINDOW < 0:
        raise ValueError("MODAL_SCALEDOWN_WINDOW must be zero or greater.")


_validate_configuration()

app = modal.App(APP_NAME)

hf_cache_volume = modal.Volume.from_name(
    "qwen3-14b-hf-cache",
    create_if_missing=True,
)
vllm_cache_volume = modal.Volume.from_name(
    "qwen3-14b-vllm-cache",
    create_if_missing=True,
)

download_image = (
    modal.Image.debian_slim(python_version="3.12")
    .uv_pip_install(f"huggingface-hub=={HUGGINGFACE_HUB_VERSION}")
    .env(
        {
            "HF_HOME": HF_CACHE_ROOT,
            "HF_HUB_CACHE": HF_HUB_CACHE,
            "HF_XET_HIGH_PERFORMANCE": "1",
        }
    )
)

vllm_image = (
    modal.Image.from_registry(
        "nvidia/cuda:12.9.0-devel-ubuntu22.04",
        add_python="3.12",
    )
    .entrypoint([])
    .uv_pip_install(
        f"vllm=={VLLM_VERSION}",
        f"huggingface-hub=={HUGGINGFACE_HUB_VERSION}",
    )
    .env(
        {
            "HF_HOME": HF_CACHE_ROOT,
            "HF_HUB_CACHE": HF_HUB_CACHE,
            "HF_XET_HIGH_PERFORMANCE": "1",
            "VLLM_CACHE_ROOT": VLLM_CACHE_ROOT,
        }
    )
)


@app.function(
    image=download_image,
    volumes={HF_CACHE_ROOT: hf_cache_volume},
    timeout=7_200,
    max_containers=1,
)
def download_model() -> str:
    """Tải model trên CPU và lưu bền trong Hugging Face Volume."""
    from huggingface_hub import snapshot_download
    from huggingface_hub.errors import (
        HfHubHTTPError,
        IncompleteSnapshotError,
        LocalEntryNotFoundError,
    )

    try:
        try:
            snapshot_path = snapshot_download(
                repo_id=MODEL_ID,
                cache_dir=HF_HUB_CACHE,
                local_files_only=True,
            )
        except (IncompleteSnapshotError, LocalEntryNotFoundError, OSError, ValueError):
            snapshot_path = snapshot_download(
                repo_id=MODEL_ID,
                cache_dir=HF_HUB_CACHE,
            )
        hf_cache_volume.commit()
    except (HfHubHTTPError, IncompleteSnapshotError, OSError, ValueError) as exc:
        raise RuntimeError(
            "Hugging Face download failed. Check network access and the model ID, "
            "then run download_model again. This public Qwen model does not "
            "normally require HF_TOKEN."
        ) from exc

    message = (
        f"Model {MODEL_ID} is stored in Modal Volume 'qwen3-14b-hf-cache' "
        f"(snapshot: {snapshot_path}). No model weights were downloaded to the laptop."
    )
    print(message)
    return message


@app.cls(
    image=vllm_image,
    gpu=GPU,
    volumes={
        HF_CACHE_ROOT: hf_cache_volume.with_mount_options(read_only=True),
        VLLM_CACHE_ROOT: vllm_cache_volume,
    },
    timeout=1_200,
    max_containers=1,
    min_containers=0,
    scaledown_window=SCALEDOWN_WINDOW,
)
@modal.concurrent(max_inputs=1)
class Qwen14B:
    """Tải một engine vLLM Qwen3-14B-AWQ cho mỗi GPU container."""

    @modal.enter()
    def load_model(self) -> None:
        """Lấy snapshot đã cache và chỉ khởi tạo vLLM một lần khi container khởi động."""
        import torch
        from huggingface_hub import snapshot_download
        from huggingface_hub.errors import IncompleteSnapshotError
        from vllm import LLM

        try:
            model_path = snapshot_download(
                repo_id=MODEL_ID,
                cache_dir=HF_HUB_CACHE,
                local_files_only=True,
            )
        except (IncompleteSnapshotError, OSError, ValueError) as exc:
            raise RuntimeError(
                "The model snapshot is missing or incomplete in the Modal Volume. "
                "Run download_model before starting inference."
            ) from exc

        try:
            self.llm = LLM(
                model=model_path,
                quantization="awq",
                dtype="auto",
                trust_remote_code=False,
                tensor_parallel_size=1,
                max_model_len=MAX_MODEL_LEN,
                max_num_seqs=1,
                enable_prefix_caching=True,
                gpu_memory_utilization=0.90,
            )
            vllm_cache_volume.commit()
        except torch.cuda.OutOfMemoryError as exc:
            raise RuntimeError(_oom_guidance()) from exc
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            if "out of memory" in str(exc).lower():
                raise RuntimeError(_oom_guidance()) from exc
            raise RuntimeError(
                f"vLLM {VLLM_VERSION} could not load {MODEL_ID}. Confirm the "
                "cached snapshot is complete and check vLLM/model compatibility."
            ) from exc

    @modal.method()
    def chat(
        self,
        messages: list[dict[str, str]],
        thinking: bool = False,
        max_tokens: int = 256,
        json_schema: dict[str, object] | None = None,
        temperature: float = 0.1,
        seed: int | None = None,
    ) -> str:
        """Sinh một câu trả lời cuối, có thể bị ràng buộc bởi JSON schema."""
        from vllm import SamplingParams
        from vllm.sampling_params import StructuredOutputsParams

        _validate_messages(messages)
        if not 1 <= max_tokens <= 1536:
            raise ValueError("max_tokens must be between 1 and 1536.")
        if not 0 <= temperature <= 2:
            raise ValueError("temperature must be between 0 and 2.")
        _validate_json_schema(json_schema)

        sampling_params = SamplingParams(
            max_tokens=max_tokens,
            temperature=temperature,
            seed=seed,
            structured_outputs=(
                StructuredOutputsParams(json=json_schema)
                if json_schema is not None
                else None
            ),
        )
        try:
            request_outputs = self.llm.chat(
                messages,
                sampling_params=sampling_params,
                use_tqdm=False,
                chat_template_kwargs={"enable_thinking": thinking},
            )
        except (RuntimeError, ValueError) as exc:
            if "out of memory" in str(exc).lower():
                raise RuntimeError(_oom_guidance()) from exc
            raise RuntimeError(
                "vLLM inference failed. Check the Modal logs, model compatibility, "
                "and available Modal credit."
            ) from exc

        if not request_outputs or not request_outputs[0].outputs:
            raise RuntimeError(
                "vLLM returned no output. Retry with a non-empty prompt."
            )

        final_text = _final_answer_only(request_outputs[0].outputs[0].text)
        if not final_text:
            raise RuntimeError(
                "The model returned no final answer. Increase max_tokens (up to 1536) "
                "or disable thinking."
            )
        return final_text


def _validate_messages(messages: list[dict[str, str]]) -> None:
    """Validate schema chat nhỏ chỉ chứa văn bản mà ứng dụng này chấp nhận."""
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty list.")

    allowed_roles = {"system", "user", "assistant"}
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise TypeError(f"messages[{index}] must be a dictionary.")
        role = message.get("role")
        content = message.get("content")
        if role not in allowed_roles:
            raise ValueError(
                f"messages[{index}].role must be system, user, or assistant."
            )
        if not isinstance(content, str) or not content.strip():
            raise ValueError(f"messages[{index}].content must be non-empty text.")


def _validate_json_schema(json_schema: dict[str, object] | None) -> None:
    """Chỉ chấp nhận JSON schema có giới hạn, với gốc là object cho output ràng buộc."""
    if json_schema is None:
        return
    if not isinstance(json_schema, dict):
        raise TypeError("json_schema must be a dictionary or None.")
    if json_schema.get("type") != "object":
        raise ValueError("json_schema must describe a top-level JSON object.")
    if not isinstance(json_schema.get("properties"), dict):
        raise TypeError("json_schema.properties must be a dictionary.")
    try:
        encoded_schema = json.dumps(json_schema, ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("json_schema must contain only JSON-serializable values.") from exc
    if len(encoded_schema) > 32_000:
        raise ValueError("json_schema must not exceed 32,000 serialized characters.")


def _final_answer_only(generated_text: str) -> str:
    """Loại bỏ khối suy luận của Qwen và chỉ trả về văn bản cuối cho người dùng."""
    text = generated_text.strip()
    if "</think>" in text:
        text = text.rsplit("</think>", maxsplit=1)[1].strip()
    elif "<think>" in text:
        return ""
    return text


def _oom_guidance() -> str:
    """Trả về thứ tự khôi phục CUDA OOM đã quy định, ưu tiên tiết kiệm chi phí."""
    return (
        "CUDA out of memory. Set MODAL_MAX_MODEL_LEN=2048, keep max_num_seqs=1, "
        "and reduce max_tokens first. If L4 still fails, explicitly set "
        "MODAL_GPU=L40S; this app never upgrades the GPU automatically."
    )


def _run_remote_chat(prompt: str, thinking: bool, max_tokens: int) -> str:
    """Gọi lớp GPU và chuyển các lỗi Modal cục bộ thường gặp thành thông báo phù hợp."""
    if not prompt.strip():
        raise ValueError("Prompt must not be empty.")
    if not 1 <= max_tokens <= 1536:
        raise ValueError("--max-tokens must be between 1 and 1536.")

    messages: list[dict[str, str]] = [{"role": "user", "content": prompt.strip()}]
    try:
        return Qwen14B().chat.remote(
            messages=messages,
            thinking=thinking,
            max_tokens=max_tokens,
        )
    except modal.exception.AuthError as exc:
        raise RuntimeError(
            "Modal is not configured. Run 'py -m modal setup' and try again."
        ) from exc
    except modal.exception.TimeoutError as exc:
        raise RuntimeError(
            "The Modal request timed out. Check the app logs and Modal credit, "
            "then retry."
        ) from exc
    except modal.exception.ResourceExhaustedError as exc:
        raise RuntimeError(
            "Modal capacity or credit is exhausted. Check the Modal Dashboard and "
            "Workspace budget before retrying."
        ) from exc


@app.local_entrypoint()
def main(
    prompt: str = "Explain why the sky appears blue in two short sentences.",
    thinking: bool = DEFAULT_THINKING,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> None:
    """Gửi một prompt đến Modal và in câu trả lời cuối ở máy cục bộ."""
    answer = _run_remote_chat(prompt, thinking, max_tokens)
    print(answer)

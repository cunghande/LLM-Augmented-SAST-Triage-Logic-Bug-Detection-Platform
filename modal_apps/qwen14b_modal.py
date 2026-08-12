"""Compatibility entrypoint for the packaged Qwen3-14B Modal application."""

from sast_triage.triage.qwen14b_modal_app import (
    APP_NAME,
    DEFAULT_MAX_TOKENS,
    DEFAULT_THINKING,
    GPU,
    MODEL_ID,
    Qwen14B,
    app,
    download_model,
    main,
)

__all__ = [
    "APP_NAME",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_THINKING",
    "GPU",
    "MODEL_ID",
    "Qwen14B",
    "app",
    "download_model",
    "main",
]

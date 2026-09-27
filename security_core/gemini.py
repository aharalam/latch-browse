"""Isolated Gemini access for the security core.

Security models here are NOT agents: no tools, no function calling, no
credentials in prompts. Every call is a single structured-JSON inference with a
timeout and a bounded retry. Errors raise GuardModelError so callers can fail
closed.
"""

from __future__ import annotations

import json
import os
from typing import Any


class GuardModelError(RuntimeError):
    """Raised when the security model is unavailable or returns bad output."""


def guard_model_name() -> str:
    return os.environ.get("GUARD_MODEL", "").strip() or "gemini/gemini-2.5-flash"


def gemini_available() -> bool:
    """True when a Gemini key is configured. Without it the core runs in
    DEGRADED heuristic mode and says so in every trace."""
    return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))


def call_json(system: str, user: str, timeout_s: float = 25.0) -> dict[str, Any]:
    """One structured inference. No tools are ever passed."""
    if not gemini_available():
        raise GuardModelError("GEMINI_API_KEY not configured")
    try:
        import litellm  # imported lazily so unit tests run without it
    except Exception as exc:  # pragma: no cover
        raise GuardModelError(f"litellm unavailable: {exc}") from exc

    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    last_err: Exception | None = None
    for _attempt in range(2):  # bounded retry
        from .budget import consume_attempt
        consume_attempt()
        try:
            resp = litellm.completion(
                model=guard_model_name(),
                api_key=key,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                temperature=0,
                timeout=timeout_s,
                num_retries=0,
                max_tokens=2048,
            )
            text = resp["choices"][0]["message"]["content"] or ""
            text = text.strip()
            if text.startswith("```"):
                text = text.strip("`")
                if text.lower().startswith("json"):
                    text = text[4:]
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("model output is not a JSON object")
            return data
        except Exception as exc:  # retry once, then fail closed upstream
            last_err = exc
    raise GuardModelError(f"security model call failed: {str(last_err)[:200]}")

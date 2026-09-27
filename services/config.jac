"""Runtime configuration read from environment variables with safe defaults."""

import os;
import from dotenv { load_dotenv }

# `jac start` does not read .env itself. Load the project's .env once, before
# any key lookup; variables already set in the real environment win.
with entry {
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"), override=False);
    # An empty LLM_MODEL (e.g. added blank in a hosting dashboard) would make
    # byLLM fall back to an unintended model; treat empty as unset.
    if not os.environ.get("LLM_MODEL", "").strip() {
        os.environ["LLM_MODEL"] = "openai/gpt-4o-mini";
    }
}

obj Budgets {
    has rate_limit_enabled: bool = True,
        rate_limit_requests: int = 20,
        rate_limit_window_seconds: int = 3600,
        trusted_proxy_hops: int = 1,
        max_searches: int = 3,
        max_pages: int = 4,
        max_agent_steps: int = 8,
        max_model_calls: int = 14,
        search_provider: str = "wikipedia",
        guard_url: str = "",
        data_dir: str = ".latch_data";
}

def _env_int(name: str, fallback: int) -> int {
    raw = os.environ.get(name, "");
    try {
        return max(1, int(raw)) if raw else fallback;
    } except ValueError {
        return fallback;
    }
}

def get_budgets() -> Budgets {
    return Budgets(
        rate_limit_enabled=os.environ.get("RATE_LIMIT_ENABLED", "true").lower() != "false",
        rate_limit_requests=_env_int("RATE_LIMIT_REQUESTS", 20),
        rate_limit_window_seconds=_env_int("RATE_LIMIT_WINDOW_SECONDS", 3600),
        trusted_proxy_hops=_env_int("TRUSTED_PROXY_HOPS", 1),
        max_searches=_env_int("MAX_SEARCHES_PER_SESSION", 3),
        max_pages=_env_int("MAX_PAGES_PER_SESSION", 4),
        max_agent_steps=_env_int("MAX_AGENT_STEPS", 8),
        max_model_calls=_env_int("MAX_MODEL_CALLS_PER_SESSION", _env_int("MAX_GEMINI_CALLS_PER_SESSION", 14)),
        search_provider=os.environ.get("SEARCH_PROVIDER", "wikipedia").lower(),
        guard_url=os.environ.get("GUARD_URL", ""),
        data_dir=os.environ.get("LATCH_DATA_DIR", ".latch_data")
    );
}

def model_configured() -> bool {
    return bool(os.environ.get("OPENAI_API_KEY", ""));
}

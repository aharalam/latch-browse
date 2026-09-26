"""Runtime configuration read from environment variables with safe defaults."""

import os;

obj Budgets {
    has rate_limit_enabled: bool = True,
        rate_limit_requests: int = 20,
        rate_limit_window_seconds: int = 3600,
        trusted_proxy_hops: int = 1,
        max_searches: int = 3,
        max_pages: int = 4,
        max_agent_steps: int = 8,
        max_gemini_calls: int = 14,
        search_provider: str = "duckduckgo",
        guard_url: str = "",
        data_dir: str = ".latch_data";
}

def _env_int(name: str, fallback: int) -> int {
    raw = os.environ.get(name, "");
    try {
        return int(raw) if raw else fallback;
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
        max_gemini_calls=_env_int("MAX_GEMINI_CALLS_PER_SESSION", 14),
        search_provider=os.environ.get("SEARCH_PROVIDER", "duckduckgo").lower(),
        guard_url=os.environ.get("GUARD_URL", ""),
        data_dir=os.environ.get("LATCH_DATA_DIR", ".latch_data")
    );
}

def gemini_configured() -> bool {
    return bool(os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", ""));
}

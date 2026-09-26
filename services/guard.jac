"""Client for the Python Security Core.

GUARD_URL set   -> call the separately deployed Cloud Run guard over HTTPS with
                   a Google identity token (service-to-service IAM) and an
                   optional shared secret.
GUARD_URL empty -> call the same core in-process (local dev / preview).

Any failure returns a fail-closed BLOCK result - never raw content.
"""

import os;
import httpx;
import security_core;
import from services.config { get_budgets }
import from services.models { IntentContract }

def _intent_dict(intent: IntentContract) -> dict {
    return {"goal": intent.goal, "allowed": intent.allowed, "forbidden": intent.forbidden};
}

def _id_token(audience: str) -> str {
    try {
        r = httpx.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
            params={"audience": audience},
            headers={"Metadata-Flavor": "Google"},
            timeout=3.0
        );
        return r.text if r.status_code == 200 else "";
    } except Exception {
        return "";
    }
}

def _remote(path: str, body: dict) -> dict {
    base = get_budgets().guard_url.rstrip("/");
    headers: dict = {"Content-Type": "application/json"};
    tok = _id_token(base);
    if tok {
        headers["Authorization"] = "Bearer " + tok;
    }
    secret = os.environ.get("GUARD_SHARED_SECRET", "");
    if secret {
        headers["X-Guard-Secret"] = secret;
    }
    r = httpx.post(base + path, json=body, headers=headers, timeout=60.0);
    r.raise_for_status();
    return r.json();
}

def _closed(url: str, reason: str) -> dict {
    return {
        "artifact": {"artifact_id": "", "source": url, "provenance": "UNTRUSTED_WEB", "decision": "BLOCK",
                     "sanitized_content": "", "structured_data": [], "capabilities": {"allowed": [], "forbidden": []}, "links": []},
        "finding": None,
        "view": [],
        "trace": {"L1": "NOT RUN", "L2": "GUARD UNAVAILABLE", "L3": "NO CAPABILITIES", "L4": "NOT RUN",
                  "decision": "BLOCKED", "released": False, "engine": "unavailable", "threat": "UNKNOWN",
                  "categories": [], "confidence": 0.0, "note": "GUARD UNAVAILABLE - CONTENT NOT RELEASED (" + reason[:120] + ")"}
    };
}

"""Raw page -> guard. The ONLY entry point for page content."""
def guard_page(raw: str, url: str, intent: IntentContract) -> dict {
    try {
        if get_budgets().guard_url {
            return _remote("/v1/page", {"url": url, "raw": raw, "is_html": True, "intent": _intent_dict(intent)});
        }
        return security_core.process_page(raw, url, _intent_dict(intent));
    } except Exception as e {
        return _closed(url, str(e));
    }
}

"""Raw search results -> guard. Titles, snippets and URLs are untrusted."""
def guard_search(results: list[dict], intent: IntentContract) -> dict {
    try {
        if get_budgets().guard_url {
            return _remote("/v1/search", {"results": results, "intent": _intent_dict(intent)});
        }
        return security_core.process_search_results(results, _intent_dict(intent));
    } except Exception as e {
        return {"safe_results": [], "findings": [], "error": "GUARD UNAVAILABLE: " + str(e)[:120], "trace": {"L2": "GUARD UNAVAILABLE"}};
    }
}

def guard_mode() -> str {
    try {
        return str(security_core.guard_status().get("mode", "unknown"));
    } except Exception {
        return "unavailable";
    }
}

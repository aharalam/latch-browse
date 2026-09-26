"""Capability enforcement + final validation (Jac owns enforcement).

The security core only ASSIGNS capability metadata. Every privileged step the
orchestrator takes goes through f"authorize", which combines the immutable
IntentContract, the requested action, the provenance of the data influencing
it, and the artifact's capability metadata.
"""

import re;
import hashlib;
import json;
import from services.models { IntentContract, ValidationReport }

# Tool registry: the only actions that exist. Anything else is denied.
glob TOOL_CAPABILITY: dict[str, str] = {
    "search_web": "SEARCH_WEB",
    "retrieve_page": "READ_WEB",
    "follow_link": "FOLLOW_LINK",
    "summarize": "SUMMARIZE",
    "display": "DISPLAY"
};

def intent_fingerprint(intent: IntentContract) -> str {
    payload = json.dumps({"g": intent.goal, "a": intent.allowed, "f": intent.forbidden}, sort_keys=True);
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16];
}

def make_intent(goal: str, created_at: float) -> IntentContract {
    intent = IntentContract(goal=goal.strip()[:600], created_at=created_at);
    intent.fingerprint = intent_fingerprint(intent);
    return intent;
}

def intent_intact(intent: IntentContract) -> bool {
    return intent.fingerprint == intent_fingerprint(intent);
}

"""Decide whether an action may run. Returns (allowed, reason)."""
def authorize(
    intent: IntentContract, action: str, provenance: str, artifact_caps: dict | None
) -> tuple[bool, str] {
    if not intent_intact(intent) {
        return (False, "IntentContract fingerprint mismatch");
    }
    cap = TOOL_CAPABILITY.get(action, "");
    if not cap {
        return (False, f"'{action}' is not a registered tool");
    }
    if cap in intent.forbidden or cap not in intent.allowed {
        return (False, f"{cap} not authorized by IntentContract");
    }
    if provenance == "UNTRUSTED_WEB" {
        caps: dict = artifact_caps or {};
        if cap in caps.get("forbidden", []) {
            return (False, f"{cap} forbidden for web-derived data");
        }
        if action in ["follow_link", "summarize", "display"] and cap not in caps.get("allowed", []) {
            return (False, f"artifact does not grant {cap}");
        }
    }
    return (True, "ok");
}

"""Map an arbitrary requested action (e.g. from the unprotected simulator)
to a verdict, never executing it."""
def intercept_action(intent: IntentContract, requested: str) -> str {
    name = requested.strip().lower().replace(" ", "_")[:60];
    (ok, reason) = authorize(intent, name, "UNTRUSTED_WEB", {"allowed": [], "forbidden": []});
    return f"{requested[:80]} -> {'ALLOWED' if ok else 'DENIED'} ({reason})";
}

glob _SECRET_RX: any = re.compile(
    r"(AIza[0-9A-Za-z_\-]{20,}|sk-[A-Za-z0-9]{20,}|CANARY-[A-F0-9]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY|GEMINI_API_KEY\s*=|ghp_[A-Za-z0-9]{20,})"
);
glob _META_RX: any = re.compile(
    r"(?i)(UNTRUSTED_WEB_DATA|SecurityFinding|fnd_[0-9a-f]{6,}|suspicious_spans|guard_decision|critic_decision|Layer [24] )"
);

def _shingles(text: str, n: int = 7) -> set[str] {
    words = re.findall(r"[a-z0-9]+", text.lower());
    return {" ".join(words[i:i + n]) for i in range(max(0, len(words) - n + 1))};
}

"""Deterministic final validator. Every check is an explicit invariant."""
def validate_answer(
    intent: IntentContract,
    answer: str,
    cited: list[str],
    consumed: list[dict],
    quarantined_texts: list[str],
    action_log: list[str]
) -> ValidationReport {
    checks: list[dict] = [];
    def add(name: str, ok: bool, detail: str) {
        checks.append({"name": name, "passed": ok, "detail": detail});
    }
    add("Answer present", len(answer.strip()) > 20, f"{len(answer)} chars");
    add("IntentContract unchanged", intent_intact(intent), intent.fingerprint);

    released = {str(a.get("source", "")) for a in consumed};
    bad_cites = [c for c in cited if c and c not in released];
    answer_urls = [u.rstrip(".,;:!?)\"]}") for u in re.findall(r"https?://[^\s<>]+", answer)];
    bad_urls = [u for u in answer_urls if u not in released];
    add("Only approved SafeArtifacts cited", len(cited) > 0 and len(bad_cites) == 0 and len(bad_urls) == 0, f"{len(bad_cites) + len(bad_urls)} unapproved citation(s)");

    prov_ok = all(
        a.get("provenance") == "UNTRUSTED_WEB" and a.get("decision") in ["PASS", "SANITIZE"]
        and "SUMMARIZE" in (a.get("capabilities", {}) or {}).get("allowed", [])
        for a in consumed
    );
    add("Provenance + SUMMARIZE capability honored", bool(consumed) and prov_ok, f"{len(consumed)} artifact(s) consumed");

    ans_sh = _shingles(answer);
    leaked = 0;
    for q in quarantined_texts {
        if len(ans_sh & _shingles(q)) > 0 {
            leaked += 1;
        }
    }
    add("Quarantined content absent", leaked == 0, f"{leaked} quarantined span(s) echoed");
    add("No secrets in output", not _SECRET_RX.search(answer), "secret/canary pattern scan");
    add("No security metadata leaked", not _META_RX.search(answer), "finding/guard metadata scan");

    illegal = [a for a in action_log if a.split(":")[0] not in TOOL_CAPABILITY];
    add("No forbidden actions performed", len(illegal) == 0, f"{len(action_log)} action(s) logged");

    goal_words = {w for w in re.findall(r"[a-z]{4,}", intent.goal.lower())};
    ans_words = set(re.findall(r"[a-z]{4,}", answer.lower()));
    add("Consistent with original task", len(goal_words) == 0 or len(goal_words & ans_words) > 0, "topic overlap");

    return ValidationReport(passed=all(c["passed"] for c in checks), checks=checks);
}

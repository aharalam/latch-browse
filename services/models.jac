"""Typed boundary objects shared by the orchestrator, the UI and the IT console.

Note the deliberate split:
  * SessionView    - what the research user sees (includes their own task).
  * FindingView    - what the IT console sees. It has NO task/prompt field.
"""

obj IntentContract {
    has goal: str,
        allowed: list[str] = ["SEARCH_WEB", "READ_WEB", "FOLLOW_LINK", "SUMMARIZE", "DISPLAY"],
        forbidden: list[str] = ["SEND_DATA", "SEND_EMAIL", "PAYMENT", "CODE_EXECUTION", "CREDENTIAL_ACCESS", "TOOL_CALL", "MODIFY_INTENT"],
        created_at: float = 0.0,
        fingerprint: str = "";
}

obj TimelineEvent {
    has seq: int,
        kind: str,
        label: str,
        detail: str = "",
        ts: float = 0.0,
        ref: str = "";
}

obj SegmentView {
    has sid: str,
        channel: str,
        text: str,
        quarantined: bool = False;
}

obj GuardTrace {
    has l1: str = "",
        l2: str = "",
        l3: str = "",
        l4: str = "",
        decision: str = "",
        released: bool = False,
        engine: str = "",
        threat: str = "",
        categories: list[str] = [],
        confidence: float = 0.0,
        note: str = "";
}

obj PageInspection {
    has ref: str,
        url: str,
        trace: GuardTrace,
        segments: list[SegmentView] = [],
        facts: list[dict] = [],
        finding_id: str = "";
}

obj ValidationReport {
    has passed: bool = False,
        checks: list[dict] = [];
}

obj SessionView {
    has session_id: str,
        task: str,
        status: str,
        events: list[TimelineEvent] = [],
        inspections: list[PageInspection] = [],
        answer: str = "",
        sources: list[str] = [],
        validation: ValidationReport = ValidationReport(),
        budget: dict = {},
        error: str = "";
}

obj StartResult {
    has ok: bool,
        session_id: str = "",
        error: str = "",
        rate_limited: bool = False;
}

obj FindingView {
    has finding_id: str,
        seq: int,
        detected_at: float,
        url: str,
        host: str,
        risk: str,
        classification: str,
        attack_categories: list[str] = [],
        suspicious_spans: list[dict] = [],
        guard_decision: str = "",
        critic_decision: str = "",
        confidence: float = 0.0,
        explanation: str = "",
        layer_results: dict = {},
        sanitized_preview: str = "",
        allowed_sinks: list[str] = [],
        forbidden_sinks: list[str] = [],
        trust: str = "UNTRUSTED_WEB",
        origin: str = "research",
        review_status: str = "PENDING_REVIEW",
        reviewed_at: float = 0.0;
}

obj FixtureInfo {
    has id: str,
        name: str,
        host: str,
        task: str;
}

obj ComparisonResult {
    has fixture_id: str,
        task: str,
        url: str,
        unprotected_answer: str = "",
        unprotected_actions: list[str] = [],
        unprotected_canary_leaked: bool = False,
        unprotected_error: str = "",
        protected: PageInspection | None = None,
        protected_answer: str = "",
        protected_validation: ValidationReport = ValidationReport(),
        protected_error: str = "",
        guard_mode: str = "";
}

obj GuardStatus {
    has gemini: bool,
        mode: str,
        rate_limit: str,
        budgets: dict = {};
}

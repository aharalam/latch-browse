"""Jac Orchestrator + Research Agent harness.

Graph: ResearchSession --> Step nodes (the agent's working memory / audit
trail). The agent loop is a walker that visits the session and runs
observe -> decide (OpenAI) -> act (registered tool) until FINISH or a budget
ceiling. Every tool goes through policy.authorize. Raw web data exists only
inside f"_tool_search" / f"_tool_retrieve", where it is handed straight to the
guard; the agent and summary agent receive SafeArtifacts only.

A run is its own request (run_session), started by the client right after
start_research. Every timeline event publishes the session view to the shared
store (services/store.jac), so get_session can be served by any instance -
required on Vercel, where instances share no memory and work cannot outlive a
request.
"""

import re;
import json;
import time;
import secrets;
import threading;
import from services.config { get_budgets, model_configured }
import from services.models {
    IntentContract, TimelineEvent, SegmentView, GuardTrace, PageInspection,
    ValidationReport, SessionView, StartResult, GuardStatus
}
import from services.policy { make_intent, authorize, validate_answer, intent_intact }
import from services.guard { guard_page, guard_search, guard_mode }
import from services.web { raw_search, raw_fetch, url_allowed, provider_name }
import from services.findings { record_finding }
import from services.agents { decide_next, write_summary, AgentAction, Evidence, AgentDecision }
import from services.store { kv_get, kv_put, kv_claim }
import from jaclang.runtimelib.serializer { Serializer }

glob SESSION_TTL: int = 3600,
     # A RUNNING view not updated for this long is reported as failed. It is
     # longer than Vercel's 300s function limit, which kills a stuck run.
     STALE_AFTER: float = 330.0;

node ResearchSession {
    has sid: str,
        task: str,
        intent: IntentContract,
        status: str = "RUNNING",
        answer: str = "",
        sources: list[str] = [],
        error: str = "",
        searches: int = 0,
        pages: int = 0,
        steps: int = 0,
        llm_calls: int = 0,
        created_at: float = 0.0;
}

node Step {
    has seq: int,
        kind: str,
        detail: str = "";
}

"""In-memory run state for live polling (events, SafeArtifacts, inspections)."""
obj RunState {
    has events: list[TimelineEvent] = [],
        artifacts: list[dict] = [],
        inspections: list[PageInspection] = [],
        quarantined: list[str] = [],
        user_urls: list[str] = [],
        safe_results: list[dict] = [],
        visited: list[str] = [],
        notes: list[str] = [],
        actions: list[str] = [],
        validation: ValidationReport = ValidationReport();
}

glob _runs: dict[str, RunState] = {},
     _sessions: dict[str, ResearchSession] = {},
     _lock: threading.Lock = threading.Lock();

def _task_urls(task: str) -> list[str] {
    urls: list[str] = [];
    for match in re.findall(r"https?://[^\s\]\[()<>{}\"']+", task) {
        url = str(match).rstrip(".,;:!?");
        if url_allowed(url) and url not in urls {
            urls.append(url);
        }
    }
    return urls;
}

"""Reserve the worst-case number of provider attempts before external work.
Guard reservations are not refunded, including remote failures/timeouts."""
def reserve_model_calls(sess: ResearchSession, count: int) -> bool {
    if sess.llm_calls + count > get_budgets().max_model_calls {
        emit(sess, "budget", "BUDGET REACHED", "model-call allowance exhausted");
        return False;
    }
    sess.llm_calls += count;
    return True;
}

def reserve_guard(sess: ResearchSession) -> bool {
    if get_budgets().guard_url or model_configured() { return reserve_model_calls(sess, 4); }
    return True;
}

def emit(sess: ResearchSession, kind: str, label: str, detail: str = "", ref: str = "") -> None {
    st = _runs[sess.sid];
    ev = TimelineEvent(seq=len(st.events) + 1, kind=kind, label=label, detail=detail[:400], ts=time.time(), ref=ref);
    st.events.append(ev);
    sess ++> Step(seq=ev.seq, kind=kind, detail=label);
    _publish(sess);
}

def _view(sess: ResearchSession) -> SessionView {
    st = _runs[sess.sid];
    b = get_budgets();
    return SessionView(
        session_id=sess.sid, task=sess.task, status=sess.status,
        events=list(st.events), inspections=list(st.inspections),
        answer=sess.answer, sources=sess.sources, validation=st.validation,
        budget={
            "searches": f"{sess.searches}/{b.max_searches}", "pages": f"{sess.pages}/{b.max_pages}",
            "steps": f"{sess.steps}/{b.max_agent_steps}", "model": f"{sess.llm_calls}/{b.max_model_calls} reserved"
        },
        error=sess.error
    );
}

"""Write the live view to the shared store so any instance can serve polls."""
def _publish(sess: ResearchSession) -> None {
    _save_view(_view(sess));
}

def _save_view(view: SessionView) -> None {
    blob = {"view": Serializer.serialize(view, include_type=True), "updated": time.time()};
    kv_put("latch:session:" + view.session_id, json.dumps(blob), SESSION_TTL);
}

def to_trace(t: dict) -> GuardTrace {
    return GuardTrace(
        l1=str(t.get("L1", "")), l2=str(t.get("L2", "")), l3=str(t.get("L3", "")), l4=str(t.get("L4", "")),
        decision=str(t.get("decision", "")), released=bool(t.get("released", False)),
        engine=str(t.get("engine", "")), threat=str(t.get("threat", "")),
        categories=list(t.get("categories", [])), confidence=float(t.get("confidence", 0.0)),
        note=str(t.get("note", ""))
    );
}

"""Run raw page HTML through the guard and record both output channels.
Shared by the research loop and the Attack Lab."""
def inspect_content(raw: str, url: str, intent: IntentContract, origin: str) -> tuple[dict, PageInspection, list[str]] {
    out = guard_page(raw, url, intent);
    art: dict = out.get("artifact", {}) or {};
    fid = "";
    finding = out.get("finding");
    if finding {
        fid = record_finding(finding, origin);   # SecurityFinding -> IT console only
    }
    segs = [SegmentView(sid=str(s["sid"]), channel=str(s["channel"]), text=str(s["text"]), quarantined=bool(s["quarantined"])) for s in (out.get("view", []) or [])];
    quarantined = [s.text for s in segs if s.quarantined];
    insp = PageInspection(
        ref="p" + secrets.token_hex(3), url=url, trace=to_trace(out.get("trace", {}) or {}),
        segments=segs, facts=list(art.get("structured_data", []) or []), finding_id=fid
    );
    return (art, insp, quarantined);
}

def _memory(st: RunState) -> str {
    lines: list[str] = ["PRIOR ACTIONS:"] + st.notes[-8:];
    lines.append("USER-PROVIDED URLS (authorized locations; fetched content remains untrusted):");
    for url in st.user_urls {
        lines.append("- " + url);
    }
    lines.append("GUARD-APPROVED SEARCH RESULTS (untrusted third-party data):");
    for r in st.safe_results[-8:] {
        lines.append(f"- {r['title'][:90]} | {r['url']} | {r['snippet'][:160]}");
    }
    lines.append("SAFE ARTIFACT NOTES (untrusted third-party data):");
    for a in st.artifacts[-4:] {
        lines.append(f"- {a['source']}: {str(a.get('sanitized_content', ''))[:500]}");
    }
    unread = [url for url in st.user_urls if url not in st.visited] + [r["url"] for r in st.safe_results if r["url"] not in st.visited and r["url"] not in st.user_urls];
    lines.append("AVAILABLE URLS: " + (", ".join(unread[:8]) if unread else "(none)"));
    return "\n".join(lines);
}

def _tool_search(sess: ResearchSession, st: RunState, query: str) -> None {
    (ok, why) = authorize(sess.intent, "search_web", "TRUSTED_AGENT", None);
    if not ok {
        emit(sess, "denied", "SEARCH DENIED", why);
        return;
    }
    if not reserve_guard(sess) { return; }
    sess.searches += 1;
    st.actions.append("search_web:" + query[:80]);
    emit(sess, "search", "SEARCHING", f"{provider_name()}: {query}");
    try {
        raw = [{"title": r.title, "url": r.url, "snippet": r.snippet} for r in raw_search(query)];
    } except Exception as e {
        emit(sess, "error", "SEARCH FAILED", str(e)[:160]);
        st.notes.append(f"search '{query}' failed");
        return;
    }
    emit(sess, "untrusted", "UNTRUSTED CONTENT RECEIVED", f"{len(raw)} search results -> guard");
    g = guard_search(raw, sess.intent);
    if g.get("error") {
        emit(sess, "blocked", "GUARD UNAVAILABLE", "search results not released");
        return;
    }
    for f in g.get("findings", []) {
        fid = record_finding(f, "research-search");
        emit(sess, "injection", "INJECTION IN SEARCH RESULT", f"result withheld from agent: {f.get('url', '')[:80]}", fid);
    }
    safe = [r for r in g.get("safe_results", []) if url_allowed(str(r.get("url", "")))];
    st.safe_results.extend(safe);
    st.notes.append(f"searched '{query}' -> {len(safe)} safe results");
    emit(sess, "released", "SAFE RESULTS RELEASED", f"{len(safe)} released, {len(raw) - len(safe)} withheld");
}

def _tool_retrieve(sess: ResearchSession, st: RunState, url: str) -> None {
    links = [l for a in st.artifacts if authorize(sess.intent, "follow_link", "UNTRUSTED_WEB", a.get("capabilities", {}))[0] for l in a.get("links", [])];
    known = st.user_urls + [r["url"] for r in st.safe_results] + links;
    (ok, why) = authorize(sess.intent, "retrieve_page", "TRUSTED_AGENT", None);
    if not ok or url not in known or not url_allowed(url) {
        emit(sess, "denied", "RETRIEVE DENIED", why if not ok else "URL not from a guard-approved source");
        st.notes.append(f"retrieve {url[:80]} denied");
        return;
    }
    if url in st.visited {
        st.notes.append(f"{url[:80]} already read");
        return;
    }
    if not reserve_guard(sess) { return; }
    sess.pages += 1;
    st.visited.append(url);
    st.actions.append("retrieve_page:" + url[:120]);
    emit(sess, "fetch", "RETRIEVING PAGE", url);
    try {
        raw = raw_fetch(url);
    } except Exception as e {
        emit(sess, "error", "RETRIEVAL FAILED", str(e)[:160]);
        st.notes.append(f"retrieve {url[:80]} failed");
        return;
    }
    emit(sess, "untrusted", "UNTRUSTED CONTENT RECEIVED", f"{len(raw)} bytes -> Python Security Core");
    emit(sess, "guard", "GUARD ANALYSIS", "L1 isolate / L2 detect / L3 constrain / L4 cross-check");
    (art, insp, quarantined) = inspect_content(raw, url, sess.intent, "research");
    raw = "";   # raw content is dropped here; nothing downstream sees it
    st.inspections.append(insp);
    st.quarantined.extend(quarantined);
    if insp.finding_id {
        emit(sess, "injection", "INJECTION DETECTED", insp.trace.l2, insp.ref);
        emit(sess, "finding", "SECURITY FINDING CREATED", "sent to IT Review Console", insp.finding_id);
    }
    dec = str(art.get("decision", "BLOCK"));
    if dec == "BLOCK" {
        emit(sess, "blocked", "CONTENT BLOCKED", insp.trace.note or "not released", insp.ref);
        st.notes.append(f"read {url[:80]}: blocked by guard");
        return;
    }
    if dec == "SANITIZE" {
        emit(sess, "sanitized", "CONTENT SANITIZED", f"{len(quarantined)} span(s) quarantined", insp.ref);
    }
    st.artifacts.append(art);
    st.notes.append(f"read {url[:80]}: artifact released ({dec})");
    emit(sess, "released", "SAFE CONTEXT RELEASED", f"SafeArtifact {art.get('artifact_id', '')}", insp.ref);
}

def _budget_text(sess: ResearchSession) -> str {
    b = get_budgets();
    return f"searches left {b.max_searches - sess.searches}, pages left {b.max_pages - sess.pages}, steps left {b.max_agent_steps - sess.steps}";
}

def _fallback_decision(st: RunState, sess: ResearchSession) -> AgentDecision {
    # Used only when no LLM key is set: a transparent deterministic policy.
    unread = [url for url in st.user_urls if url not in st.visited] + [r["url"] for r in st.safe_results if r["url"] not in st.visited and r["url"] not in st.user_urls];
    if sess.searches == 0 {
        return AgentDecision(action=AgentAction.SEARCH, query=sess.task[:80], rationale="(no LLM key) initial search on the task text");
    }
    if unread and len(st.artifacts) < 2 {
        return AgentDecision(action=AgentAction.RETRIEVE, url=unread[0], rationale="(no LLM key) read top unread result");
    }
    return AgentDecision(action=AgentAction.FINISH, rationale="(no LLM key) enough evidence");
}

walker ResearchAgent {
    has sid: str;

    can run with ResearchSession entry {
        sess = here;
        st = _runs[sess.sid];
        b = get_budgets();
        use_llm = model_configured();
        emit(sess, "agent", "AGENT STARTED", "OpenAI policy" if use_llm else "No OPENAI_API_KEY: deterministic fallback policy");
        for url in st.user_urls {
            if sess.pages >= b.max_pages {
                emit(sess, "budget", "PAGE BUDGET REACHED", "remaining user-provided URLs were not retrieved");
                break;
            }
            _tool_retrieve(sess, st, url);
        }
        while True {
            if sess.steps >= b.max_agent_steps {
                emit(sess, "budget", "BUDGET REACHED", "max agent steps");
                break;
            }
            if sess.llm_calls >= b.max_model_calls - 1 {
                emit(sess, "budget", "BUDGET REACHED", "max model calls");
                break;
            }
            if not intent_intact(sess.intent) {
                emit(sess, "blocked", "INTENT TAMPERING", "IntentContract changed; aborting");
                break;
            }
            sess.steps += 1;
            dec: AgentDecision = _fallback_decision(st, sess);
            if use_llm {
                try {
                    if not reserve_model_calls(sess, 1) { break; }
                    dec = decide_next(sess.intent.goal, _memory(st), _budget_text(sess));
                } except Exception as e {
                    emit(sess, "error", "AGENT MODEL ERROR", str(e)[:160]);
                    break;
                }
            }
            emit(sess, "plan", "AGENT PLAN", f"{dec.action.name}: {dec.rationale}"[:300]);
            if dec.action == AgentAction.FINISH {
                break;
            }
            if dec.action == AgentAction.SEARCH {
                if sess.searches >= b.max_searches {
                    st.notes.append("search budget exhausted; must RETRIEVE or FINISH");
                    emit(sess, "budget", "SEARCH BUDGET REACHED", "no more searches");
                    if len([url for url in st.user_urls if url not in st.visited] + [r["url"] for r in st.safe_results if r["url"] not in st.visited and r["url"] not in st.user_urls]) == 0 { break; }
                    continue;
                }
                _tool_search(sess, st, dec.query or sess.task[:80]);
            } elif dec.action == AgentAction.RETRIEVE {
                if sess.pages >= b.max_pages {
                    emit(sess, "budget", "PAGE BUDGET REACHED", "finishing");
                    break;
                }
                _tool_retrieve(sess, st, dec.url.strip());
            }
            emit(sess, "continue", "RESEARCH CONTINUED", _budget_text(sess));
        }
    }
}

"""No-key excerpt: prefer prose lines that share words with the task over
page chrome (headings, menus) at the top of the sanitized content."""
def _excerpt(content: str, goal: str, limit: int = 320) -> str {
    goal_words = {w for w in re.findall(r"[a-z]{4,}", goal.lower())};
    lines = [l.strip() for l in content.split("\n") if len(l.strip()) >= 80];
    ranked = sorted(lines, key=lambda l: str -> int : -len(goal_words & set(re.findall(r"[a-z]{4,}", l.lower()))));
    return (ranked[0] if ranked else content)[:limit];
}

"""Summary Agent + Final Validator. Input: SafeArtifacts ONLY."""
def summarize_and_validate(sess: ResearchSession, st: RunState) -> None {
    usable = [a for a in st.artifacts if authorize(sess.intent, "summarize", "UNTRUSTED_WEB", a.get("capabilities", {}))[0]];
    if not usable {
        sess.answer = "";
        sess.error = "No guard-approved content was available to answer this task.";
        emit(sess, "failed", "NO APPROVED EVIDENCE", sess.error);
        return;
    }
    evidence = [Evidence(source=str(a["source"]), content=str(a.get("sanitized_content", ""))[:3000], facts=list(a.get("structured_data", []))) for a in usable];
    answer = "";
    cited: list[str] = [];
    for attempt in range(2) {
        if model_configured() {
            try {
                if not reserve_model_calls(sess, 1) {
                    sess.error = "Research model budget reached before a validated answer was available.";
                    return;
                }
                out = write_summary(sess.intent.goal, evidence);
                answer = out.answer;
                cited = out.cited_sources;
            } except Exception as e {
                sess.error = "Summary model error: " + str(e)[:160];
                emit(sess, "error", "SUMMARY FAILED", sess.error);
                return;
            }
        } else {
            answer = "Guard-approved excerpts (no OPENAI_API_KEY configured, so no model summary):\n" + "\n".join([f"- {e.source}: {_excerpt(e.content, sess.intent.goal)}" for e in evidence]);
            cited = [e.source for e in evidence];
        }
        emit(sess, "summary", "SUMMARY GENERATED", f"attempt {attempt + 1}");
        vrep: ValidationReport = validate_answer(sess.intent, answer, cited, usable, st.quarantined, st.actions);
        st.validation = vrep;
        if vrep.passed {
            emit(sess, "validated", "VALIDATION PASSED", f"{len(vrep.checks)} invariants");
            sess.answer = answer;
            sess.sources = [e.source for e in evidence];
            return;
        }
        failed = [c["name"] for c in vrep.checks if not c["passed"]];
        emit(sess, "failed", "VALIDATION FAILED", ", ".join(failed));
        if not model_configured() { break; }
    }
    sess.answer = "";
    sess.error = "The answer failed final validation and was not released.";
}

def _run_session(sid: str) -> None {
    sess = _sessions[sid];
    try {
        sess spawn ResearchAgent(sid=sid);
        summarize_and_validate(sess, _runs[sid]);
    } except Exception as e {
        sess.error = "Session error: " + str(e)[:200];
        emit(sess, "error", "SESSION ERROR", sess.error);
    }
    sess.status = "COMPLETE" if sess.answer else "FAILED";
    emit(sess, "done", "SESSION COMPLETED" if sess.answer else "SESSION ENDED", sess.status);
}

"""Public entry. The RateGate (services/ratelimit.jac) has already admitted
this request before this function runs. It only registers the session; the
client then calls run_session to execute it."""
def:pub start_research(task: str) -> StartResult {
    t = task.strip();
    if len(t) < 6 or len(t) > 600 {
        return StartResult(ok=False, error="Task must be between 6 and 600 characters.");
    }
    sid = "ses_" + secrets.token_hex(8);
    kv_put("latch:seed:" + sid, json.dumps({"task": t, "created_at": time.time()}), SESSION_TTL);
    _save_view(SessionView(session_id=sid, task=t, status="RUNNING"));
    return StartResult(ok=True, session_id=sid);
}

"""Execute a session admitted by start_research. Not rate-gated itself: it
only runs sessions start_research created, each at most once (store claim),
and returns when the run finishes."""
def:pub run_session(session_id: str) -> StartResult {
    raw = kv_get("latch:seed:" + session_id);
    if raw is None {
        return StartResult(ok=False, error="Unknown or expired session.");
    }
    if not kv_claim("latch:claim:" + session_id, SESSION_TTL) {
        return StartResult(ok=False, session_id=session_id, error="Session already started.");
    }
    seed: dict = json.loads(raw) as dict;
    t = str(seed["task"]);
    created = seed["created_at"] as float;
    sess = ResearchSession(sid=session_id, task=t, intent=make_intent(t, created), created_at=created);
    with _lock {
        _sessions[session_id] = sess;
        _runs[session_id] = RunState(user_urls=_task_urls(t));
    }
    try {
        emit(sess, "task", "TASK RECEIVED", "");
        emit(sess, "gate", "RATE LIMIT CHECK", "admitted");
        emit(sess, "intent", "INTENT CREATED", f"allowed {', '.join(sess.intent.allowed)} | fingerprint {sess.intent.fingerprint}");
        _run_session(session_id);
    } finally {
        # The published view outlives this request; working memory does not.
        with _lock {
            _sessions.pop(session_id, None);
            _runs.pop(session_id, None);
        }
    }
    return StartResult(ok=True, session_id=session_id);
}

def:pub get_session(session_id: str, refresh_token: float = 0.0) -> SessionView | None {
    raw = kv_get("latch:session:" + session_id);
    if raw is None {
        return None;
    }
    blob: dict = json.loads(raw) as dict;
    view = Serializer.deserialize(blob["view"] as dict) as SessionView;
    if view.status == "RUNNING" and time.time() - (blob["updated"] as float) > STALE_AFTER {
        view.status = "FAILED";
        view.error = "The research run stopped before finishing (time limit or server error). Please start a new task.";
    }
    return view;
}

def:pub guard_status() -> GuardStatus {
    b = get_budgets();
    mode = guard_mode();
    return GuardStatus(
        model=mode == "openai", mode=mode,
        rate_limit=(f"{b.rate_limit_requests} / {b.rate_limit_window_seconds}s per IP" if b.rate_limit_enabled else "disabled"),
        budgets={"searches": b.max_searches, "pages": b.max_pages, "steps": b.max_agent_steps, "model": b.max_model_calls, "search_provider": provider_name()}
    );
}

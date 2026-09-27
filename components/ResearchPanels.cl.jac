"""Research view panels: pipeline strip, agent timeline, budget meters and
the result dock. Everything here is derived from the SessionView the
orchestrator returns; nothing is simulated on the client."""

sv import from ..services.models { TimelineEvent, SessionView }
import from react { useEffect, useRef }
import from .SecurityBadges { fmtTime, StateTag, UrlText }

"""Pipeline stages, in order, and the timeline event kinds that belong to each.
`zone` groups stages by who handles them; the trust boundary sits between
the "web" and "core" zones."""
glob STAGES: list[dict] = [
    {"id": "plan", "label": "Plan", "verb": "Planning", "zone": "web", "kinds": ["agent", "plan"]},
    {"id": "search", "label": "Search", "verb": "Searching", "zone": "web", "kinds": ["search"]},
    {"id": "fetch", "label": "Fetch", "verb": "Fetching", "zone": "web", "kinds": ["fetch"]},
    {"id": "inspect", "label": "Inspect", "verb": "Inspecting", "zone": "core", "kinds": ["untrusted", "guard"]},
    {"id": "quarantine", "label": "Quarantine", "verb": "Quarantining", "zone": "core", "kinds": ["injection", "sanitized", "blocked"]},
    {"id": "release", "label": "Release", "verb": "Releasing", "zone": "core", "kinds": ["released"]},
    {"id": "summarize", "label": "Summarize", "verb": "Summarizing", "zone": "answer", "kinds": ["summary"]},
    {"id": "validate", "label": "Validate", "verb": "Validating", "zone": "answer", "kinds": ["validated"]}
];

glob ZONES: list[dict] = [
    {"id": "web", "label": "Agent on the open web", "note": "untrusted"},
    {"id": "core", "label": "LatchBrowse Security Core", "note": "L1 to L4"},
    {"id": "answer", "label": "Answer", "note": "SafeArtifacts only"}
];

"""Which stage a timeline event belongs to ("" if none)."""
def:pub stageOf(kind: str, label: str) -> str {
    for st in STAGES {
        if kind in st["kinds"] { return str(st["id"]); }
    }
    if kind in ["error", "failed", "denied"] {
        if "SEARCH" in label { return "search"; }
        if "RETRIEV" in label { return "fetch"; }
        if "SUMMARY" in label { return "summarize"; }
        if "VALIDATION" in label { return "validate"; }
    }
    return "";
}

"""Per-stage counts, alert flags and the stage of the latest event."""
def:pub pipelineState(events: list[TimelineEvent]) -> dict {
    counts: dict = {};
    alerts: dict = {};
    last = "";
    for ev in events {
        sid = stageOf(ev.kind, ev.label);
        if sid == "" { continue; }
        last = sid;
        if ev.kind in ["error", "failed", "denied"] {
            alerts[sid] = True;
            continue;
        }
        counts[sid] = (counts[sid] or 0) + 1;
        if ev.kind in ["injection", "blocked"] { alerts[sid] = True; }
    }
    return {"counts": counts, "alerts": alerts, "last": last};
}

def:pub currentVerb(events: list[TimelineEvent]) -> str {
    last = pipelineState(events)["last"];
    for st in STAGES {
        if st["id"] == last { return str(st["verb"]); }
    }
    return "Starting";
}

def:pub StageItem(st: dict, n: int, state: str) -> JsxElement {
    mark = "✕" if state == "alert" else ("●" if state == "active" else ("✓" if state == "done" else "○"));
    note = "-";
    if state == "alert" {
        note = "detected" if st["id"] == "quarantine" else "failed";
    } elif n > 0 {
        note = str(n) + "x";
    }
    return <li className="lb-stage relative flex shrink-0 items-center gap-1.5 py-1" data-state={state}>
        <span aria-hidden="true" className="w-3 text-center font-mono text-micro">{mark}</span>
        <span className="text-meta font-semibold">{st["label"]}</span>
        <span className="font-mono text-micro text-fg-3 tabular">{note}</span>
        <span className="sr-only">{", " + state}</span>
        {state == "active" and <span className="lb-scan" aria-hidden="true" />}
    </li>;
}

def:pub PipelineStrip(events: list[TimelineEvent], running: bool) -> JsxElement {
    ps = pipelineState(events);
    counts = ps["counts"];
    alerts = ps["alerts"];
    return <div className="flex min-w-max items-stretch gap-0 lg:min-w-0" role="group" aria-label="Research pipeline">
        {for z in ZONES {
            zid = str(z["id"]);
            if zid == "core" {
                <div key="boundary" className="flex shrink-0 flex-col justify-center gap-1 px-3" aria-label="Trust boundary">
                    <span className="text-micro font-semibold whitespace-nowrap text-brand">{"Trust boundary"}</span>
                    <span className="lb-hatch h-1.5 w-full" aria-hidden="true" />
                </div>
            }
            <div key={zid} className={"flex min-w-0 flex-col justify-center gap-0.5 px-3 py-1.5 " + ("flex-[3] bg-surface" if zid == "core" else ("flex-[3]" if zid == "web" else "flex-[2] border-l border-line"))}>
                <span className="text-micro text-fg-3">
                    <span className="font-semibold text-fg-2">{z["label"]}</span>{"  " + str(z["note"])}
                </span>
                <ol className="flex items-center gap-2">
                    {for (i, st) in enumerate([s for s in STAGES if s["zone"] == zid]) {
                        sid = str(st["id"]);
                        n: int = int(counts[sid] or 0);
                        state = "alert" if alerts[sid] else (("active" if running and ps["last"] == sid else ("done" if n > 0 else "idle")));
                        if i > 0 {
                            <li key={sid + "-c"} aria-hidden="true" className={"h-px min-w-3 flex-1 " + ("bg-fg-3" if n > 0 else "bg-line-strong")} />
                        }
                        <StageItem key={sid} st={st} n={n} state={state} />
                    }}
                </ol>
            </div>
        }}
    </div>;
}

"""Visual weight tier for an event kind: routine events recede,
security-critical ones stand out."""
def:pub eventTier(kind: str) -> str {
    if kind in ["injection", "blocked", "failed", "error", "denied"] { return "critical"; }
    if kind in ["sanitized", "finding", "budget"] { return "attention"; }
    if kind in ["released", "validated", "done"] { return "success"; }
    if kind in ["untrusted", "guard"] { return "boundary"; }
    return "routine";
}

def:pub EventBody(ev: TimelineEvent, tier: str) -> JsxElement {
    mark = "✕" if tier == "critical" else ("!" if tier == "attention" else ("✓" if tier == "success" else ("◇" if tier == "boundary" else "·")));
    labelCls = "tone-hostile" if tier == "critical" else ("tone-warn" if tier == "attention" else ("tone-safe" if tier == "success" else ("text-fg" if tier == "boundary" else "text-fg-2")));
    return <div className="grid grid-cols-[3.75rem_0.875rem_minmax(0,1fr)] gap-x-1.5">
        <span className="pt-px font-mono text-micro text-fg-3 tabular">{fmtTime(ev.ts)}</span>
        <span aria-hidden="true" className={"pt-px text-center font-mono text-micro " + labelCls}>{mark}</span>
        <div className="min-w-0">
            <span className={"font-mono text-micro " + ("font-semibold " if tier != "routine" else "font-medium ") + labelCls}>{ev.label}</span>
            {ev.detail and <p title={ev.detail} className={"mt-0.5 break-words text-meta " + ("text-fg-2" if tier in ["critical", "attention"] else "line-clamp-2 text-fg-3")}>{ev.detail}</p>}
        </div>
    </div>;
}

def:pub Timeline(events: list[TimelineEvent], running: bool, selectedRef: str, onSelect: Callable[[str], None]) -> JsxElement {
    scroller: any = useRef(None);
    useEffect(lambda {
        el = scroller.current;
        if running and el { el.scrollTop = el.scrollHeight; }
    }, [len(events), running]);

    return <div ref={scroller} className="relative min-h-0 flex-1 overflow-y-auto">
        {len(events) == 0 and <div className="flex flex-col gap-2 px-3 pt-3 text-body text-fg-2">
            <p className="font-medium text-fg">{"No session yet"}</p>
            <p>{"Every step the agent takes, and every time web content crosses the trust boundary, is logged here as it happens."}</p>
        </div>}
        <ol className="flex flex-col py-1">
            {for ev in events {
                tier = eventTier(ev.kind);
                pageRef = ev.ref.startswith("p");
                rowCls = "lb-enter relative block w-full border-l-2 px-3 py-1.5 text-left ";
                if tier == "critical" {
                    rowCls = rowCls + "border-hostile bg-hostile/[0.07] ";
                } elif tier == "attention" {
                    rowCls = rowCls + "border-warn/70 ";
                } elif tier == "success" {
                    rowCls = rowCls + "border-safe/50 ";
                } else {
                    rowCls = rowCls + "border-transparent ";
                }
                if pageRef and ev.ref == selectedRef { rowCls = rowCls + "bg-overlay "; }
                <li key={str(ev.seq)}>
                    {pageRef and <button type="button" className={rowCls + "cursor-pointer hover:bg-raised"} onClick={lambda { onSelect(ev.ref); }}>
                        <EventBody ev={ev} tier={tier} />
                        <span className="sr-only">{"Show this page in the content view"}</span>
                    </button>}
                    {not pageRef and <div className={rowCls}><EventBody ev={ev} tier={tier} /></div>}
                </li>
            }}
        </ol>
    </div>;
}

"""Budget readout: the orchestrator's own "used/limit" strings, with a meter."""
def:pub BudgetMeter(label: str, value: str) -> JsxElement {
    head = value.split(" ")[0];
    parts = head.split("/");
    pct: float = 0.0;
    if len(parts) == 2 and Number(parts[1]) > 0 {
        pct = Math.min(100, Math.round(Number(parts[0]) * 100 / Number(parts[1])));
    }
    return <div className="flex min-w-0 flex-col gap-1">
        <div className="flex items-baseline justify-between gap-2">
            <span className="text-micro text-fg-3">{label}</span>
            <span className="font-mono text-micro text-fg tabular">{head}</span>
        </div>
        <div className="h-0.5 w-full bg-overlay" role="presentation">
            <div className={"h-full " + ("bg-warn" if pct >= 100 else "bg-fg-3")} style={{"width": str(pct) + "%"}} />
        </div>
    </div>;
}

def:pub ResultDock(session: SessionView | None) -> JsxElement {
    if session is None { return <></>; }
    if session.status == "RUNNING" {
        return <div className="flex shrink-0 items-center gap-3 border-t border-line bg-surface px-4 py-2.5 text-body">
            <span className="lb-tag" data-tone="idle"><span aria-hidden="true">{"○"}</span><span>{"HELD"}</span></span>
            <span className="text-fg-2">{"The answer is written only from released SafeArtifacts, then checked by the final validator before it is shown."}</span>
        </div>;
    }
    checks = session.validation.checks;
    passed = session.validation.passed;
    hasChecks = len(checks) > 0;
    released = bool(session.answer);
    nOk = len([c for c in checks if c["passed"]]);
    return <section aria-labelledby="result-title" className={"lb-fade flex max-h-[42%] min-h-0 shrink-0 flex-col border-t-2 bg-surface " + ("border-safe" if released else "border-hostile")}>
        <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2">
            <h2 id="result-title" className="text-title font-semibold">{"Validated answer" if released else "Answer not released"}</h2>
            {hasChecks and <StateTag label={("VALIDATION PASSED" if passed else "VALIDATION FAILED")} tone={"PASS" if passed else "FAILED"} />}
            {hasChecks and <span className="font-mono text-micro text-fg-3 tabular">{str(nOk) + "/" + str(len(checks)) + " invariants hold"}</span>}
            <span className="ml-auto font-mono text-micro text-fg-3">{session.status}</span>
        </div>
        <div className="relative min-h-0 overflow-y-auto px-4 py-3">
            {session.answer and <p className="max-w-[80ch] text-read whitespace-pre-line text-fg">{session.answer}</p>}
            {session.error and <p className="mt-1 max-w-[80ch] text-body tone-hostile">{session.error}</p>}
            {len(session.sources) > 0 and <div className="mt-3 flex flex-col gap-1">
                <h3 className="text-micro font-semibold text-fg-3">{"Sources cited"}</h3>
                <ul className="flex flex-wrap gap-x-4 gap-y-1">
                    {for s in session.sources { <li key={s}><UrlText url={s} className="text-micro" /></li> }}
                </ul>
            </div>}
            {hasChecks and <div className="mt-3 flex flex-col gap-1">
                <h3 className="text-micro font-semibold text-fg-3">{"Final validator"}</h3>
                <ul className="grid grid-cols-1 gap-x-6 gap-y-0.5 sm:grid-cols-2">
                    {for c in checks {
                        <li key={str(c["name"])} className="flex items-center gap-2 font-mono text-micro">
                            <span className={"w-4 text-center " + ("tone-safe" if c["passed"] else "tone-hostile")} aria-hidden="true">{"✓" if c["passed"] else "✕"}</span>
                            <span className={"text-fg-2" if c["passed"] else "tone-hostile"}>{str(c["name"])}</span>
                            <span className="sr-only">{"passed" if c["passed"] else "failed"}</span>
                        </li>
                    }}
                </ul>
            </div>}
        </div>
    </section>;
}

"""Research workspace: task bar on top, agent timeline left, live content
center, Guard Inspector right, validated answer below the content."""

sv import from ..services.research { start_research, run_session, get_session, guard_status }
sv import from ..services.models { SessionView, GuardStatus, PageInspection }
import from .AppNav { AppNav }
import from .GuardPanels { GuardInspector, ContentViewer }
import from .SecurityBadges { fmtTime }
import from .ui.button { Button }
import from .ui.textarea { Textarea }
import from react { useEffect, useRef }
import from "@hugeicons/react" { HugeiconsIcon }
import from "@hugeicons/core-free-icons" { Search01Icon, CheckmarkCircle01Icon, Alert01Icon }

glob EXAMPLE_TASKS: list[str] = [
    "Find pricing for three popular project management tools.",
    "What is the current population of Iceland and how has it changed?",
    "Summarize what indirect prompt injection is."
];

def:pub eventTone(kind: str) -> str {
    if kind in ["injection", "blocked", "failed", "error", "denied"] { return "text-red-400 border-red-500"; }
    if kind in ["sanitized", "guard", "untrusted", "finding", "budget"] { return "text-orange-400 border-orange-500"; }
    if kind in ["released", "validated", "done"] { return "text-emerald-400 border-emerald-500"; }
    if kind in ["plan", "agent", "summary"] { return "text-primary border-primary"; }
    return "text-zinc-400 border-zinc-600";
}

def:pub ResearchWorkspace() -> JsxElement {
    has task: str = "",
        session: SessionView | None = None,
        sessionId: str = "",
        starting: bool = False,
        error: str = "",
        rateLimited: bool = False,
        selectedRef: str = "",
        showOriginal: bool = True,
        status: GuardStatus | None = None;

    requestState = useRef({"busy": False, "mounted": True});

    can with entry { loadStatus(); }
    useEffect(lambda {
        requestState.current.mounted = True;
        return lambda { requestState.current.mounted = False; };
    }, []);
    useEffect(lambda {
        control = {"cancelled": False, "timer": None};
        if sessionId != "" { poll(sessionId, control); }
        return lambda {
            control.cancelled = True;
            if control.timer is not None { clearTimeout(control.timer); }
        };
    }, [sessionId]);

    async def loadStatus -> None;
    async def startTask -> None;
    async def poll(sid: str, control: any) -> None;
    async def launchRun(sid: str) -> None;

    sx: any = session;
    running = sessionId != "" and (session is None or session.status == "RUNNING");
    inspections: list[PageInspection] = session.inspections if session is not None else [];
    current: PageInspection | None = None;
    for i in inspections {
        if i.ref == selectedRef { current = i; }
    }
    if current is None and len(inspections) > 0 { current = inspections[len(inspections) - 1]; }

    statusText = "idle";
    tone = "muted";
    if status is not None {
        statusText = ("Gemini configured" if status.gemini else ("guard unavailable" if status.mode == "unavailable" else "degraded guard (no key)")) + " / " + status.budgets.get("search_provider", "");
        tone = "ok" if status.gemini else "warn";
    }

    return <div className="dark flex min-h-svh flex-col bg-background text-foreground lg:h-svh">
        <AppNav status={statusText} statusTone={tone} />
        <div className="border-b border-border bg-card pt-3 pb-3 pl-4 pr-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start">
                <div className="flex flex-1 flex-col gap-1.5">
                    <label htmlFor="task" className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{"Research task  /  TRUSTED_USER"}</label>
                    <Textarea
                        id="task"
                        value={task}
                        onChange={lambda (e: ChangeEvent) { task = e.target.value; }}
                        placeholder="e.g. Find pricing for three popular project management tools."
                        className="min-h-[52px] resize-none text-sm"
                        rows={2}
                    />
                    <div className="flex flex-wrap gap-1.5">
                        {for ex in EXAMPLE_TASKS {
                            <button key={ex} onClick={lambda { task = ex; }} className="rounded-sm border border-border pt-0.5 pb-0.5 pl-2 pr-2 text-[11px] text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground">{ex}</button>
                        }}
                    </div>
                </div>
                <div className="flex flex-row gap-3 lg:flex-col lg:items-stretch lg:w-56">
                    <Button onClick={startTask} disabled={starting or running or len(task.strip()) < 6} className="h-10 flex-1 lg:flex-none">
                        <HugeiconsIcon icon={Search01Icon} strokeWidth={2} className="size-4" />
                        {"Starting..." if starting else ("Agent running..." if running else "Run secure research")}
                    </Button>
                    {session is not None and <div className="grid flex-1 grid-cols-2 gap-x-3 font-mono text-[10px] text-muted-foreground lg:flex-none">
                        <span>{"searches " + str(session.budget.get("searches", ""))}</span>
                        <span>{"pages " + str(session.budget.get("pages", ""))}</span>
                        <span>{"steps " + str(session.budget.get("steps", ""))}</span>
                        <span>{"gemini " + str(session.budget.get("gemini", ""))}</span>
                    </div>}
                </div>
            </div>
            {rateLimited and <div className="mt-3 border-l-2 border-orange-500 bg-orange-500/10 pt-2 pb-2 pl-3 pr-3 text-xs">
                <p className="font-semibold text-orange-300">{"Request limit reached."}</p>
                <p className="text-muted-foreground">{"This demo is temporarily limiting research requests to protect hackathon API resources. Please try again later."}</p>
            </div>}
            {(error and not rateLimited) and <p className="mt-2 text-xs text-red-400">{error}</p>}
        </div>

        <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[280px_1fr_300px]">
            <aside className="min-h-0 overflow-auto border-b border-border lg:border-b-0 lg:border-r">
                <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-background pt-2 pb-2 pl-3 pr-3">
                    <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-primary">{"Agent timeline"}</span>
                    {running and <span className="font-mono text-[10px] text-orange-400 animate-pulse">{"LIVE"}</span>}
                </div>
                {session is None and <p className="pt-4 pl-3 pr-3 text-xs text-muted-foreground">{"Submit a task. Every step the agent takes, and every trust-boundary crossing, is logged here."}</p>}
                <ol className="flex flex-col">
                    {for ev in (session.events if session is not None else []) {
                        <li key={str(ev.seq)} className={"border-l-2 pt-1.5 pb-1.5 pl-3 pr-3 animate-in fade-in slide-in-from-left-1 duration-300 " + eventTone(ev.kind).split(" ")[1] + (" cursor-pointer hover:bg-secondary/50" if ev.ref.startswith("p") else "")} onClick={lambda { if ev.ref.startswith("p") { selectedRef = ev.ref; } }}>
                            <div className="flex items-center gap-2">
                                <span className="font-mono text-[10px] text-muted-foreground tabular-nums">{fmtTime(ev.ts)}</span>
                                <span className={"font-mono text-[11px] font-semibold " + eventTone(ev.kind).split(" ")[0]}>{ev.label}</span>
                            </div>
                            {ev.detail and <p className="mt-0.5 break-words text-[11px] leading-snug text-muted-foreground">{ev.detail}</p>}
                        </li>
                    }}
                </ol>
            </aside>

            <main className="flex min-h-0 flex-col overflow-auto">
                {len(inspections) > 1 and <div className="flex gap-1 overflow-x-auto border-b border-border pt-1.5 pb-1.5 pl-3 pr-3">
                    {for i in inspections {
                        <button key={i.ref} onClick={lambda { selectedRef = i.ref; }} className={"shrink-0 rounded-sm border pt-0.5 pb-0.5 pl-2 pr-2 font-mono text-[10px] " + ("border-primary text-foreground" if current is not None and current.ref == i.ref else "border-border text-muted-foreground")}>
                            {i.url.replace("https://", "")[:40]}
                        </button>
                    }}
                </div>}
                <div className="flex items-center justify-between border-b border-border pt-2 pb-2 pl-4 pr-4">
                    <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-primary">{"Live content / browser view"}</span>
                    <div className="flex items-center gap-1 font-mono text-[10px]">
                        <button onClick={lambda { showOriginal = True; }} className={"rounded-sm pt-0.5 pb-0.5 pl-2 pr-2 " + ("bg-secondary text-foreground" if showOriginal else "text-muted-foreground")}>{"original"}</button>
                        <button onClick={lambda { showOriginal = False; }} className={"rounded-sm pt-0.5 pb-0.5 pl-2 pr-2 " + ("bg-secondary text-foreground" if not showOriginal else "text-muted-foreground")}>{"sanitized"}</button>
                    </div>
                </div>
                <div className="flex-1 pt-3 pb-4 pl-4 pr-4">
                    <ContentViewer insp={current} showOriginal={showOriginal} />
                </div>
                {session is not None and session.status != "RUNNING" and <div className="border-t border-border bg-card pt-4 pb-5 pl-4 pr-4">
                    <div className="flex items-center gap-2">
                        <HugeiconsIcon icon={CheckmarkCircle01Icon if session.answer else Alert01Icon} strokeWidth={2} className={"size-4 " + ("text-emerald-400" if session.answer else "text-red-400")} />
                        <h2 className="text-sm font-semibold">{"Validated answer" if session.answer else "Answer not released"}</h2>
                        <span className={"ml-auto font-mono text-[10px] " + ("text-emerald-400" if session.validation.passed else "text-red-400")}>{("VALIDATION PASSED" if session.validation.passed else "VALIDATION FAILED") if len(session.validation.checks) > 0 else ""}</span>
                    </div>
                    {session.answer and <p className="mt-2 whitespace-pre-line text-sm leading-relaxed">{session.answer}</p>}
                    {session.error and <p className="mt-2 text-xs text-red-400">{session.error}</p>}
                    {len(sx.sources) > 0 and <div className="mt-3 flex flex-wrap gap-2">
                        {for s in sx.sources { <span key={s} className="rounded-sm border border-border pt-0.5 pb-0.5 pl-2 pr-2 font-mono text-[10px] text-muted-foreground">{s.replace("https://", "")[:60]}</span> }}
                    </div>}
                    {len(sx.validation.checks) > 0 and <div className="mt-3 grid grid-cols-1 gap-x-4 gap-y-0.5 sm:grid-cols-2">
                        {for c in sx.validation.checks {
                            <div key={str(c["name"])} className="flex items-center gap-2 font-mono text-[10px]">
                                <span className={"text-emerald-400" if c["passed"] else "text-red-400"}>{"[ok]" if c["passed"] else "[x]"}</span>
                                <span className="text-muted-foreground">{str(c["name"])}</span>
                            </div>
                        }}
                    </div>}
                </div>}
            </main>

            <aside className="min-h-0 overflow-auto border-t border-border pl-4 pr-4 pb-4 lg:border-t-0 lg:border-l">
                <div className="sticky top-0 z-10 -ml-4 -mr-4 border-b border-border bg-background pt-2 pb-2 pl-4 pr-4">
                    <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-primary">{"Guard inspector"}</span>
                </div>
                <GuardInspector insp={current} />
            </aside>
        </div>
    </div>;
}

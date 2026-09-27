"""Research workspace: task bar and pipeline strip on top, agent timeline
left, untrusted web content center (with the validated answer docked
beneath it), Guard Inspector right."""

sv import from ..services.research { start_research, run_session, get_session, guard_status }
sv import from ..services.models { SessionView, GuardStatus, PageInspection, TimelineEvent }
import from .AppNav { AppNav }
import from .GuardPanels { GuardInspector, ContentViewer }
import from .ResearchPanels { PipelineStrip, Timeline, BudgetMeter, ResultDock, currentVerb }
import from .SecurityBadges { marker, toneOf, splitUrl }
import from react { useEffect, useRef }

glob EXAMPLE_TASKS: list[str] = [
    "Find pricing for three popular project management tools.",
    "What is the current population of Iceland and how has it changed?",
    "Summarize what indirect prompt injection is."
];

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

    events: list[TimelineEvent] = session.events if session is not None else [];
    stage = currentVerb(events) if running else "";
    taskLen = len(task.strip());

    def onTaskKey(e: KeyboardEvent) {
        if e.key == "Enter" and (e.metaKey or e.ctrlKey) {
            e.preventDefault();
            startTask();
        }
    }
    def selectPage(ref: str) { selectedRef = ref; }

    navStatus: list[dict] = [{"label": "Guard", "value": "not reported", "tone": "idle"}];
    if status is not None {
        guardTone = "safe" if status.gemini else ("hostile" if status.mode == "unavailable" else "warn");
        navStatus = [
            {"label": "Guard", "value": status.mode + ("" if status.gemini or status.mode == "unavailable" else " (no Gemini key)"), "tone": guardTone},
            {"label": "Search", "value": status.budgets.get("search_provider", ""), "tone": "idle"},
            {"label": "Rate limit", "value": status.rate_limit, "tone": "idle"}
        ];
    }

    runLabel = "Starting session…" if starting else (("Agent running: " + stage) if running else "Run secure research");

    return <div className="dark flex min-h-svh flex-col bg-canvas text-fg lg:h-svh">
        <AppNav status={navStatus} />
        <h1 className="sr-only">{"LatchBrowse research workspace"}</h1>

        <section aria-label="Research task" className="relative border-b border-line bg-surface px-4 pt-3 pb-3">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:gap-5">
                <div className="flex min-w-0 flex-1 flex-col gap-1.5">
                    <div className="flex items-center gap-2">
                        <label htmlFor="task" className="text-meta font-semibold text-fg">{"Research task"}</label>
                        <span className="lb-tag" data-tone="idle" title="Your task is trusted input. Web content never is."><span aria-hidden="true">{"◇"}</span><span>{"TRUSTED_USER"}</span></span>
                        <span className={"ml-auto font-mono text-micro tabular " + ("tone-warn" if taskLen > 600 else "text-fg-3")} aria-live="polite">{str(taskLen) + " / 600"}</span>
                    </div>
                    <textarea
                        id="task"
                        value={task}
                        onChange={lambda (e: ChangeEvent) { task = e.target.value; }}
                        onKeyDown={onTaskKey}
                        placeholder="e.g. Compare the free tiers of three note-taking apps…"
                        className="lb-input h-auto min-h-[3.25rem] resize-none py-2 text-read"
                        rows={2}
                        aria-describedby="task-hint"
                    />
                    <div className="flex flex-wrap items-center gap-x-1 gap-y-1">
                        <span id="task-hint" className="mr-1 text-micro text-fg-3">{"Try an example"}</span>
                        {for ex in EXAMPLE_TASKS {
                            <button key={ex} type="button" onClick={lambda { task = ex; }} className="rounded-sm px-1.5 py-1 text-left text-meta text-fg-2 underline decoration-line-strong underline-offset-4 hover:text-fg hover:decoration-fg-3">{ex}</button>
                        }}
                    </div>
                </div>
                <div className="flex flex-col gap-2.5 lg:w-64">
                    <button type="button" onClick={startTask} disabled={starting or running or taskLen < 6} className="lb-btn lb-btn-primary lb-btn-lg relative w-full overflow-hidden">
                        {not (starting or running) and <span aria-hidden="true" className="font-mono">{"▶"}</span>}
                        <span>{runLabel}</span>
                        {(starting or running) and <span className="lb-scan" aria-hidden="true" />}
                    </button>
                    {not (starting or running) and <p className="text-micro text-fg-3">{("Ctrl + Enter to run. " if taskLen >= 6 else "Enter at least 6 characters. ") + "Web pages cross the Security Core before the agent sees them."}</p>}
                    {session is not None and <div className="grid grid-cols-2 gap-x-4 gap-y-1.5" aria-label="Session budget">
                        <BudgetMeter label="Searches" value={str(sx.budget["searches"] or "")} />
                        <BudgetMeter label="Pages" value={str(sx.budget["pages"] or "")} />
                        <BudgetMeter label="Steps" value={str(sx.budget["steps"] or "")} />
                        <BudgetMeter label="Gemini" value={str(sx.budget["gemini"] or "")} />
                    </div>}
                </div>
            </div>
            {rateLimited and <div role="alert" className="mt-3 flex gap-3 border-l-2 border-warn bg-warn/10 px-3 py-2 text-body">
                <span className="lb-tag" data-tone="warn"><span aria-hidden="true">{"!"}</span><span>{"RATE LIMITED"}</span></span>
                <div>
                    <p className="font-semibold text-fg">{"Request limit reached."}</p>
                    <p className="text-fg-2">{"This demo is temporarily limiting research requests to protect hackathon API resources. Please try again later."}</p>
                </div>
            </div>}
            {(error and not rateLimited) and <p role="alert" className="mt-2 border-l-2 border-hostile pl-2.5 text-body tone-hostile">{error}</p>}
        </section>

        <div className="overflow-x-auto border-b border-line bg-canvas">
            <PipelineStrip events={events} running={running} />
        </div>

        <div className="relative grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[15.5rem_minmax(0,1fr)_17.5rem] xl:grid-cols-[18.5rem_minmax(0,1fr)_20rem]">
            <aside aria-labelledby="timeline-title" className="flex max-h-[60svh] min-h-0 flex-col border-b border-line lg:max-h-none lg:border-r lg:border-b-0">
                <div className="lb-panel-head">
                    <h2 id="timeline-title" className="lb-panel-title">{"Agent timeline"}</h2>
                    <span className="lb-panel-sub tabular">{str(len(events)) + " events"}</span>
                    {running and <span className="ml-auto flex items-center gap-1.5 font-mono text-micro text-brand"><span className="size-1.5 rounded-full bg-brand" aria-hidden="true" />{stage}</span>}
                </div>
                <Timeline events={events} running={running} selectedRef={current.ref if current is not None else ""} onSelect={selectPage} />
            </aside>

            <main id="main" className="flex min-h-[70svh] min-w-0 flex-col lg:min-h-0">
                <div className="lb-panel-head">
                    <h2 className="lb-panel-title">{"Web content"}</h2>
                    <span className="lb-panel-sub hidden xl:inline">{"untrusted input, as the guard saw it"}</span>
                    <div className="lb-seg ml-auto" role="group" aria-label="Content view">
                        <button type="button" aria-pressed={showOriginal} onClick={lambda { showOriginal = True; }}>{"Original"}</button>
                        <button type="button" aria-pressed={not showOriginal} onClick={lambda { showOriginal = False; }}>{"Sanitized"}</button>
                    </div>
                </div>
                {len(inspections) > 0 and <div role="group" aria-label="Retrieved pages" className="flex shrink-0 overflow-x-auto border-b border-line bg-surface">
                    {for i in inspections {
                        parts = splitUrl(i.url);
                        isCur = current is not None and current.ref == i.ref;
                        <button
                            key={i.ref}
                            type="button"
                            aria-pressed={isCur}
                            title={i.url}
                            onClick={lambda { selectedRef = i.ref; }}
                            className={"flex max-w-72 shrink-0 items-center gap-2 border-r border-line px-3 py-1.5 text-left " + ("bg-canvas shadow-[inset_0_2px_0_var(--lb-brand)]" if isCur else "hover:bg-raised")}
                        >
                            <span aria-hidden="true" className={"font-mono text-micro tone-" + toneOf(i.trace.decision)}>{marker(i.trace.decision)}</span>
                            <span className="min-w-0 truncate font-mono text-micro">
                                <span className={"text-fg" if isCur else "text-fg-2"}>{parts[0]}</span>
                                <span className="text-fg-3">{parts[1]}</span>
                            </span>
                            <span className="sr-only">{i.trace.decision}</span>
                        </button>
                    }}
                </div>}
                <div className="relative min-h-0 flex-1 overflow-y-auto px-4 pt-3 pb-6">
                    {(running and len(inspections) == 0) and <div className="flex flex-col gap-1 text-body text-fg-2" role="status">
                        <p className="font-medium text-fg">{stage + "…"}</p>
                        <p>{"The first retrieved page will appear here once it has crossed the Security Core."}</p>
                    </div>}
                    {not (running and len(inspections) == 0) and <ContentViewer insp={current} showOriginal={showOriginal} />}
                </div>
                <ResultDock session={session} />
            </main>

            <aside aria-labelledby="inspector-title" className="flex min-h-0 flex-col border-t border-line lg:border-t-0 lg:border-l">
                <div className="lb-panel-head">
                    <h2 id="inspector-title" className="lb-panel-title">{"Guard inspector"}</h2>
                    <span className="lb-panel-sub hidden xl:inline">{"Python Security Core"}</span>
                </div>
                <div className="relative min-h-0 flex-1 overflow-y-auto px-3">
                    <GuardInspector insp={current} />
                </div>
            </aside>
        </div>
        <p className="sr-only" role="status" aria-live="polite">{("Agent " + stage) if running else ((("Session " + session.status.lower()) if session is not None else ""))}</p>
    </div>;
}

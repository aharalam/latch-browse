"""Attack Lab: pick a fixture, run the same task/page/injection unprotected
vs protected, side by side."""

sv import from ..services.attacklab { list_fixtures, run_attack_fixture }
sv import from ..services.models { FixtureInfo, ComparisonResult }
import from .AppNav { AppNav }
import from .GuardPanels { GuardInspector, ContentViewer }
import from .SecurityBadges { StateTag, DecisionTag }
import from .ui.skeleton { Skeleton }
import from "@jac/runtime" { Link }

"""One outcome readout in the comparison summary."""
def:pub Outcome(label: str, children: any = None) -> JsxElement {
    return <div className="flex min-w-0 flex-col gap-1">
        <dt className="text-micro text-fg-3">{label}</dt>
        <dd className="min-w-0">{children}</dd>
    </div>;
}

def:pub LaneHead(title: str, path: str, tone: str, mark: str) -> JsxElement {
    return <div className={"flex flex-wrap items-center gap-x-3 gap-y-0.5 border-b px-4 py-2 " + ("border-hostile/40 bg-hostile/[0.08]" if tone == "hostile" else "border-safe/40 bg-safe/[0.06]")}>
        <span aria-hidden="true" className={"font-mono text-meta tone-" + tone}>{mark}</span>
        <h2 className="text-title font-semibold">{title}</h2>
        <span className="ml-auto font-mono text-micro text-fg-3">{path}</span>
    </div>;
}

def:pub AttackLab() -> JsxElement {
    has fixtures: list[FixtureInfo] = [],
        selectedId: str = "",
        result: ComparisonResult | None = None,
        loading: bool = True,
        running: bool = False,
        error: str = "",
        rateLimited: bool = False;

    async can with entry {
        try {
            # Read the fetched list from a local: the `fixtures` state value
            # is not updated until the next render.
            loaded = await list_fixtures();
            fixtures = loaded;
            if len(loaded) > 0 { selectedId = loaded[0].id; }
        } except Exception as e {
            error = "Could not load fixtures.";
        }
        loading = False;
    }

    async def runComparison -> None {
        if selectedId == "" { return; }
        running = True;
        error = "";
        rateLimited = False;
        result = None;
        try {
            result = await run_attack_fixture(selectedId, "both");
        } except Exception as e {
            msg = str(e);
            if "429" in msg or "RATE_LIMITED" in msg or "limit" in msg.lower() {
                rateLimited = True;
            } else {
                error = "Run failed: " + msg;
            }
        }
        running = False;
    }

    r: any = result;
    selected: any = None;
    for f in fixtures {
        if f.id == selectedId { selected = f; }
    }

    quarantined = 0;
    if r is not None and r.protected is not None {
        quarantined = len([s for s in r.protected.segments if s.quarantined]);
    }
    baselineRan = r is not None and not r.unprotected_error;

    navStatus: list[dict] = [{"label": "Fixtures", "value": "controlled", "tone": "warn"}];
    if r is not None {
        navStatus = navStatus + [{"label": "Guard", "value": r.guard_mode, "tone": "safe" if r.guard_mode == "gemini" else "warn"}];
    }

    return <div className="dark flex min-h-svh flex-col bg-canvas text-fg lg:h-svh">
        <AppNav status={navStatus} />
        <div className="grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[17rem_minmax(0,1fr)]">
            <aside aria-labelledby="lab-title" className="flex min-h-0 flex-col border-b border-line lg:border-r lg:border-b-0">
                <div className="border-b border-line bg-surface px-4 py-3">
                    <h1 id="lab-title" className="text-display font-semibold tracking-tight">{"Attack lab"}</h1>
                    <p className="mt-1 text-meta text-fg-2">{"Real fixtures through the real pipeline. No verdict is hard-coded, and dangerous actions are intercepted, never executed."}</p>
                </div>
                <div className="flex h-8 items-center border-b border-line px-4 text-micro font-semibold text-fg-3" id="fixture-label">{"Hostile page fixtures"}</div>
                {loading and <div className="flex flex-col gap-2 px-4 pt-3" aria-busy="true"><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /></div>}
                <ul className="min-h-0 flex-1 overflow-y-auto" aria-labelledby="fixture-label">
                    {for f in fixtures {
                        isSel = f.id == selectedId;
                        <li key={f.id}>
                            <button
                                type="button"
                                aria-pressed={isSel}
                                onClick={lambda { selectedId = f.id; result = None; }}
                                className={"flex w-full flex-col items-start gap-0.5 border-b border-line/60 py-2 pr-3 pl-4 text-left " + ("bg-overlay shadow-[inset_2px_0_0_var(--lb-brand)]" if isSel else "hover:bg-raised")}
                            >
                                <span className={"text-body font-medium " + ("text-fg" if isSel else "text-fg-2")}>{f.name}</span>
                                <span className="font-mono text-micro text-fg-3">{f.host}</span>
                            </button>
                        </li>
                    }}
                </ul>
                {error and <p role="alert" className="border-t border-line px-4 py-2 text-body tone-hostile">{error}</p>}
            </aside>

            <main id="main" className="flex min-h-0 min-w-0 flex-col">
                <section aria-label="Comparison setup" className="flex flex-wrap items-end gap-4 border-b border-line bg-surface px-4 py-3">
                    <div className="flex min-w-0 flex-1 flex-col gap-1">
                        <span className="text-micro text-fg-3">{"Task, identical in both runs"}</span>
                        <p className="text-read font-medium">{selected.task if selected is not None else "Select a fixture to see its task."}</p>
                        {selected is not None and <p className="font-mono text-micro text-fg-3">{"page  https://" + selected.host}</p>}
                    </div>
                    <button type="button" onClick={runComparison} disabled={running or selectedId == ""} className="lb-btn lb-btn-primary lb-btn-lg relative overflow-hidden">
                        {not running and <span aria-hidden="true" className="font-mono">{"▶"}</span>}
                        <span>{"Running both paths…" if running else "Run comparison"}</span>
                        {running and <span className="lb-scan" aria-hidden="true" />}
                    </button>
                </section>
                {rateLimited and <div role="alert" className="flex gap-3 border-b border-warn/40 bg-warn/10 px-4 py-2 text-body">
                    <span className="lb-tag" data-tone="warn"><span aria-hidden="true">{"!"}</span><span>{"RATE LIMITED"}</span></span>
                    <p><span className="font-semibold text-fg">{"Request limit reached. "}</span><span className="text-fg-2">{"This demo is temporarily limiting research requests to protect hackathon API resources. Please try again later."}</span></p>
                </div>}

                {(r is None and not running) and <div className="flex flex-1 flex-col gap-4 px-6 pt-10">
                    <div className="flex max-w-2xl flex-col gap-2 text-body text-fg-2">
                        <p className="text-title font-semibold text-fg">{"Protected vs unprotected"}</p>
                        <p>{"Run the comparison to watch a naive agent read the hostile page directly, then the same page cross the LatchBrowse trust boundary."}</p>
                    </div>
                    <ol className="grid max-w-3xl grid-cols-1 gap-px border border-line bg-line md:grid-cols-2" aria-label="The two paths">
                        <li className="flex flex-col gap-1 bg-canvas px-4 py-3">
                            <span className="text-meta font-semibold tone-hostile">{"Unprotected agent"}</span>
                            <span className="font-mono text-micro text-fg-2">{"hostile page  >  model  >  answer + tool calls"}</span>
                        </li>
                        <li className="flex flex-col gap-1 bg-canvas px-4 py-3">
                            <span className="text-meta font-semibold tone-safe">{"LatchBrowse protected"}</span>
                            <span className="font-mono text-micro text-fg-2">{"hostile page  >  L1 to L4  >  SafeArtifact  >  summary"}</span>
                        </li>
                    </ol>
                </div>}
                {running and <div className="grid flex-1 grid-cols-1 gap-px bg-line xl:grid-cols-2" aria-busy="true" aria-label="Running comparison">
                    <div className="flex flex-col gap-2 bg-canvas px-4 pt-4"><Skeleton className="h-4 w-40" /><Skeleton className="h-24 w-full" /><Skeleton className="h-16 w-full" /></div>
                    <div className="flex flex-col gap-2 bg-canvas px-4 pt-4"><Skeleton className="h-4 w-40" /><Skeleton className="h-24 w-full" /><Skeleton className="h-16 w-full" /></div>
                </div>}

                {r is not None and <div className="flex min-h-0 flex-1 flex-col">
                    <dl className="grid grid-cols-2 gap-x-6 gap-y-3 border-b border-line px-4 py-3 md:grid-cols-3 xl:grid-cols-6" aria-label="Comparison outcome">
                        <Outcome label="Unprotected: canary secret leaked">
                            {baselineRan and <StateTag label={"YES" if r.unprotected_canary_leaked else "NO"} tone={"CRITICAL" if r.unprotected_canary_leaked else "PASS"} />}
                            {not baselineRan and <span className="font-mono text-micro text-fg-3">{"not tested"}</span>}
                        </Outcome>
                        <Outcome label="Unprotected: tool calls attempted">
                            {baselineRan and <span className={"font-mono text-meta font-semibold tabular " + ("tone-hostile" if len(r.unprotected_actions) > 0 else "text-fg")}>{str(len(r.unprotected_actions)) + " intercepted"}</span>}
                            {not baselineRan and <span className="font-mono text-micro text-fg-3">{"not tested"}</span>}
                        </Outcome>
                        <Outcome label="Protected: guard decision">
                            {r.protected is not None and <DecisionTag decision={r.protected.trace.decision} />}
                        </Outcome>
                        <Outcome label="Protected: spans quarantined">
                            <span className={"font-mono text-meta font-semibold tabular " + ("tone-hostile" if quarantined > 0 else "text-fg")}>{str(quarantined)}</span>
                        </Outcome>
                        <Outcome label="Protected: final validation">
                            {len(r.protected_validation.checks) > 0 and <StateTag label={("PASSED" if r.protected_validation.passed else "FAILED") + " " + str(len(r.protected_validation.checks))} tone={"PASS" if r.protected_validation.passed else "FAILED"} />}
                            {len(r.protected_validation.checks) == 0 and <span className="font-mono text-micro text-fg-3">{"not run"}</span>}
                        </Outcome>
                        <Outcome label="SecurityFinding">
                            {(r.protected is not None and r.protected.finding_id) and <Link to="/console" className="font-mono text-micro text-brand underline-offset-2 hover:underline">{r.protected.finding_id}</Link>}
                            {not (r.protected is not None and r.protected.finding_id) and <span className="font-mono text-micro text-fg-3">{"none"}</span>}
                        </Outcome>
                    </dl>

                    <div className="grid min-h-0 flex-1 grid-cols-1 gap-px bg-line xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)_18rem]">
                        <section aria-label="Unprotected agent" className="flex min-h-0 min-w-0 flex-col bg-canvas">
                            <LaneHead title="Unprotected agent" path="raw page > model" tone="hostile" mark="✕" />
                            <div className="relative flex min-h-0 flex-col gap-4 overflow-y-auto px-4 pt-3 pb-5">
                                {r.unprotected_error and <p className="border-l-2 border-warn bg-warn/10 px-3 py-1.5 text-body text-fg">{r.unprotected_error}</p>}
                                <div>
                                    <h3 className="text-micro font-semibold text-fg-3">{"Raw page text it would receive" if (r.unprotected_error and r.unprotected_answer) else "Answer it would give"}</h3>
                                    <p className="mt-1 max-w-[70ch] text-read whitespace-pre-line text-fg/90">{r.unprotected_answer or "-"}</p>
                                </div>
                                <div>
                                    <h3 className="text-micro font-semibold text-fg-3">{"Tool calls attempted (intercepted)"}</h3>
                                    {len(r.unprotected_actions) == 0 and <p className="mt-1 font-mono text-micro text-fg-3">{"none"}</p>}
                                    <ul className="flex flex-col">
                                        {for a in r.unprotected_actions {
                                            <li key={a} className="mt-1 border-l-2 border-hostile bg-hostile/[0.08] px-2 py-1 font-mono text-micro break-words text-fg">{a}</li>
                                        }}
                                    </ul>
                                </div>
                            </div>
                        </section>

                        <section aria-label="LatchBrowse protected" className="flex min-h-0 min-w-0 flex-col bg-canvas">
                            <LaneHead title="LatchBrowse protected" path="page > Security Core > SafeArtifact > summary" tone="safe" mark="✓" />
                            <div className="relative flex min-h-0 flex-col gap-5 overflow-y-auto px-4 pt-3 pb-5">
                                <ContentViewer insp={r.protected} showOriginal={True} />
                                <div className="border-t border-line pt-3">
                                    <div className="flex flex-wrap items-center gap-2">
                                        <h3 className="text-meta font-semibold">{"Summary agent answer"}</h3>
                                        <span className="font-mono text-micro text-fg-3">{"from the SafeArtifact only"}</span>
                                    </div>
                                    {r.protected_error and <p className="mt-2 border-l-2 border-hostile pl-2.5 text-body tone-hostile">{r.protected_error}</p>}
                                    <p className="mt-1 max-w-[75ch] text-read whitespace-pre-line text-fg">{r.protected_answer or "-"}</p>
                                </div>
                            </div>
                        </section>

                        <aside aria-label="Guard inspector" className="flex min-h-0 flex-col bg-canvas">
                            <div className="lb-panel-head">
                                <h2 className="lb-panel-title">{"Guard inspector"}</h2>
                                <span className="lb-panel-sub">{"guard " + r.guard_mode}</span>
                            </div>
                            <div className="relative min-h-0 overflow-y-auto px-3">
                                <GuardInspector insp={r.protected} />
                            </div>
                        </aside>
                    </div>
                </div>}
            </main>
        </div>
    </div>;
}

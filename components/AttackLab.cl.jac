"""Attack Lab: pick a fixture, run the same task/page/injection unprotected
vs protected, side by side."""

sv import from ..services.attacklab { list_fixtures, run_attack_fixture }
sv import from ..services.models { FixtureInfo, ComparisonResult }
import from .AppNav { AppNav }
import from .GuardPanels { GuardInspector, ContentViewer }
import from .ui.button { Button }
import from .ui.skeleton { Skeleton }
import from "@jac/runtime" { Link }
import from "@hugeicons/react" { HugeiconsIcon }
import from "@hugeicons/core-free-icons" { Alert01Icon, LockIcon, ArrowRight01Icon }

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
            fixtures = await list_fixtures();
            if len(fixtures) > 0 { selectedId = fixtures[0].id; }
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

    return <div className="dark flex min-h-svh flex-col bg-background text-foreground">
        <AppNav status="controlled fixtures" statusTone="warn" />
        <div className="grid flex-1 grid-cols-1 lg:grid-cols-[260px_1fr]">
            <aside className="border-b border-border lg:border-b-0 lg:border-r">
                <div className="border-b border-border pt-3 pb-3 pl-4 pr-4">
                    <h1 className="text-base font-semibold tracking-tight">{"Attack Lab"}</h1>
                    <p className="text-[11px] text-muted-foreground">{"Real fixtures, real pipeline. No verdicts are hard-coded; dangerous actions are intercepted, never executed."}</p>
                </div>
                {loading and <div className="flex flex-col gap-2 pt-3 pl-4 pr-4"><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /><Skeleton className="h-9 w-full" /></div>}
                <ul className="flex flex-col">
                    {for f in fixtures {
                        <li key={f.id}>
                            <button onClick={lambda { selectedId = f.id; result = None; }} className={"flex w-full flex-col items-start gap-0.5 border-b border-border/50 border-l-2 pt-2 pb-2 pl-4 pr-3 text-left transition-colors " + ("border-l-primary bg-secondary/60" if f.id == selectedId else "border-l-transparent hover:bg-secondary/30")}>
                                <span className="text-xs font-medium">{f.name}</span>
                                <span className="font-mono text-[10px] text-muted-foreground">{f.host}</span>
                            </button>
                        </li>
                    }}
                </ul>
                {error and <p className="pt-3 pl-4 pr-4 text-xs text-red-400">{error}</p>}
            </aside>

            <main className="flex min-w-0 flex-col">
                <div className="flex flex-wrap items-end gap-4 border-b border-border bg-card pt-3 pb-3 pl-4 pr-4">
                    <div className="flex min-w-0 flex-1 flex-col gap-1">
                        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{"Task (identical in both runs)"}</span>
                        <p className="text-sm">{selected.task if selected is not None else "Select a fixture"}</p>
                        <p className="font-mono text-[11px] text-muted-foreground">{("page: https://" + selected.host) if selected is not None else ""}</p>
                    </div>
                    <Button onClick={runComparison} disabled={running or selectedId == ""} className="h-9">
                        {"Running both paths..." if running else "Run comparison"}
                        <HugeiconsIcon icon={ArrowRight01Icon} strokeWidth={2} className="size-4" />
                    </Button>
                </div>
                {rateLimited and <div className="border-b border-orange-500/40 bg-orange-500/10 pt-2 pb-2 pl-4 pr-4 text-xs">
                    <span className="font-semibold text-orange-300">{"Request limit reached. "}</span>
                    <span className="text-muted-foreground">{"This demo is temporarily limiting research requests to protect hackathon API resources. Please try again later."}</span>
                </div>}

                {(r is None and not running) and <div className="flex flex-1 flex-col items-center justify-center gap-2 pt-16 pb-16 text-center">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-primary">{"Protected vs unprotected"}</span>
                    <p className="max-w-md text-xs text-muted-foreground">{"Run the comparison to watch a naive agent read the hostile page directly, then the same page cross the LatchBrowse trust boundary."}</p>
                </div>}
                {running and <div className="grid flex-1 grid-cols-1 gap-px bg-border xl:grid-cols-2">
                    <div className="flex flex-col gap-2 bg-background pt-4 pl-4 pr-4"><Skeleton className="h-4 w-40" /><Skeleton className="h-24 w-full" /><Skeleton className="h-16 w-full" /></div>
                    <div className="flex flex-col gap-2 bg-background pt-4 pl-4 pr-4"><Skeleton className="h-4 w-40" /><Skeleton className="h-24 w-full" /><Skeleton className="h-16 w-full" /></div>
                </div>}

                {r is not None and <div className="grid flex-1 grid-cols-1 gap-px bg-border xl:grid-cols-2">
                    <section className="flex min-w-0 flex-col bg-background">
                        <div className="flex items-center gap-2 border-b border-red-500/40 bg-red-500/10 pt-2 pb-2 pl-4 pr-4">
                            <HugeiconsIcon icon={Alert01Icon} strokeWidth={2} className="size-4 text-red-400" />
                            <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-red-300">{"Unprotected agent"}</span>
                            <span className="ml-auto font-mono text-[10px] text-muted-foreground">{"raw page -> model"}</span>
                        </div>
                        <div className="flex flex-col gap-4 pt-3 pb-4 pl-4 pr-4">
                            {r.unprotected_error and <p className="text-xs text-orange-300">{r.unprotected_error}</p>}
                            <div>
                                <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{"Answer it would give"}</div>
                                <p className="mt-1 whitespace-pre-line text-sm leading-relaxed text-foreground/90">{r.unprotected_answer or "-"}</p>
                            </div>
                            <div>
                                <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{"Tool calls attempted (intercepted)"}</div>
                                {len(r.unprotected_actions) == 0 and <p className="mt-1 font-mono text-xs text-muted-foreground">{"none"}</p>}
                                {for a in r.unprotected_actions {
                                    <p key={a} className="mt-1 border-l-2 border-red-500 bg-red-500/5 pt-1 pb-1 pl-2 font-mono text-[11px] text-red-300">{a}</p>
                                }}
                            </div>
                            <div className="font-mono text-[11px]">
                                <span className="text-muted-foreground">{"canary secret leaked: "}</span>
                                <span className={"font-semibold " + ("text-red-400" if r.unprotected_canary_leaked else "text-emerald-400")}>{"YES" if r.unprotected_canary_leaked else "no"}</span>
                            </div>
                        </div>
                    </section>

                    <section className="flex min-w-0 flex-col bg-background">
                        <div className="flex items-center gap-2 border-b border-emerald-500/40 bg-emerald-500/10 pt-2 pb-2 pl-4 pr-4">
                            <HugeiconsIcon icon={LockIcon} strokeWidth={2} className="size-4 text-emerald-400" />
                            <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-emerald-300">{"LatchBrowse protected"}</span>
                            <span className="ml-auto font-mono text-[10px] text-muted-foreground">{"guard: " + r.guard_mode}</span>
                        </div>
                        <div className="grid grid-cols-1 gap-4 pt-3 pb-4 pl-4 pr-4 md:grid-cols-[1fr_220px]">
                            <div className="flex min-w-0 flex-col gap-4">
                                <ContentViewer insp={r.protected} showOriginal={True} />
                                <div>
                                    <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{"Summary agent answer (SafeArtifact only)"}</div>
                                    {r.protected_error and <p className="mt-1 text-xs text-orange-300">{r.protected_error}</p>}
                                    <p className="mt-1 whitespace-pre-line text-sm leading-relaxed">{r.protected_answer or "-"}</p>
                                    {len(r.protected_validation.checks) > 0 and <p className={"mt-2 font-mono text-[10px] " + ("text-emerald-400" if r.protected_validation.passed else "text-red-400")}>{("FINAL VALIDATION PASSED" if r.protected_validation.passed else "FINAL VALIDATION FAILED") + " (" + str(len(r.protected_validation.checks)) + " invariants)"}</p>}
                                </div>
                                {(r.protected is not None and r.protected.finding_id) and <Link to="/console" className="font-mono text-[11px] text-primary underline-offset-4 hover:underline">{"SecurityFinding " + r.protected.finding_id + " sent to IT Review Console ->"}</Link>}
                            </div>
                            <div className="border-t border-border md:border-l md:border-t-0 md:pl-4">
                                <GuardInspector insp={r.protected} />
                            </div>
                        </div>
                    </section>
                </div>}
            </main>
        </div>
    </div>;
}

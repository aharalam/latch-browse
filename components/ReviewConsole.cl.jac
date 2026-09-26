"""IT Review Console - Wireshark-style SecurityFinding inspector.

Consumes FindingView only (no user prompt field exists on it)."""

sv import from ..services.findings { list_findings, flag_finding }
sv import from ..services.models { FindingView }
import from .AppNav { AppNav }
import from .SecurityBadges { StateTag, DecisionTag, fmtTime, severityClass, marker }
import from .ui.button { Button }
import from .ui.input { Input }
import from .ui.native_select { NativeSelect, NativeSelectOption }
import from .ui.skeleton { Skeleton }
import from .ui.empty { Empty, EmptyHeader, EmptyMedia, EmptyTitle, EmptyDescription, EmptyContent }
import from "@jac/runtime" { Link }
import from "@hugeicons/react" { HugeiconsIcon }
import from "@hugeicons/core-free-icons" { Search01Icon, Alert01Icon, RefreshIcon }
import from "sonner" { toast }
import from react { useEffect, useRef }

glob RISK_ORDER: dict = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1};

def:pub DetailRow(label: str, value: any, mono: bool = True) -> JsxElement {
    return <div className="grid grid-cols-[120px_1fr] gap-3 border-b border-border/50 pt-1 pb-1 text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className={("font-mono " if mono else "") + "break-all text-foreground"}>{value}</span>
    </div>;
}

def:pub DetailSection(title: str, children: any = None) -> JsxElement {
    return <section className="flex flex-col">
        <div className="flex items-center gap-2 bg-secondary/50 pt-1 pb-1 pl-3 pr-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-primary">
            <span aria-hidden="true">{"v"}</span><span>{title}</span>
        </div>
        <div className="flex flex-col pl-3 pr-3 pt-1 pb-2">{children}</div>
    </section>;
}

def:pub FindingInspector(f: any, flagging: bool, onFlag: any) -> JsxElement {
    flagged = f.review_status == "HUMAN_FLAGGED";
    return <div className="flex flex-col">
        <div className="flex flex-wrap items-center gap-2 border-b border-border pt-2 pb-2 pl-3 pr-3">
            <span className="font-mono text-xs text-muted-foreground">{"#" + str(f.seq)}</span>
            <span className="font-mono text-sm font-semibold truncate max-w-full">{f.host}</span>
            <StateTag label={f.risk} />
            <span className="ml-auto" />
            {flagged and <StateTag label="HUMAN FLAGGED" tone="CRITICAL" />}
        </div>
        <DetailSection title="Event">
            <DetailRow label="Finding ID" value={f.finding_id} />
            <DetailRow label="Timestamp" value={fmtTime(f.detected_at) + "  (" + new(Date, f.detected_at * 1000).toISOString() + ")"} />
            <DetailRow label="URL" value={f.url} />
            <DetailRow label="Host" value={f.host} />
            <DetailRow label="Source" value={f.origin} />
            <DetailRow label="Decision" value={<DecisionTag decision={f.guard_decision} />} />
            <DetailRow label="Risk" value={f.risk} />
        </DetailSection>
        <DetailSection title="Detection">
            <DetailRow label="Classification" value={f.classification} />
            <DetailRow label="Categories" value={", ".join(f.attack_categories) or "-"} />
            <DetailRow label="Layer 2" value={str(f.layer_results.get("L2", "-"))} />
            <DetailRow label="Layer 4" value={str(f.layer_results.get("L4", "-"))} />
            <DetailRow label="Critic" value={f.critic_decision} />
            <DetailRow label="Confidence" value={str(Math.round(f.confidence * 100)) + "%"} />
            <DetailRow label="Explanation" value={f.explanation or "-"} mono={False} />
        </DetailSection>
        <DetailSection title="Content">
            {len(f.suspicious_spans) == 0 and <p className="text-xs text-muted-foreground pt-1">{"No localized spans."}</p>}
            {for sp in f.suspicious_spans {
                <div key={str(sp["sid"])} className="mt-1 border-l-2 border-red-500 bg-red-500/5 pt-1.5 pb-1.5 pl-2 pr-2">
                    <div className="flex gap-2 font-mono text-[10px] uppercase text-red-400">
                        <span>{"QUARANTINED " + str(sp["sid"])}</span><span>{str(sp["category"])}</span>
                    </div>
                    <p className="font-mono text-xs text-foreground/90 break-words">{str(sp["excerpt"])}</p>
                </div>
            }}
            {f.sanitized_preview and <div className="mt-2 border-l-2 border-emerald-500 bg-emerald-500/5 pt-1.5 pb-1.5 pl-2 pr-2">
                <div className="font-mono text-[10px] uppercase text-emerald-400">{"SANITIZED (released portion)"}</div>
                <p className="text-xs text-foreground/80 whitespace-pre-line">{f.sanitized_preview}</p>
            </div>}
        </DetailSection>
        <DetailSection title="Capability">
            <DetailRow label="trust" value={f.trust} />
            <DetailRow label="allowed sinks" value={", ".join(f.allowed_sinks) or "none"} />
            <DetailRow label="forbidden sinks" value={", ".join(f.forbidden_sinks) or "-"} />
        </DetailSection>
        <DetailSection title="Review">
            <DetailRow label="Status" value={"Human-confirmed prompt injection" if flagged else "Awaiting human review"} mono={False} />
            {flagged and <DetailRow label="Reviewed" value={fmtTime(f.reviewed_at)} />}
            <div className="flex flex-wrap items-center gap-3 pt-2">
                <Button size="sm" variant={"secondary" if flagged else "default"} disabled={flagged or flagging} onClick={onFlag}>
                    {"FLAGGED" if flagged else ("Flagging..." if flagging else "Flag as prompt injection")}
                </Button>
                <span className="text-[11px] text-muted-foreground">{"Review metadata only. Does not change runtime security policy."}</span>
            </div>
        </DetailSection>
    </div>;
}

def:pub ReviewConsole() -> JsxElement {
    has findings: list[FindingView] = [],
        loading: bool = True,
        error: str = "",
        selectedId: str = "",
        hostFilter: str = "",
        severityFilter: str = "ALL",
        statusFilter: str = "ALL",
        sortKey: str = "time",
        sortDesc: bool = True,
        flagging: bool = False;

    feed = useRef({"mounted": True, "busy": False, "selectedId": "", "revision": 0});
    feed.current.selectedId = selectedId;
    useEffect(lambda {
        feed.current.mounted = True;
        loadFindings();
        timer = setInterval(lambda { loadFindings(); }, 5000);
        return lambda {
            feed.current.mounted = False;
            clearInterval(timer);
        };
    }, []);

    async def loadFindings -> None;
    async def flagSelected -> None;
    def toggleSort(key: str) -> None;
    def visibleRows -> list[FindingView];

    rows = visibleRows();
    selected: FindingView | None = None;
    for f in findings {
        if f.finding_id == selectedId { selected = f; }
    }
    pending = len([f for f in findings if f.review_status == "PENDING_REVIEW"]);
    flaggedCount = len(findings) - pending;

    def th(label: str, key: str, cls: str = "") -> JsxElement {
        arrow = ("v" if sortDesc else "^") if sortKey == key else "";
        return <th className={"sticky top-0 z-10 bg-secondary pt-1.5 pb-1.5 pl-2 pr-2 text-left font-mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground " + cls}>
            <button className="flex items-center gap-1 hover:text-foreground" onClick={lambda { toggleSort(key); }}>
                <span>{label}</span><span className="text-primary">{arrow}</span>
            </button>
        </th>;
    }

    return <div className="dark flex h-svh flex-col bg-background text-foreground">
        <AppNav status={str(pending) + " pending review"} statusTone={"warn" if pending > 0 else "ok"} />
        <div className="flex flex-wrap items-center gap-2 border-b border-border bg-card pt-2 pb-2 pl-4 pr-4">
            <div className="flex flex-col mr-4">
                <h1 className="text-base font-semibold tracking-tight">{"IT Review Console"}</h1>
                <p className="text-[11px] text-muted-foreground">{"Suspicious web traffic encountered by AI agents. User research prompts are never shown here."}</p>
            </div>
            <div className="relative w-full sm:w-56">
                <HugeiconsIcon icon={Search01Icon} strokeWidth={2} className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input value={hostFilter} onChange={lambda (e: ChangeEvent) { hostFilter = e.target.value; }} placeholder="Filter host / url" className="h-8 pl-7 font-mono text-xs" />
            </div>
            <NativeSelect value={severityFilter} onChange={lambda (e: ChangeEvent) { severityFilter = e.target.value; }} className="h-8 text-xs" aria-label="Severity filter">
                <NativeSelectOption value="ALL">{"All severities"}</NativeSelectOption>
                <NativeSelectOption value="CRITICAL">{"Critical"}</NativeSelectOption>
                <NativeSelectOption value="HIGH">{"High"}</NativeSelectOption>
                <NativeSelectOption value="MEDIUM">{"Medium"}</NativeSelectOption>
                <NativeSelectOption value="LOW">{"Low"}</NativeSelectOption>
            </NativeSelect>
            <NativeSelect value={statusFilter} onChange={lambda (e: ChangeEvent) { statusFilter = e.target.value; }} className="h-8 text-xs" aria-label="Status filter">
                <NativeSelectOption value="ALL">{"All statuses"}</NativeSelectOption>
                <NativeSelectOption value="PENDING_REVIEW">{"Pending review"}</NativeSelectOption>
                <NativeSelectOption value="HUMAN_FLAGGED">{"Human flagged"}</NativeSelectOption>
            </NativeSelect>
            <div className="ml-auto flex items-center gap-4 font-mono text-[11px] text-muted-foreground">
                <span>{"shown " + str(len(rows)) + "/" + str(len(findings))}</span>
                <span className="text-orange-400">{"pending " + str(pending)}</span>
                <span className="text-red-400">{"flagged " + str(flaggedCount)}</span>
                <Button size="sm" variant="outline" className="h-7" onClick={loadFindings}>
                    <HugeiconsIcon icon={RefreshIcon} strokeWidth={2} className="size-3.5" />{"Refresh"}
                </Button>
            </div>
        </div>
        {error and <div className="border-b border-red-500/40 bg-red-500/10 pt-1.5 pb-1.5 pl-4 pr-4 text-xs text-red-300">{error + " "}<button className="underline" onClick={loadFindings}>{"Retry"}</button></div>}
        <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
            <div className="min-h-0 flex-1 overflow-auto border-b border-border lg:border-b-0 lg:border-r">
                {loading and <div className="flex flex-col gap-1 pt-2 pl-2 pr-2">
                    <Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-2/3" />
                </div>}
                {(not loading and len(findings) == 0) and <div className="pt-10 pb-10 pl-6 pr-6">
                    <Empty className="border border-dashed pt-12 pb-12">
                        <EmptyHeader>
                            <EmptyMedia variant="icon"><HugeiconsIcon icon={Alert01Icon} strokeWidth={2} /></EmptyMedia>
                            <EmptyTitle>{"No security findings yet"}</EmptyTitle>
                            <EmptyDescription>{"Findings appear here when the Security Core detects injection in a page or search result."}</EmptyDescription>
                        </EmptyHeader>
                        <EmptyContent><Link to="/lab"><Button size="sm">{"Open Attack Lab"}</Button></Link></EmptyContent>
                    </Empty>
                </div>}
                {(not loading and len(findings) > 0) and <table className="w-full border-collapse text-xs">
                    <thead>
                        <tr>
                            {th("No.", "seq", "w-14")}
                            {th("Time", "time", "w-20")}
                            {th("Host / URL", "host", "")}
                            {th("Severity", "risk", "w-24")}
                            {th("Detection", "class", "")}
                            {th("Decision", "decision", "w-24")}
                            {th("Status", "status", "w-32")}
                        </tr>
                    </thead>
                    <tbody>
                        {for f in rows {
                            <tr
                                key={f.finding_id}
                                onClick={lambda { selectedId = f.finding_id; }}
                                className={"cursor-pointer border-b border-border/40 font-mono transition-colors " + ("bg-primary/15 outline outline-1 outline-primary/50" if f.finding_id == selectedId else "hover:bg-secondary/50")}
                            >
                                <td className="pt-1 pb-1 pl-2 pr-2 text-muted-foreground tabular-nums">{str(f.seq)}</td>
                                <td className="pt-1 pb-1 pl-2 pr-2 tabular-nums">{fmtTime(f.detected_at)}</td>
                                <td className="max-w-[260px] truncate pt-1 pb-1 pl-2 pr-2" title={f.url}>{f.url.replace("https://", "").replace("http://", "")}</td>
                                <td className="pt-1 pb-1 pl-2 pr-2"><span className={"font-semibold " + severityClass(f.risk).split(" ")[0]}>{marker(f.risk) + " " + f.risk}</span></td>
                                <td className="truncate pt-1 pb-1 pl-2 pr-2">{f.classification}</td>
                                <td className="pt-1 pb-1 pl-2 pr-2">{f.guard_decision}</td>
                                <td className={"pt-1 pb-1 pl-2 pr-2 font-semibold " + ("text-red-400" if f.review_status == "HUMAN_FLAGGED" else "text-zinc-400")}>{"FLAGGED" if f.review_status == "HUMAN_FLAGGED" else "PENDING"}</td>
                            </tr>
                        }}
                    </tbody>
                </table>}
                {(not loading and len(findings) > 0 and len(rows) == 0) and <p className="pt-6 text-center text-xs text-muted-foreground">{"No findings match these filters."}</p>}
            </div>
            <aside className="min-h-0 overflow-auto bg-card lg:w-[460px] xl:w-[540px] max-h-[55svh] lg:max-h-none">
                {selected is not None and <FindingInspector f={selected} flagging={flagging} onFlag={flagSelected} />}
                {selected is None and <div className="flex h-full min-h-40 flex-col items-center justify-center gap-1 pt-8 pb-8 text-center">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-primary">{"Inspector"}</span>
                    <p className="text-xs text-muted-foreground">{"Select a row to inspect event, detection, content, capability and review details."}</p>
                </div>}
            </aside>
        </div>
    </div>;
}

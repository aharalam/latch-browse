"""IT Review Console - Wireshark-style SecurityFinding inspector.

Consumes FindingView only (no user prompt field exists on it)."""

sv import from ..services.findings { list_findings, flag_finding, mark_finding_safe }
sv import from ..services.models { FindingView }
import from .AppNav { AppNav }
import from .SecurityBadges { StateTag, DecisionTag, SeverityText, UrlText, fmtTime }
import from .ui.skeleton { Skeleton }
import from "@jac/runtime" { Link }
import from "sonner" { toast }
import from react { useEffect, useRef }

glob RISK_ORDER: dict = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1};

"""The client runtime has no str.join for untyped lists, so join by hand."""
def:pub joinText(items: list, sep: str = ", ") -> str {
    out = "";
    for x in items {
        if out { out = out + sep; }
        out = out + str(x);
    }
    return out;
}

def:pub DetailRow(label: str, value: any, mono: bool = True) -> JsxElement {
    return <div className="lb-kv px-3">
        <dt className="lb-key">{label}</dt>
        <dd className={("font-mono text-meta " if mono else "text-body ") + "min-w-0 break-words text-fg"}>{value}</dd>
    </div>;
}

def:pub DetailSection(title: str, children: any = None, meta: str = "") -> JsxElement {
    return <details className="lb-section" open={True}>
        <summary>
            <span>{title}</span>
            {meta and <span className="ml-auto font-mono text-micro font-normal text-fg-3">{meta}</span>}
        </summary>
        <dl className="flex flex-col pt-0.5 pb-2">{children}</dl>
    </details>;
}

"""Review workflow: pending -> flag -> human flagged. Review metadata only."""
def:pub ReviewStep(label: str, state: str, last: bool = False) -> JsxElement {
    cls = "tone-hostile" if state == "flagged" else ("text-fg" if state == "current" else ("text-fg-2" if state == "done" else "text-fg-3"));
    mark = "✕" if state == "flagged" else ("●" if state == "current" else ("✓" if state == "done" else "○"));
    return <li className={"flex items-center gap-1.5 " + cls} aria-current={"step" if state == "current" else None}>
        <span aria-hidden="true" className="font-mono text-micro">{mark}</span>
        <span className="text-meta font-medium whitespace-nowrap">{label}</span>
        {not last and <span aria-hidden="true" className="mx-1 h-px w-5 bg-line-strong" />}
    </li>;
}

def:pub FindingInspector(f: FindingView | None, reviewing: bool, onFlag: any, onSafe: any) -> JsxElement {
    if f is None { return <div />; }
    flagged = f.review_status == "HUMAN_FLAGGED";
    safe = f.review_status == "HUMAN_SAFE";
    reviewed = flagged or safe;
    return <div key={f.finding_id} className="lb-fade flex min-h-full flex-col">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-line bg-surface px-3 py-2.5">
            <span className="font-mono text-meta text-fg-3 tabular">{"#" + str(f.seq)}</span>
            <h2 className="min-w-0 truncate font-mono text-title font-semibold">{f.host}</h2>
            <StateTag label={f.risk} />
            <span className="ml-auto" />
            <StateTag label={"HUMAN FLAGGED" if flagged else ("HUMAN SAFE" if safe else "PENDING REVIEW")} tone={"FLAGGED" if flagged else ("safe" if safe else "idle")} />
        </div>
        <div className="flex-1">
            <DetailSection title="Event" meta={f.finding_id}>
                <DetailRow label="Finding ID" value={f.finding_id} />
                <DetailRow label="Timestamp" value={<span className="tabular">{fmtTime(f.detected_at)}<span className="text-fg-3">{"  " + new(Date, f.detected_at * 1000).toISOString()}</span></span>} />
                <DetailRow label="URL" value={<span className="break-all">{f.url}</span>} />
                <DetailRow label="Host" value={f.host} />
                <DetailRow label="Source" value={f.origin} />
                <DetailRow label="Decision" value={<DecisionTag decision={f.guard_decision} />} />
                <DetailRow label="Severity" value={<SeverityText level={f.risk} />} />
            </DetailSection>
            <DetailSection title="Detection" meta={str(Math.round(f.confidence * 100)) + "% confidence"}>
                <DetailRow label="Classification" value={<span className="font-semibold">{f.classification}</span>} />
                <DetailRow label="Categories" value={joinText(f.attack_categories) or "-"} />
                <DetailRow label="Layer 2" value={<span className={"tone-hostile" if "DETECTED" in str(f.layer_results.get("L2", "")) else ""}>{str(f.layer_results.get("L2", "-"))}</span>} />
                <DetailRow label="Layer 4" value={<span className={"tone-safe" if "PASSED" in str(f.layer_results.get("L4", "")) else "tone-warn"}>{str(f.layer_results.get("L4", "-"))}</span>} />
                <DetailRow label="Critic" value={f.critic_decision} />
                <DetailRow label="Confidence" value={<span className="tabular">{str(Math.round(f.confidence * 100)) + "%"}</span>} />
                <DetailRow label="Explanation" value={f.explanation or "-"} mono={False} />
            </DetailSection>
            <DetailSection title="Content" meta={str(len(f.suspicious_spans)) + " quarantined"}>
                <div className="flex flex-col gap-2 px-3 pt-1">
                    {len(f.suspicious_spans) == 0 and <p className="text-body text-fg-2">{"No localized spans."}</p>}
                    {for sp in f.suspicious_spans {
                        <div key={str(sp["sid"])} className="border-l-2 border-hostile bg-hostile/[0.08] px-3 py-1.5">
                            <div className="flex flex-wrap gap-x-2 font-mono text-micro">
                                <span className="font-semibold tone-hostile">{"✕ QUARANTINED"}</span>
                                <span className="text-fg-3">{str(sp["sid"])}</span>
                                <span className="text-fg-2">{str(sp["category"])}</span>
                            </div>
                            <p className="mt-0.5 font-mono text-meta break-words text-fg">{str(sp["excerpt"])}</p>
                        </div>
                    }}
                    {f.sanitized_preview and <div className="border-l-2 border-safe bg-safe/[0.06] px-3 py-1.5">
                        <div className="font-mono text-micro font-semibold tone-safe">{"✓ SANITIZED  released portion"}</div>
                        <p className="mt-0.5 text-body whitespace-pre-line text-fg-2">{f.sanitized_preview}</p>
                    </div>}
                </div>
            </DetailSection>
            <DetailSection title="Capability">
                <DetailRow label="Provenance" value={<StateTag label={f.trust} tone="idle" />} />
                <DetailRow label="Allowed sinks" value={<span className="tone-safe">{joinText(f.allowed_sinks) or "none"}</span>} />
                <DetailRow label="Forbidden sinks" value={<span className="tone-hostile">{joinText(f.forbidden_sinks) or "-"}</span>} />
            </DetailSection>
        </div>
        <section aria-label="Human review" className="sticky bottom-0 border-t border-line bg-surface px-3 py-3">
            <div className="flex items-center justify-between gap-2">
                <h3 className="text-meta font-semibold">{"Review"}</h3>
                {reviewed and <span className="font-mono text-micro text-fg-3 tabular">{"reviewed " + fmtTime(f.reviewed_at)}</span>}
            </div>
            <ol className="mt-2 flex flex-wrap items-center gap-y-1" aria-label="Review progress">
                <ReviewStep label="Pending review" state={"done" if reviewed else "current"} />
                <ReviewStep label={"Marked safe" if safe else "Flag as prompt injection"} state={"done" if reviewed else "todo"} />
                <ReviewStep label={"Human safe" if safe else "Human flagged"} state={"done" if safe else ("flagged" if flagged else "todo")} last={True} />
            </ol>
            <div className="mt-3 flex flex-wrap items-center gap-3">
                <button type="button" className={"lb-btn " + ("" if reviewed else "lb-btn-primary")} disabled={reviewed or reviewing} onClick={onFlag}>
                    {"Flagged" if flagged else ("Flagging…" if reviewing else "Flag as prompt injection")}
                </button>
                <button type="button" className={"lb-btn " + ("" if reviewed else "tone-safe")} disabled={reviewed or reviewing} onClick={onSafe}>
                    {"Marked safe" if safe else ("Saving…" if reviewing else "Mark as safe")}
                </button>
                <p className="min-w-0 flex-1 text-micro text-fg-3">{"Review metadata only. Does not change runtime security policy."}</p>
            </div>
        </section>
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
        reviewing: bool = False,
        lastUpdated: float = 0.0;

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
    async def markSelectedSafe -> None;
    def toggleSort(key: str) -> None;
    def visibleRows -> list[FindingView];

    rows = visibleRows();
    selected: FindingView | None = None;
    for f in findings {
        if f.finding_id == selectedId { selected = f; }
    }
    pending = len([f for f in findings if f.review_status == "PENDING_REVIEW"]);
    flaggedCount = len([f for f in findings if f.review_status == "HUMAN_FLAGGED"]);
    safeCount = len([f for f in findings if f.review_status == "HUMAN_SAFE"]);
    selVisible = len([f for f in rows if f.finding_id == selectedId]) > 0;

    """Arrow keys move the selection through the visible rows."""
    def onRowKey(e: KeyboardEvent, fid: str) {
        if e.key == "Enter" or e.key == " " {
            e.preventDefault();
            selectedId = fid;
            return;
        }
        if e.key != "ArrowDown" and e.key != "ArrowUp" { return; }
        e.preventDefault();
        idx = -1;
        for (i, f) in enumerate(rows) {
            if f.finding_id == fid { idx = i; }
        }
        nxt = idx + (1 if e.key == "ArrowDown" else -1);
        if nxt < 0 or nxt >= len(rows) { return; }
        nid = rows[nxt].finding_id;
        selectedId = nid;
        el: any = document.getElementById("finding-" + nid);
        if el { el.focus(); }
    }

    def th(label: str, key: str, cls: str = "") -> JsxElement {
        active = sortKey == key;
        return <th scope="col" aria-sort={(("descending" if sortDesc else "ascending") if active else "none")} className={"sticky top-0 z-10 border-b border-line-strong bg-surface p-0 text-left " + cls}>
            <button type="button" className={"flex h-8 w-full items-center gap-1 px-2 text-micro font-semibold hover:text-fg " + ("text-fg" if active else "text-fg-3")} onClick={lambda { toggleSort(key); }}>
                <span>{label}</span>
                <span aria-hidden="true" className="font-mono text-brand">{("▼" if sortDesc else "▲") if active else ""}</span>
            </button>
        </th>;
    }

    navStatus: list[dict] = [{"label": "Findings", "value": "loading", "tone": "idle"}];
    if not loading {
        navStatus = [
            {"label": "Pending review", "value": str(pending), "tone": "warn" if pending > 0 else "safe"},
            {"label": "Auto-refresh", "value": "5s", "tone": "hostile" if error else "safe"}
        ];
    }

    return <div className="dark flex min-h-svh flex-col bg-canvas text-fg lg:h-svh">
        <AppNav status={navStatus} />
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line bg-surface px-4 py-2.5">
            <div className="flex min-w-0 flex-col">
                <h1 className="text-display font-semibold tracking-tight">{"Review console"}</h1>
                <p className="text-meta text-fg-2">{"Suspicious web content that AI agents encountered. User research prompts are never shown here."}</p>
            </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2" role="search" aria-label="Filter findings">
            <div className="relative w-full sm:w-64">
                <label htmlFor="host-filter" className="sr-only">{"Filter by host or URL"}</label>
                <span aria-hidden="true" className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 font-mono text-micro text-fg-3">{"/"}</span>
                <input id="host-filter" type="search" value={hostFilter} onChange={lambda (e: ChangeEvent) { hostFilter = e.target.value; }} placeholder="Filter host or URL, e.g. example.com…" autoComplete="off" spellCheck={False} className="lb-input pl-6 font-mono text-meta" />
            </div>
            <label htmlFor="sev-filter" className="sr-only">{"Severity"}</label>
            <select id="sev-filter" value={severityFilter} onChange={lambda (e: ChangeEvent) { severityFilter = e.target.value; }} className="lb-select">
                <option value="ALL">{"All severities"}</option>
                <option value="CRITICAL">{"Critical"}</option>
                <option value="HIGH">{"High"}</option>
                <option value="MEDIUM">{"Medium"}</option>
                <option value="LOW">{"Low"}</option>
            </select>
            <div className="lb-seg" role="group" aria-label="Review status">
                <button type="button" aria-pressed={statusFilter == "ALL"} onClick={lambda { statusFilter = "ALL"; }}>{"All"}</button>
                <button type="button" aria-pressed={statusFilter == "PENDING_REVIEW"} onClick={lambda { statusFilter = "PENDING_REVIEW"; }}>{"Pending"}<span className="font-mono text-micro text-fg-3 tabular">{str(pending)}</span></button>
                <button type="button" aria-pressed={statusFilter == "HUMAN_FLAGGED"} onClick={lambda { statusFilter = "HUMAN_FLAGGED"; }}>{"Flagged"}<span className="font-mono text-micro text-fg-3 tabular">{str(flaggedCount)}</span></button>
                <button type="button" aria-pressed={statusFilter == "HUMAN_SAFE"} onClick={lambda { statusFilter = "HUMAN_SAFE"; }}>{"Safe"}<span className="font-mono text-micro text-fg-3 tabular">{str(safeCount)}</span></button>
            </div>
            <div className="ml-auto flex items-center gap-3">
                <span className="font-mono text-micro text-fg-3 tabular" aria-live="polite">{"showing " + str(len(rows)) + " of " + str(len(findings))}</span>
                <button type="button" className="lb-btn lb-btn-sm" onClick={loadFindings}>
                    <span aria-hidden="true" className="font-mono">{"↻"}</span>{"Refresh"}
                </button>
            </div>
        </div>
        {error and <div role="alert" className="flex items-center gap-3 border-b border-hostile/40 bg-hostile/10 px-4 py-1.5 text-body">
            <span className="lb-tag" data-tone="hostile"><span aria-hidden="true">{"✕"}</span><span>{"FEED ERROR"}</span></span>
            <span className="text-fg">{error}</span>
            <button type="button" className="lb-btn lb-btn-sm ml-auto" onClick={loadFindings}>{"Retry"}</button>
        </div>}
        <main id="main" className="flex min-h-0 flex-1 flex-col lg:flex-row">
            <div className="relative max-h-[50svh] min-h-48 flex-1 overflow-auto border-b border-line lg:max-h-none lg:min-h-0 lg:border-r lg:border-b-0">
                {loading and <div className="flex flex-col gap-1 p-2" aria-busy="true" aria-label="Loading findings">
                    <Skeleton className="h-7 w-full" /><Skeleton className="h-7 w-full" /><Skeleton className="h-7 w-full" /><Skeleton className="h-7 w-2/3" />
                </div>}
                {(not loading and len(findings) == 0) and <div className="flex max-w-lg flex-col gap-2 px-6 pt-10 text-body text-fg-2">
                    <p className="text-title font-semibold text-fg">{"No security findings yet"}</p>
                    <p>{"Nothing suspicious has been detected. Findings appear here when the Security Core detects injection in a page or search result an agent retrieved."}</p>
                    <p>{"To see one now, run a fixture in the Attack Lab."}</p>
                    <Link to="/lab" className="lb-btn mt-2 self-start">{"Open Attack Lab"}</Link>
                </div>}
                {(not loading and len(findings) > 0) and <table className="w-full min-w-[40rem] table-fixed border-collapse text-body">
                    <caption className="sr-only">{"Security findings. Use the arrow keys to move between rows."}</caption>
                    <thead>
                        <tr>
                            {th("No.", "seq", "w-11")}
                            {th("Time", "time", "w-[4.75rem]")}
                            {th("Host / URL", "host", "")}
                            {th("Severity", "risk", "w-[6.25rem]")}
                            {th("Detection", "class", "w-36")}
                            {th("Decision", "decision", "w-[5.75rem]")}
                            {th("Status", "status", "w-[6.5rem]")}
                        </tr>
                    </thead>
                    <tbody>
                        {for (i, f) in enumerate(rows) {
                            isSel = f.finding_id == selectedId;
                            isFlagged = f.review_status == "HUMAN_FLAGGED";
                            isSafe = f.review_status == "HUMAN_SAFE";
                            <tr
                                key={f.finding_id}
                                id={"finding-" + f.finding_id}
                                tabIndex={0 if (isSel or (not selVisible and i == 0)) else -1}
                                aria-current={"true" if isSel else None}
                                onClick={lambda { selectedId = f.finding_id; }}
                                onKeyDown={lambda (e: KeyboardEvent) { onRowKey(e, f.finding_id); }}
                                className={"h-8 cursor-pointer border-b border-line/60 font-mono text-meta outline-none focus-visible:bg-raised focus-visible:shadow-[inset_0_0_0_1px_var(--lb-brand)] " + ("bg-overlay shadow-[inset_2px_0_0_var(--lb-brand)]" if isSel else "hover:bg-raised")}
                            >
                                <td className="px-2 text-fg-3 tabular">{str(f.seq)}</td>
                                <td className="px-2 text-fg-2 tabular">{fmtTime(f.detected_at)}</td>
                                <td className="truncate px-2"><UrlText url={f.url} /></td>
                                <td className="px-2"><SeverityText level={f.risk} /></td>
                                <td className="truncate px-2 font-sans text-body text-fg">{f.classification}</td>
                                <td className={"px-2 tone-" + ("hostile" if f.guard_decision in ["BLOCK", "BLOCKED"] else ("warn" if f.guard_decision in ["SANITIZE", "SANITIZED"] else "idle"))}>{f.guard_decision}</td>
                                <td className="px-2"><StateTag label={"FLAGGED" if isFlagged else ("SAFE" if isSafe else "PENDING")} tone={"FLAGGED" if isFlagged else ("safe" if isSafe else "idle")} /></td>
                            </tr>
                        }}
                    </tbody>
                </table>}
                {(not loading and len(findings) > 0 and len(rows) == 0) and <p className="px-4 pt-6 text-body text-fg-2">{"No findings match these filters."}</p>}
            </div>
            <aside aria-label="Finding inspector" className="relative min-h-0 bg-canvas lg:w-[26rem] lg:overflow-auto xl:w-[29rem] 2xl:w-[34rem]">
                {selected is not None and <FindingInspector f={selected} reviewing={reviewing} onFlag={flagSelected} onSafe={markSelectedSafe} />}
                {selected is None and <div className="flex flex-col gap-2 px-5 pt-8 text-body text-fg-2">
                    <p className="font-semibold text-fg">{"Nothing selected"}</p>
                    <p>{"Select a finding to inspect its event, detection, content, capability and review details. Use the arrow keys to move between rows."}</p>
                </div>}
            </aside>
        </main>
        <footer className="flex h-6 shrink-0 items-center gap-4 border-t border-line bg-surface px-4 font-mono text-micro text-fg-3">
            <span className="tabular">{"updated " + (fmtTime(lastUpdated / 1000) if lastUpdated > 0 else "--:--:--")}</span>
            <span>{"auto-refresh every 5s"}</span>
            <span className="ml-auto hidden sm:inline">{"prompts are not recorded on findings"}</span>
        </footer>
    </div>;
}

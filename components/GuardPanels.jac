"""Reusable research-view panels: live content viewer + Guard Inspector."""

import from .SecurityBadges { StateTag, DecisionTag }

def:pub InspectorRow(label: str, children: any = None) -> JsxElement {
    return <div className="flex flex-col gap-1 border-b border-border/60 pt-2 pb-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{label}</span>
        <div className="text-xs font-medium">{children}</div>
    </div>;
}

def:pub GuardInspector(insp: any) -> JsxElement {
    if insp is None {
        return <div className="flex flex-col gap-2 pt-6 text-xs text-muted-foreground">
            <span className="font-mono text-[10px] uppercase tracking-widest text-primary">{"Guard Inspector"}</span>
            <p>{"No page has crossed the trust boundary yet. When the agent retrieves content, each layer's verdict appears here."}</p>
        </div>;
    }
    t = insp.trace;
    return <div className="flex flex-col animate-in fade-in duration-300">
        <InspectorRow label="Trust"><StateTag label="UNTRUSTED_WEB" tone="pending" /></InspectorRow>
        <InspectorRow label="Threat"><StateTag label={t.threat or "NONE"} /></InspectorRow>
        <InspectorRow label="Attack">
            {len(t.categories) == 0 and <span className="text-muted-foreground">{"None detected"}</span>}
            <div className="flex flex-col">
                {for c in t.categories { <span key={c} className="capitalize">{c.replace("_", " ")}</span> }}
            </div>
        </InspectorRow>
        <InspectorRow label="Decision"><DecisionTag decision={t.decision} /></InspectorRow>
        <InspectorRow label="Confidence"><span className="font-mono tabular-nums">{str(Math.round(t.confidence * 100)) + "%"}</span></InspectorRow>
        <InspectorRow label="Layer 1 - Isolate"><span className="font-mono">{t.l1}</span></InspectorRow>
        <InspectorRow label="Layer 2 - Detect"><span className={"font-mono " + ("text-red-400" if "DETECTED" in t.l2 else ("text-orange-400" if "UNAVAILABLE" in t.l2 else "text-emerald-400"))}>{t.l2}</span></InspectorRow>
        <InspectorRow label="Layer 3 - Constrain"><span className="font-mono">{t.l3}</span></InspectorRow>
        <InspectorRow label="Layer 4 - Cross-check"><span className={"font-mono " + ("text-emerald-400" if "PASSED" in t.l4 else "text-orange-400")}>{t.l4}</span></InspectorRow>
        <InspectorRow label="Safe artifact"><span className={"font-mono " + ("text-emerald-400" if t.released else "text-red-400")}>{"RELEASED" if t.released else "NOT RELEASED"}</span></InspectorRow>
        <InspectorRow label="Engine"><span className="font-mono text-muted-foreground">{t.engine}</span></InspectorRow>
        {t.note and <p className="pt-2 text-[11px] leading-relaxed text-muted-foreground">{t.note}</p>}
    </div>;
}

def:pub ContentViewer(insp: any, showOriginal: bool) -> JsxElement {
    if insp is None {
        return <div className="flex h-full min-h-60 flex-col items-center justify-center gap-2 text-center">
            <span className="font-mono text-[10px] uppercase tracking-widest text-primary">{"Live content view"}</span>
            <p className="max-w-sm text-xs text-muted-foreground">{"Retrieved pages render here segment by segment. Quarantined spans are marked in red; only green-lit text becomes a SafeArtifact."}</p>
        </div>;
    }
    return <div className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2 border-b border-border pb-2">
            <span className="font-mono text-xs text-muted-foreground">{"GET"}</span>
            <span className="truncate font-mono text-xs">{insp.url}</span>
            <DecisionTag decision={insp.trace.decision} />
        </div>
        {len(insp.segments) == 0 and <p className="pt-4 text-xs text-muted-foreground">{"No content was released for display."}</p>}
        {for s in insp.segments {
            if s.quarantined {
                <div key={s.sid} className="mt-1 border-l-2 border-red-500 bg-red-500/[0.07] pt-1.5 pb-1.5 pl-3 pr-2">
                    <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-red-400">
                        <span>{"x QUARANTINED"}</span><span className="text-muted-foreground">{str(s.sid) + " / " + str(s.channel)}</span>
                        <span className="ml-auto text-muted-foreground">{"not sent to agent"}</span>
                    </div>
                    {showOriginal and <p className="font-mono text-xs text-red-200/80 line-through decoration-red-500/60 break-words">{s.text}</p>}
                    {not showOriginal and <p className="font-mono text-xs text-muted-foreground">{"[hostile span withheld - toggle 'original' to inspect]"}</p>}
                </div>
            } elif s.channel == "visible" or s.channel == "title" {
                <div key={s.sid} className="flex gap-3 pt-1 pb-1">
                    <span className="w-8 shrink-0 pt-0.5 font-mono text-[10px] text-muted-foreground">{s.sid}</span>
                    <p className="text-sm leading-relaxed text-foreground/90">{s.text}</p>
                </div>
            } elif showOriginal {
                <div key={s.sid} className="flex gap-3 pt-1 pb-1 opacity-70">
                    <span className="w-8 shrink-0 pt-0.5 font-mono text-[10px] text-muted-foreground">{s.sid}</span>
                    <p className="font-mono text-xs text-muted-foreground">{"[" + s.channel + "] " + s.text}</p>
                </div>
            }
        }}
        {len(insp.facts) > 0 and <div className="mt-3 border border-emerald-500/30 bg-emerald-500/5 pt-2 pb-2 pl-3 pr-3">
            <div className="font-mono text-[10px] uppercase tracking-widest text-emerald-400">{"Typed extraction (provenance UNTRUSTED_WEB)"}</div>
            <div className="mt-1 flex flex-col gap-0.5">
                {for fct in insp.facts {
                    <code key={JSON.stringify(fct)} className="font-mono text-[11px] text-foreground/80">{JSON.stringify(fct)}</code>
                }}
            </div>
        </div>}
    </div>;
}

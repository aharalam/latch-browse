"""Reusable research-view panels: live content viewer + Guard Inspector."""

sv import from ..services.models { PageInspection, SegmentView }
import from "@jac/runtime" { Link }
import from .SecurityBadges { StateTag, DecisionTag, UrlText }

"""Tone for a layer's result text, from the words the guard reports."""
def:pub layerTone(layer: str, text: str) -> str {
    t = text.upper();
    if layer == "L2" {
        if "DETECTED" in t { return "hostile"; }
        if "UNAVAILABLE" in t { return "warn"; }
        return "safe";
    }
    if layer == "L4" {
        if "PASSED" in t { return "safe"; }
        if "BLOCK" in t or "DISAGREE" in t { return "hostile"; }
        return "warn";
    }
    return "idle";
}

def:pub layerMark(tone: str) -> str {
    if tone == "hostile" { return "✕"; }
    if tone == "warn" { return "!"; }
    if tone == "safe" { return "✓"; }
    return "•";
}

def:pub InspectorRow(label: str, children: any = None) -> JsxElement {
    return <div className="lb-kv">
        <dt className="lb-key">{label}</dt>
        <dd className="min-w-0 text-body text-fg">{children}</dd>
    </div>;
}

def:pub InspectorHeading(label: str) -> JsxElement {
    return <h3 className="pt-3 pb-1 text-micro font-semibold text-fg-3">{label}</h3>;
}

"""One row of the layer rail: marker, layer name, verdict text."""
def:pub LayerRow(num: str, name: str, text: str, tone: str) -> JsxElement {
    return <li className="relative grid grid-cols-[1.25rem_minmax(0,1fr)] gap-x-2 pb-2.5 last:pb-0">
        <span aria-hidden="true" className={"z-10 mt-0.5 flex size-5 items-center justify-center rounded-sm border bg-canvas font-mono text-micro font-semibold tone-" + tone} style={{"borderColor": "currentColor"}}>{layerMark(tone)}</span>
        <div className="min-w-0">
            <div className="flex items-baseline gap-1.5">
                <span className="font-mono text-micro text-fg-3">{"L" + num}</span>
                <span className="text-meta font-medium text-fg">{name}</span>
            </div>
            <p className={"font-mono text-micro break-words " + ("text-fg-2" if tone == "idle" else "tone-" + tone)}>{text or "-"}</p>
        </div>
    </li>;
}

def:pub GuardInspector(insp: PageInspection | None) -> JsxElement {
    if insp is None {
        return <div className="flex flex-col gap-2 pt-4 text-body text-fg-2">
            <p className="font-medium text-fg">{"Nothing inspected yet"}</p>
            <p>{"When the agent retrieves a page, the Security Core's verdict for each of its four layers appears here."}</p>
            <ol className="mt-1 flex flex-col gap-1 font-mono text-micro text-fg-3">
                <li>{"L1  Isolate: frame and tag as UNTRUSTED_WEB"}</li>
                <li>{"L2  Detect: find injected directives"}</li>
                <li>{"L3  Constrain: limit what content may do"}</li>
                <li>{"L4  Cross-check: independent critic agrees"}</li>
            </ol>
        </div>;
    }
    t = insp.trace;
    pct = Math.round(t.confidence * 100);
    return <div key={insp.ref} className="lb-fade flex flex-col pb-4">
        <InspectorHeading label="Verdict" />
        <dl className="flex flex-col">
            <InspectorRow label="Trust"><StateTag label="UNTRUSTED_WEB" tone="pending" /></InspectorRow>
            <InspectorRow label="Threat"><StateTag label={t.threat or "NONE"} /></InspectorRow>
            <InspectorRow label="Decision"><DecisionTag decision={t.decision} /></InspectorRow>
            <InspectorRow label="Confidence">
                <div className="flex items-center gap-2">
                    <div className="h-1 w-16 overflow-hidden rounded-full bg-overlay" role="presentation">
                        <div className="h-full bg-fg-2" style={{"width": str(pct) + "%"}} />
                    </div>
                    <span className="font-mono text-micro tabular">{str(pct) + "%"}</span>
                </div>
            </InspectorRow>
            <InspectorRow label="Detection">
                {len(t.categories) == 0 and <span className="text-fg-2">{"None detected"}</span>}
                {len(t.categories) > 0 and <ul className="flex flex-col">
                    {for c in t.categories { <li key={c} className="font-medium capitalize tone-hostile">{c.replace("_", " ")}</li> }}
                </ul>}
            </InspectorRow>
        </dl>

        <InspectorHeading label="Security layers" />
        <ol className="relative flex flex-col pt-1" aria-label="Security layers">
            <span aria-hidden="true" className="absolute top-3 bottom-3 left-2.5 w-px bg-line-strong" />
            <LayerRow num="1" name="Isolate" text={t.l1} tone={layerTone("L1", t.l1)} />
            <LayerRow num="2" name="Detect" text={t.l2} tone={layerTone("L2", t.l2)} />
            <LayerRow num="3" name="Constrain" text={t.l3} tone={layerTone("L3", t.l3)} />
            <LayerRow num="4" name="Cross-check" text={t.l4} tone={layerTone("L4", t.l4)} />
        </ol>

        <InspectorHeading label="Output" />
        <dl className="flex flex-col">
            <InspectorRow label="SafeArtifact">
                <StateTag label={"RELEASED" if t.released else "NOT RELEASED"} tone={"RELEASED" if t.released else "BLOCKED"} />
            </InspectorRow>
            <InspectorRow label="Engine"><span className="font-mono text-micro text-fg-2">{t.engine or "-"}</span></InspectorRow>
            {insp.finding_id and <InspectorRow label="Finding">
                <Link to="/console" className="font-mono text-micro text-brand underline-offset-2 hover:underline">{insp.finding_id}</Link>
                <p className="text-micro text-fg-3">{"Logged for IT review"}</p>
            </InspectorRow>}
        </dl>
        {t.note and <p className="mt-3 border-l-2 border-line-strong pl-2.5 text-meta text-fg-2">{t.note}</p>}
    </div>;
}

def:pub isHiddenChannel(s: SegmentView) -> bool {
    return not s.quarantined and s.channel != "visible" and s.channel != "title";
}

def:pub ContentViewer(insp: PageInspection | None, showOriginal: bool) -> JsxElement {
    if insp is None {
        return <div className="flex max-w-xl flex-col gap-3 pt-2 text-body text-fg-2">
            <p className="text-read font-medium text-fg">{"No page retrieved yet"}</p>
            <p>{"Pages the agent retrieves appear here segment by segment, exactly as the Security Core split them."}</p>
            <ul className="flex flex-col gap-1.5">
                <li className="flex gap-2"><span className="lb-tag" data-tone="hostile">{"✕ QUARANTINED"}</span><span>{"Hostile spans. Never sent to the agent."}</span></li>
                <li className="flex gap-2"><span className="lb-tag" data-tone="safe">{"✓ RELEASED"}</span><span>{"Text that became a SafeArtifact."}</span></li>
            </ul>
        </div>;
    }
    segs = insp.segments;
    hidden = [s for s in segs if isHiddenChannel(s)];
    quarantined = len([s for s in segs if s.quarantined]);
    showBody = showOriginal or insp.trace.released;
    return <div key={insp.ref} className="lb-fade flex min-w-0 flex-col">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line pb-2">
            <span className="font-mono text-micro font-semibold text-fg-3">{"GET"}</span>
            <UrlText url={insp.url} className="min-w-0 truncate text-meta" />
            <DecisionTag decision={insp.trace.decision} />
            <span className="ml-auto font-mono text-micro text-fg-3 tabular">
                {str(len(segs)) + " segments"}
                {quarantined > 0 and <span className="tone-hostile">{"  " + str(quarantined) + " quarantined"}</span>}
            </span>
        </div>
        {len(segs) == 0 and <p className="pt-4 text-body text-fg-2">{"No content was released for display."}</p>}
        {(not showOriginal and not insp.trace.released) and <div className="mt-3 border-l-2 border-hostile bg-hostile/10 px-3 py-2 text-body">
            <p className="font-semibold tone-hostile">{"Content blocked"}</p>
            <p className="text-fg-2">{"No context from this page was released to the agent. Switch to Original to inspect what was received."}</p>
        </div>}
        <div className="flex flex-col pt-1">
            {for s in (segs if showBody else []) {
                if s.quarantined {
                    <div key={s.sid} className="my-1.5 border-l-2 border-hostile bg-hostile/[0.08] py-1.5 pr-3 pl-3">
                        <div className="flex flex-wrap items-center gap-x-2 font-mono text-micro">
                            <span className="font-semibold tone-hostile">{"✕ QUARANTINED"}</span>
                            <span className="text-fg-3">{str(s.sid) + " / " + str(s.channel)}</span>
                            <span className="ml-auto text-fg-3">{"not sent to agent"}</span>
                        </div>
                        {showOriginal and <p className="mt-0.5 font-mono text-meta break-words text-hostile line-through decoration-hostile/60">{s.text}</p>}
                        {not showOriginal and <p className="mt-0.5 font-mono text-meta text-fg-3">{"[hostile span withheld. Switch to Original to inspect]"}</p>}
                    </div>
                } elif s.channel == "title" {
                    <div key={s.sid} className="grid grid-cols-[2.5rem_minmax(0,1fr)] gap-2 pt-2 pb-1">
                        <span className="pt-0.5 font-mono text-micro text-fg-3">{s.sid}</span>
                        <p className="text-title font-semibold text-fg">{s.text}</p>
                    </div>
                } elif s.channel == "visible" {
                    <div key={s.sid} className="grid grid-cols-[2.5rem_minmax(0,1fr)] gap-2 py-0.5">
                        <span className="pt-1 font-mono text-micro text-fg-3">{s.sid}</span>
                        <p className="max-w-[75ch] text-read text-fg/90">{s.text}</p>
                    </div>
                }
            }}
        </div>
        {(showOriginal and len(hidden) > 0) and <details className="lb-section mt-3 border border-line">
            <summary>
                <span>{"Hidden channels and metadata"}</span>
                <span className="font-mono text-micro font-normal text-fg-3">{str(len(hidden)) + " segments, inspected but not shown on the page"}</span>
            </summary>
            <div className="flex flex-col py-1">
                {for s in hidden {
                    <div key={s.sid} className="lb-cv grid grid-cols-[2.5rem_6rem_minmax(0,1fr)] gap-2 px-3 py-0.5 font-mono text-micro">
                        <span className="text-fg-3">{s.sid}</span>
                        <span className="text-fg-3">{s.channel}</span>
                        <span className="break-all text-fg-2">{s.text}</span>
                    </div>
                }}
            </div>
        </details>}
        {len(insp.facts) > 0 and <div className="mt-3 border border-line bg-surface">
            <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-1.5">
                <span className="text-meta font-semibold text-fg">{"Typed extraction"}</span>
                <span className="font-mono text-micro text-fg-3">{"provenance UNTRUSTED_WEB"}</span>
            </div>
            <ul className="flex flex-col gap-0.5 px-3 py-2">
                {for fct in insp.facts {
                    <li key={JSON.stringify(fct)}><code className="font-mono text-micro break-all text-fg-2">{JSON.stringify(fct)}</code></li>
                }}
            </ul>
        </div>}
    </div>;
}

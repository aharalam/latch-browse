"""Shared top bar: brand, route tabs, and runtime status reported by the page.

Status items are passed in by each page from data it actually loaded;
the bar never invents a state of its own."""

import from "@jac/runtime" { Link, useLocation }

glob NAV_ITEMS: list[dict] = [
    {"label": "Research", "to": "/"},
    {"label": "Review console", "to": "/console"},
    {"label": "Attack lab", "to": "/lab"}
];

"""The latch mark: a keeper with the bolt thrown across it."""
def:pub LatchMark(className: str = "") -> JsxElement {
    return <svg viewBox="0 0 20 20" className={className} aria-hidden="true" fill="none">
        <rect x="1.5" y="4.5" width="11" height="11" rx="1.5" stroke="currentColor" strokeWidth="1.6" />
        <rect x="6" y="8.4" width="12.5" height="3.2" rx="0.8" fill="currentColor" />
    </svg>;
}

"""One status readout: small key, mono value, tone marker."""
def:pub StatusItem(label: str, value: str, tone: str = "idle") -> JsxElement {
    dot = "bg-safe" if tone == "safe" else ("bg-warn" if tone == "warn" else ("bg-hostile" if tone == "hostile" else "bg-idle"));
    return <div className="flex items-center gap-1.5 whitespace-nowrap">
        <span className={"size-1.5 rounded-full " + dot} aria-hidden="true" />
        <span className="text-meta text-fg-3">{label}</span>
        <span className="font-mono text-micro text-fg">{value}</span>
    </div>;
}

def:pub AppNav(status: list[dict] | None = None) -> JsxElement {
    items: list[dict] = status or [];
    path = useLocation().pathname.rstrip("/") or "/";   # /console/ on static hosting
    return <header className="sticky top-0 z-30 border-b border-line bg-canvas">
        <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-1 focus:left-1 focus:z-50 focus:rounded-md focus:bg-brand focus:px-3 focus:py-1.5 focus:text-brand-ink">{"Skip to main content"}</a>
        <div className="flex h-11 items-center gap-2 pr-4 pl-3">
            <Link to="/" className="flex shrink-0 items-center gap-2 rounded-sm pr-2" aria-label="LatchBrowse home">
                <LatchMark className="size-5 text-brand" />
                <span translate="no" className="hidden text-title font-semibold tracking-tight sm:inline">{"LatchBrowse"}</span>
            </Link>
            <span className="hidden border-l border-line pl-3 text-meta text-fg-3 2xl:inline">{"The web can inform your agent. Not control it."}</span>
            <nav aria-label="Primary" className="ml-1 flex min-w-0 items-center overflow-x-auto border-l border-line pl-1 sm:ml-2">
                {for item in NAV_ITEMS {
                    <Link
                        key={item["to"]}
                        to={item["to"]}
                        className="lb-navlink"
                        aria-current={"page" if path == item["to"] else None}
                    >
                        {item["label"]}
                    </Link>
                }}
            </nav>
            {len(items) > 0 and <div className="ml-auto hidden items-center gap-4 md:flex" aria-label="System status" role="group">
                {for s in items {
                    <StatusItem key={str(s["label"])} label={str(s["label"])} value={str(s["value"])} tone={str(s["tone"] or "idle")} />
                }}
            </div>}
        </div>
    </header>;
}

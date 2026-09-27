"""Shared top bar: brand, tagline, route tabs, guard runtime status."""

import from "@jac/runtime" { Link, useLocation }
import from "@hugeicons/react" { HugeiconsIcon }
import from "@hugeicons/core-free-icons" { LockIcon }

glob NAV_ITEMS: list[dict] = [
    {"label": "Research", "to": "/", "key": "01"},
    {"label": "IT Review Console", "to": "/console", "key": "02"},
    {"label": "Attack Lab", "to": "/lab", "key": "03"}
];

def:pub AppNav(status: str = "", statusTone: str = "muted") -> JsxElement {
    path = useLocation().pathname.rstrip("/") or "/";   # /console/ on static hosting
    dot = "bg-emerald-400" if statusTone == "ok" else ("bg-orange-400" if statusTone == "warn" else "bg-zinc-500");
    return <header className="sticky top-0 z-30 border-b border-border bg-background/95 backdrop-blur">
        <div className="flex h-12 items-center gap-4 pl-4 pr-4">
            <Link to="/" className="flex items-center gap-2 shrink-0">
                <div className="flex size-6 items-center justify-center rounded-sm bg-primary text-primary-foreground">
                    <HugeiconsIcon icon={LockIcon} strokeWidth={2.2} className="size-3.5" />
                </div>
                <span className="text-sm font-semibold tracking-tight">{"LatchBrowse"}</span>
            </Link>
            <span className="hidden lg:inline text-xs text-muted-foreground border-l border-border pl-4">{"The web can inform your agent. Not control it."}</span>
            <nav className="ml-auto flex items-center gap-0.5 overflow-x-auto">
                {for item in NAV_ITEMS {
                    <Link
                        key={item["to"]}
                        to={item["to"]}
                        className={"flex items-center gap-1.5 rounded-sm pt-1.5 pb-1.5 pl-2.5 pr-2.5 text-xs font-medium transition-colors whitespace-nowrap " + ("bg-secondary text-foreground" if path == item["to"] else "text-muted-foreground hover:text-foreground hover:bg-secondary/60")}
                    >
                        <span className="font-mono text-[10px] text-primary">{item["key"]}</span>
                        <span>{item["label"]}</span>
                    </Link>
                }}
            </nav>
            {status and <div className="hidden md:flex items-center gap-2 border-l border-border pl-4 font-mono text-[11px] text-muted-foreground">
                <span className={"size-1.5 rounded-full " + dot} />
                <span className="uppercase">{status}</span>
            </div>}
        </div>
    </header>;
}

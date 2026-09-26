"""Small security-state primitives. State is always text + marker, never color alone."""

def:pub severityClass(level: str) -> str {
    lv = level.upper();
    if lv == "CRITICAL" { return "text-red-400 border-red-500/50 bg-red-500/10"; }
    if lv == "HIGH" { return "text-orange-400 border-orange-500/50 bg-orange-500/10"; }
    if lv == "MEDIUM" { return "text-amber-300 border-amber-400/40 bg-amber-400/10"; }
    if lv == "NONE" or lv == "RELEASED" or lv == "PASS" { return "text-emerald-400 border-emerald-500/40 bg-emerald-500/10"; }
    return "text-zinc-400 border-zinc-600 bg-zinc-500/10";
}

def:pub decisionClass(decision: str) -> str {
    d = decision.upper();
    if d == "BLOCKED" or d == "BLOCK" { return "text-red-400 border-red-500/50 bg-red-500/10"; }
    if d == "SANITIZED" or d == "SANITIZE" { return "text-orange-400 border-orange-500/50 bg-orange-500/10"; }
    if d == "RELEASED" or d == "PASS" { return "text-emerald-400 border-emerald-500/40 bg-emerald-500/10"; }
    return "text-zinc-400 border-zinc-600 bg-zinc-500/10";
}

def:pub marker(level: str) -> str {
    lv = level.upper();
    if lv == "CRITICAL" { return "!!!"; }
    if lv == "HIGH" { return "!!"; }
    if lv == "MEDIUM" { return "!"; }
    if lv == "BLOCKED" or lv == "BLOCK" { return "x"; }
    if lv == "SANITIZED" or lv == "SANITIZE" { return "~"; }
    if lv == "RELEASED" or lv == "PASS" or lv == "NONE" { return "ok"; }
    return "-";
}

def:pub StateTag(label: str, tone: str = "") -> JsxElement {
    cls = severityClass(tone or label);
    return <span className={"inline-flex items-center gap-1 rounded-sm border pl-1.5 pr-1.5 font-mono text-[10px] font-semibold uppercase leading-5 tracking-wide " + cls}>
        <span aria-hidden="true">{marker(tone or label)}</span>
        <span>{label}</span>
    </span>;
}

def:pub DecisionTag(decision: str) -> JsxElement {
    return <span className={"inline-flex items-center gap-1 rounded-sm border pl-1.5 pr-1.5 font-mono text-[10px] font-semibold uppercase leading-5 tracking-wide " + decisionClass(decision)}>
        <span aria-hidden="true">{marker(decision)}</span>
        <span>{decision or "PENDING"}</span>
    </span>;
}

def:pub fmtTime(ts: float) -> str {
    if ts <= 0 { return "--:--:--"; }
    d = new(Date, ts * 1000);
    return pad2(int(d.getHours())) + ":" + pad2(int(d.getMinutes())) + ":" + pad2(int(d.getSeconds()));
}

def:pub pad2(n: int) -> str {
    return ("0" + str(n)) if n < 10 else str(n);
}

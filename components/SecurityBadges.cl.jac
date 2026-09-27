"""Small security-state primitives. State is always text + marker, never color alone."""

"""Map a severity / decision / review value to a semantic tone:
hostile (red), warn (orange), safe (green) or idle (gray)."""
def:pub toneOf(value: str) -> str {
    v = value.upper();
    if v in ["CRITICAL", "HIGH", "BLOCKED", "BLOCK", "HUMAN_FLAGGED", "FLAGGED", "HUMAN FLAGGED", "FAILED"] { return "hostile"; }
    if v in ["MEDIUM", "SANITIZED", "SANITIZE", "LOW"] { return "warn"; }
    if v in ["NONE", "RELEASED", "PASS", "PASSED", "OK"] { return "safe"; }
    return "idle";
}

"""Text-color class for a severity or decision value."""
def:pub severityClass(level: str) -> str {
    return "tone-" + toneOf(level);
}

"""Glyph that repeats the tone in shape, for color-independent reading."""
def:pub marker(level: str) -> str {
    lv = level.upper();
    if lv == "CRITICAL" { return "▲▲"; }
    if lv == "HIGH" { return "▲"; }
    if lv == "MEDIUM" { return "◆"; }
    if lv == "LOW" { return "◇"; }
    if lv in ["BLOCKED", "BLOCK", "HUMAN_FLAGGED", "FLAGGED", "HUMAN FLAGGED", "FAILED"] { return "✕"; }
    if lv in ["SANITIZED", "SANITIZE"] { return "◐"; }
    if lv in ["RELEASED", "PASS", "PASSED", "NONE", "OK"] { return "✓"; }
    return "○";
}

def:pub StateTag(label: str, tone: str = "") -> JsxElement {
    key = tone or label;
    return <span className="lb-tag" data-tone={toneOf(key)}>
        <span aria-hidden="true">{marker(key)}</span>
        <span>{label}</span>
    </span>;
}

def:pub DecisionTag(decision: str) -> JsxElement {
    shown = decision or "PENDING";
    return <span className="lb-tag" data-tone={toneOf(shown)}>
        <span aria-hidden="true">{marker(shown)}</span>
        <span>{shown}</span>
    </span>;
}

"""Inline severity: marker + level as colored mono text (for dense table cells)."""
def:pub SeverityText(level: str) -> JsxElement {
    return <span className={"inline-flex items-center gap-1.5 font-mono font-semibold " + severityClass(level)}>
        <span aria-hidden="true" className="inline-block w-4 text-center text-micro">{marker(level)}</span>
        <span>{level}</span>
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

"""Split a URL into host and the rest, for two-weight URL presentation."""
def:pub splitUrl(url: str) -> list[str] {
    rest = url.replace("https://", "").replace("http://", "");
    cut = rest.find("/");
    if cut < 0 { return [rest, ""]; }
    return [rest[:cut], rest[cut:]];
}

def:pub UrlText(url: str, className: str = "") -> JsxElement {
    parts = splitUrl(url);
    return <span className={"font-mono " + className} title={url}>
        <span className="text-fg">{parts[0]}</span>
        <span className="text-fg-3">{parts[1]}</span>
    </span>;
}

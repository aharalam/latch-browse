"""LatchBrowse Python Security Core - pipeline controller.

process_page(raw, url, intent)            -> GuardOutput
process_search_results(results, intent)   -> (list[SafeSearchResult], list[findings], trace)

Two strictly separate output channels:
  * SafeArtifact     - the ONLY thing downstream reasoning may consume.
  * SecurityFinding  - review data for the IT console / audit. Never flows to
                       the Summary Agent.

Plus a `trace` of layer statuses (no payload text) for the research UI, and a
`view` of segments for the live content viewer (shown to the user who
retrieved the page, never passed to any model).

Every security-model failure FAILS CLOSED: decision BLOCK, no content released.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from . import constrain
from .critic import CriticIsolationError, build_critic_input, critique
from .detect import detect
from .gemini import GuardModelError, model_available
from .isolate import TRUST_UNTRUSTED, isolate_page, isolate_search_results


@dataclass
class SafeArtifact:
    artifact_id: str
    source: str
    provenance: str
    decision: str
    sanitized_content: str
    structured_data: list[dict[str, Any]]
    capabilities: dict[str, list[str]]
    links: list[str] = field(default_factory=list)


@dataclass
class SecurityFinding:
    finding_id: str
    artifact_id: str
    url: str
    detected_at: float
    risk: str
    classification: str
    attack_categories: list[str]
    suspicious_spans: list[dict[str, str]]
    guard_decision: str
    critic_decision: str
    confidence: float
    explanation: str
    layer_results: dict[str, str]
    sanitized_preview: str
    capabilities: dict[str, list[str]]
    review_status: str = "PENDING_REVIEW"


def _risk(categories: list[str], conf: float, decision: str) -> str:
    severe = {"exfiltration", "tool_abuse", "guard_manipulation"}
    if decision == "BLOCK" and (set(categories) & severe):
        return "CRITICAL"
    if set(categories) & severe or conf >= 0.85:
        return "HIGH"
    if conf >= 0.5:
        return "MEDIUM"
    return "LOW"


def _fail_closed(url: str, reason: str) -> dict[str, Any]:
    aid = "art_" + secrets.token_hex(6)
    art = SafeArtifact(aid, url, TRUST_UNTRUSTED, "BLOCK", "", [], constrain.assign_capabilities("BLOCK", False))
    finding = SecurityFinding(
        finding_id="fnd_" + secrets.token_hex(6), artifact_id=aid, url=url, detected_at=time.time(),
        risk="HIGH", classification="Guard Unavailable", attack_categories=["guard_failure"],
        suspicious_spans=[], guard_decision="ERROR", critic_decision="NOT_RUN", confidence=0.0,
        explanation=f"Security model failure; content not released. ({reason[:160]})",
        layer_results={"L1": "FRAMED", "L2": "ERROR", "L3": "NO CAPABILITIES", "L4": "NOT RUN"},
        sanitized_preview="", capabilities=art.capabilities,
    )
    return {
        "artifact": asdict(art), "finding": asdict(finding), "view": [],
        "trace": {"L1": "FRAMED", "L2": "GUARD UNAVAILABLE", "L3": "NO CAPABILITIES",
                  "L4": "NOT RUN", "decision": "BLOCK", "released": False,
                  "engine": "unavailable", "threat": "UNKNOWN", "categories": [],
                  "confidence": 0.0, "note": "GUARD UNAVAILABLE - CONTENT NOT RELEASED"},
    }


def _extract_links(raw: str, limit: int = 8) -> list[str]:
    import re
    out: list[str] = []
    for m in re.finditer(r'href=["\'](https?://[^"\'\s<>]{4,300})["\']', raw or "", re.I):
        u = m.group(1)
        if u not in out:
            out.append(u)
        if len(out) >= limit:
            break
    return out


def process_page(raw: str, url: str, intent: dict, is_html: bool = True) -> dict[str, Any]:
    # ---- Layer 1
    content = isolate_page(raw, url, is_html=is_html)
    if not content.segments:
        return _fail_closed(url, "no extractable content")
    # ---- Layer 2
    try:
        det = detect(content, intent)
    except GuardModelError as exc:
        return _fail_closed(url, str(exc))
    except Exception as exc:  # any unexpected error also fails closed
        return _fail_closed(url, f"detector error: {exc}")

    quarantined = {sp.sid for sp in det.spans}
    # ---- Layer 3
    caps = constrain.assign_capabilities(det.decision, next_link_allowed=True)
    # ---- Layer 4 (isolated: only intent + enum claim + decision + caps)
    try:
        crit_in = build_critic_input(intent, det.claim, det.decision, caps)
        crit = critique(crit_in)
    except Exception as exc:
        return _fail_closed(url, f"critic: {exc}")

    final = det.decision
    if not crit.agrees or crit.escalate:
        # Material disagreement between Layer 2 and Layer 4: FAIL CLOSED.
        # Nothing is released and a finding is escalated for human review.
        final = "BLOCK"
    caps = constrain.assign_capabilities(final, next_link_allowed=True)

    surviving = [s for s in content.segments
                 if s.sid not in quarantined and s.channel in ("visible", "title")]
    sanitized = "" if final == "BLOCK" else "\n".join(s.text for s in surviving)[:6000]
    facts = [] if final == "BLOCK" else constrain.extract_typed([s.text for s in surviving])
    # Never recover URLs from raw HTML after sanitization. Only unmodified,
    # inspected URL segments from a wholly approved page may be proposed.
    from urllib.parse import urlsplit
    links = []
    if final == 'PASS':
        for segment in content.segments:
            if segment.channel != 'url' or segment.sid in quarantined:
                continue
            try:
                parsed = urlsplit(segment.text)
                if (parsed.scheme in ('https', 'http') and parsed.hostname
                        and not parsed.username and not parsed.password
                        and not any(c.isspace() for c in segment.text)):
                    links.append(segment.text)
            except ValueError:
                continue
        links = list(dict.fromkeys(links))[:8]

    aid = "art_" + secrets.token_hex(6)
    art = SafeArtifact(aid, url, TRUST_UNTRUSTED, final, sanitized, facts, caps, links)

    l2 = "INJECTION DETECTED" if det.is_injection else "NO DIRECTIVE FOUND"
    l4 = "CROSS-CHECK PASSED" if crit.agrees else "DISAGREEMENT - ESCALATED"
    l3 = "BLOCKED - NO SINKS" if final == "BLOCK" else "SUMMARIZE / DISPLAY ONLY"
    trace = {
        "L1": f"FRAMED ({len(content.segments)} segments, nonce fence)",
        "L2": l2, "L3": l3, "L4": l4, "decision": {"PASS": "RELEASED", "SANITIZE": "SANITIZED", "BLOCK": "BLOCKED"}[final],
        "released": final != "BLOCK", "engine": det.engine,
        "threat": _risk(det.categories, det.confidence, final) if det.is_injection else "NONE",
        "categories": det.categories, "confidence": det.confidence,
        "note": crit.reason,
    }
    view = [{"sid": s.sid, "channel": s.channel, "text": s.text[:700],
             "quarantined": s.sid in quarantined} for s in content.segments[:80]]

    finding = None
    if det.is_injection or not crit.agrees:
        finding = asdict(SecurityFinding(
            finding_id="fnd_" + secrets.token_hex(6), artifact_id=aid, url=url, detected_at=time.time(),
            risk=_risk(det.categories, det.confidence, final),
            classification=(det.categories[0].replace("_", " ").title() if det.categories else "Cross-check Escalation"),
            attack_categories=det.categories,
            suspicious_spans=[{"sid": sp.sid, "category": sp.category, "excerpt": sp.excerpt} for sp in det.spans][:10],
            guard_decision=det.decision, critic_decision=("AGREE" if crit.agrees else f"DISAGREE -> {crit.recommended_decision}"),
            confidence=det.confidence, explanation=det.explanation or crit.reason,
            layer_results={"L1": trace["L1"], "L2": f"{l2} ({det.engine})", "L3": l3, "L4": f"{l4}: {crit.reason}"[:300]},
            sanitized_preview=sanitized[:600], capabilities=caps,
        ))
    return {"artifact": asdict(art), "finding": finding, "trace": trace, "view": view}


def process_search_results(results: list[dict], intent: dict) -> dict[str, Any]:
    """Search titles/snippets/URLs are untrusted too. A result whose fields
    carry a directive is withheld from the agent; clean ones become
    SafeSearchResults."""
    if not results:
        return {"safe_results": [], "findings": [], "trace": {"L2": "NO RESULTS", "engine": "n/a"}}
    content, owner = isolate_search_results(results)
    try:
        det = detect(content, intent)
        caps = constrain.assign_capabilities(det.decision, True)
        crit = critique(build_critic_input(intent, det.claim, det.decision, caps))
    except Exception as exc:
        return {"safe_results": [], "findings": [], "error": f"GUARD UNAVAILABLE: {str(exc)[:120]}",
                "trace": {"L2": "GUARD UNAVAILABLE", "engine": "unavailable", "released": False}}
    bad_idx = {owner[sp.sid] for sp in det.spans if sp.sid in owner}
    if not crit.agrees or crit.escalate or det.decision == 'BLOCK':
        bad_idx = set(range(len(results)))  # disagreement -> withhold everything flagged batch
    safe, findings = [], []
    for i, r in enumerate(results):
        if i in bad_idx:
            findings.append(asdict(SecurityFinding(
                finding_id="fnd_" + secrets.token_hex(6), artifact_id=f"search_{i}", url=str(r.get("url", ""))[:300],
                detected_at=time.time(), risk=_risk(det.categories, det.confidence, "BLOCK"),
                classification="Search Result Injection", attack_categories=det.categories,
                suspicious_spans=[{"sid": sp.sid, "category": sp.category, "excerpt": sp.excerpt}
                                  for sp in det.spans if owner.get(sp.sid) == i],
                guard_decision="BLOCK", critic_decision="AGREE" if crit.agrees else "DISAGREE",
                confidence=det.confidence, explanation=det.explanation,
                layer_results={"L1": "FRAMED (search result fields)", "L2": f"INJECTION DETECTED ({det.engine})",
                               "L3": "WITHHELD FROM AGENT", "L4": crit.reason[:200]},
                sanitized_preview="", capabilities=constrain.assign_capabilities("BLOCK", False),
            )))
            continue
        safe.append({"index": i, "title": str(r.get("title", ""))[:200], "url": str(r.get("url", ""))[:400],
                     "snippet": str(r.get("snippet", ""))[:300], "provenance": TRUST_UNTRUSTED})
    return {"safe_results": safe, "findings": findings,
            "trace": {"L2": "INJECTION DETECTED" if det.is_injection else "CLEAN", "engine": det.engine,
                      "withheld": len(bad_idx), "released": bool(safe)}}


def guard_status() -> dict[str, Any]:
    return {"model": model_available(), "mode": "openai" if model_available() else "heuristic-degraded"}

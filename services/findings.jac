"""SecurityFinding store + IT Review Console endpoints.

Persistence: two small JSON files under LATCH_DATA_DIR (findings.json,
reviews.json), written atomically under a lock. Simple, survives page refresh
and server restart, and needs no database. On Cloud Run mount a volume or
swap for Firestore (README).

Privacy: a stored finding never contains the user's task, IntentContract, or
session id. FindingView has no field that could carry them.

Human review is METADATA ONLY. Nothing in the security pipeline or the agent
reads reviews.json; flagging changes no runtime behaviour.
"""

import json;
import os;
import time;
import threading;
import from urllib.parse { urlparse }
import from services.config { get_budgets }
import from services.models { FindingView }

glob _flock: threading.Lock = threading.Lock();

# Only these finding keys are ever persisted (allow-list, data minimization).
glob _FINDING_KEYS: list[str] = [
    "finding_id", "artifact_id", "url", "detected_at", "risk", "classification",
    "attack_categories", "suspicious_spans", "guard_decision", "critic_decision",
    "confidence", "explanation", "layer_results", "sanitized_preview", "capabilities"
];

def _path(name: str) -> str {
    d = get_budgets().data_dir;
    os.makedirs(d, exist_ok=True);
    return os.path.join(d, name);
}

def _read(name: str, fallback: any) -> any {
    p = _path(name);
    if not os.path.exists(p) {
        return fallback;
    }
    try {
        with open(p, "r", encoding="utf-8") as fh {
            return json.load(fh);
        }
    } except Exception {
        return fallback;
    }
}

def _write(name: str, data: any) -> None {
    p = _path(name);
    tmp = p + ".tmp";
    with open(tmp, "w", encoding="utf-8") as fh {
        json.dump(data, fh);
    }
    os.replace(tmp, p);
}

"""Persist a SecurityFinding from the security core. Returns its finding_id."""
def record_finding(finding: dict, origin: str) -> str {
    clean: dict = {};
    for k in _FINDING_KEYS {
        if k in finding {
            clean[k] = finding[k];
        }
    }
    clean["origin"] = origin;
    with _flock {
        items: list = _read("findings.json", []);
        last_seq: int = 100;
        if items {
            last_seq = int(items[len(items) - 1].get("seq", 100));
        }
        clean["seq"] = last_seq + 1;
        items.append(clean);
        _write("findings.json", items[-500:]);
    }
    return str(clean.get("finding_id", ""));
}

def _to_view(f: dict, reviews: dict) -> FindingView {
    url = str(f.get("url", ""));
    host = "";
    try {
        parsed = urlparse(url if "://" in url else "https://" + url);
        host = parsed.netloc or url;
    } except Exception {
        host = url[:80];
    }
    caps: dict = f.get("capabilities", {}) or {};
    rv: dict = reviews.get(str(f.get("finding_id", "")), {}) or {};
    return FindingView(
        finding_id=str(f.get("finding_id", "")),
        seq=int(f.get("seq", 0)),
        detected_at=float(f.get("detected_at", 0.0)),
        url=url,
        host=host,
        risk=str(f.get("risk", "LOW")),
        classification=str(f.get("classification", "")),
        attack_categories=list(f.get("attack_categories", [])),
        suspicious_spans=list(f.get("suspicious_spans", [])),
        guard_decision=str(f.get("guard_decision", "")),
        critic_decision=str(f.get("critic_decision", "")),
        confidence=float(f.get("confidence", 0.0)),
        explanation=str(f.get("explanation", "")),
        layer_results=dict(f.get("layer_results", {})),
        sanitized_preview=str(f.get("sanitized_preview", "")),
        allowed_sinks=list(caps.get("allowed", [])),
        forbidden_sinks=list(caps.get("forbidden", [])),
        trust="UNTRUSTED_WEB",
        origin=str(f.get("origin", "research")),
        review_status=str(rv.get("status", "PENDING_REVIEW")),
        reviewed_at=float(rv.get("at", 0.0))
    );
}

"""IT console feed. Newest first. Contains no user prompts."""
def:pub list_findings(refresh_token: float = 0.0) -> list[FindingView] {
    items: list = _read("findings.json", []);
    reviews: dict = _read("reviews.json", {});
    views = [_to_view(f, reviews) for f in items];
    views.reverse();
    return views;
}

"""Analyst marks a finding HUMAN_FLAGGED. Review metadata only - non-enforcing."""
def:pub flag_finding(finding_id: str) -> FindingView | None {
    with _flock {
        items: list = _read("findings.json", []);
        target: dict = {};
        for f in items {
            if str(f.get("finding_id", "")) == finding_id {
                target = f;
            }
        }
        if not target {
            return None;
        }
        reviews: dict = _read("reviews.json", {});
        reviews[finding_id] = {"status": "HUMAN_FLAGGED", "at": time.time()};
        _write("reviews.json", reviews);
        return _to_view(target, reviews);
    }
}

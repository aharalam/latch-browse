impl ReviewConsole.loadFindings -> None {
    loading = True;
    error = "";
    try {
        data = await list_findings();
        findings = data;
        if selectedId == "" and len(data) > 0 {
            selectedId = data[0].finding_id;
        }
    } except Exception as e {
        error = "Could not load findings.";
    }
    loading = False;
}

impl ReviewConsole.flagSelected -> None {
    if selectedId == "" { return; }
    flagging = True;
    try {
        updated = await flag_finding(selectedId);
        if updated {
            findings = [(updated if f.finding_id == selectedId else f) for f in findings];
            toast.success("Finding flagged as prompt injection");
        }
    } except Exception as e {
        toast.error("Could not flag finding");
    }
    flagging = False;
}

impl ReviewConsole.toggleSort(key: str) -> None {
    if sortKey == key {
        sortDesc = not sortDesc;
    } else {
        sortKey = key;
        sortDesc = True;
    }
}

impl ReviewConsole.visibleRows -> list[FindingView] {
    q = hostFilter.strip().lower();
    out: list[FindingView] = [];
    for f in findings {
        if q and q not in f.url.lower() and q not in f.host.lower() { continue; }
        if severityFilter != "ALL" and f.risk != severityFilter { continue; }
        if statusFilter != "ALL" and f.review_status != statusFilter { continue; }
        out.append(f);
    }
    def keyOf(f: FindingView) -> any {
        if sortKey == "seq" { return f.seq; }
        if sortKey == "host" { return f.host; }
        if sortKey == "risk" { return RISK_ORDER.get(f.risk, 0); }
        if sortKey == "class" { return f.classification; }
        if sortKey == "decision" { return f.guard_decision; }
        if sortKey == "status" { return f.review_status; }
        return f.detected_at;
    }
    out.sort(key=keyOf, reverse=sortDesc);
    return out;
}

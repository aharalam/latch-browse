impl ResearchWorkspace.loadStatus -> None {
    try {
        status = await guard_status();
    } except Exception as e {
        status = None;
    }
}

impl ResearchWorkspace.poll(sid: str, control: any) -> None {
    if control.cancelled { return; }
    try {
        s = await get_session(sid, Date.now());
        if control.cancelled { return; }
        if s {
            session = s;
            error = "";
            if s.status != "RUNNING" { return; }
        } else {
            error = "Research session is no longer available. Please start a new task.";
            sessionId = "";
            return;
        }
    } except Exception as e {
        if control.cancelled { return; }
        error = "Lost connection to the orchestrator. Retrying...";
    }
    control.timer = setTimeout(lambda { poll(sid, control); }, 1200);
}

impl ResearchWorkspace.startTask -> None {
    if requestState.current.busy or running { return; }
    if len(task.strip()) < 6 or len(task.strip()) > 600 {
        error = "Task must be between 6 and 600 characters.";
        return;
    }
    requestState.current.busy = True;
    starting = True;
    error = "";
    rateLimited = False;
    selectedRef = "";
    try {
        res = await start_research(task);
        if not requestState.current.mounted { return; }
        if res.ok {
            sessionId = res.session_id;
            session = None;
        } else {
            error = res.error;
        }
    } except Exception as e {
        if not requestState.current.mounted { return; }
        msg = str(e);
        if "429" in msg or "RATE_LIMITED" in msg or "limit" in msg.lower() {
            rateLimited = True;
        } else {
            error = "Could not start research: " + msg;
        }
    } finally {
        requestState.current.busy = False;
        if requestState.current.mounted { starting = False; }
    }
}

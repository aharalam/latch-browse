impl ResearchWorkspace.loadStatus -> None {
    try {
        status = await guard_status();
    } except Exception as e {
        status = None;
    }
}

impl ResearchWorkspace.stopPolling -> None {
    if pollTimer {
        clearInterval(pollTimer);
        pollTimer = None;
    }
}

impl ResearchWorkspace.poll -> None {
    if sessionId == "" { return; }
    try {
        s = await get_session(sessionId);
        if s {
            session = s;
            if s.status != "RUNNING" {
                stopPolling();
            }
        }
    } except Exception as e {
        error = "Lost connection to the orchestrator.";
    }
}

impl ResearchWorkspace.startTask -> None {
    if len(task.strip()) < 6 { return; }
    stopPolling();
    starting = True;
    error = "";
    rateLimited = False;
    selectedRef = "";
    try {
        res = await start_research(task);
        if res.ok {
            sessionId = res.session_id;
            session = None;
            await poll();
            pollTimer = setInterval(lambda { poll(); }, 1200);
        } else {
            error = res.error;
        }
    } except Exception as e {
        msg = str(e);
        if "429" in msg or "RATE_LIMITED" in msg or "limit" in msg.lower() {
            rateLimited = True;
        } else {
            error = "Could not start research: " + msg;
        }
    }
    starting = False;
}

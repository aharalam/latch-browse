"""LatchBrowse entry: registers endpoints, installs the rate gate, mounts the router."""

import from services.ratelimit { install_rate_gate }
import from services.research { start_research, get_session, guard_status }
import from services.findings { list_findings, flag_finding }
import from services.attacklab { list_fixtures, run_attack_fixture }
import from services.models {
    SessionView, StartResult, GuardStatus, FindingView, FixtureInfo, ComparisonResult,
    TimelineEvent, PageInspection, GuardTrace, SegmentView, ValidationReport
}

cl {
import ".styles.global.css";
import from "@jac/runtime" { Router, Routes, Route }
import from .components.ResearchWorkspace { ResearchWorkspace }
import from .components.ReviewConsole { ReviewConsole }
import from .components.AttackLab { AttackLab }
import from .components.ui.sonner_toast { Toaster }

def:pub app() -> JsxElement {
    return <div className="dark bg-background text-foreground">
        <Router>
            <Routes>
                <Route path="/" element={<ResearchWorkspace />} />
                <Route path="/console" element={<ReviewConsole />} />
                <Route path="/lab" element={<AttackLab />} />
            </Routes>
        </Router>
        <Toaster theme="dark" position="bottom-right" />
    </div>;
}
}

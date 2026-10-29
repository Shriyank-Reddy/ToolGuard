"""Turn findings into scores and Low / Medium / High levels, and run a full scan."""
from dataclasses import dataclass, field

from . import config as C
from .checks import run_static_checks
from .lockfile import check_rug_pull
from .models import Finding, Server, Tool


def level_for(score: float) -> str:
    if score >= C.LEVEL_HIGH:
        return "High"
    return "Medium" if score >= C.LEVEL_MEDIUM else "Low"


def tool_score(findings: list[Finding]) -> float:
    """Per check, take the worst finding; add the checks up; cap at MAX_SCORE."""
    worst: dict[str, int] = {}
    for f in findings:
        worst[f.check] = max(worst.get(f.check, 0), C.SEVERITY_WEIGHT[f.severity])
    return float(min(sum(worst.values()), C.MAX_SCORE))


def server_score(tool_scores: list[float]) -> float:
    """Worst tool, plus 0.5 for every other Medium-or-worse tool."""
    if not tool_scores:
        return 0.0
    ordered = sorted(tool_scores, reverse=True)
    risky_others = sum(1 for s in ordered[1:] if s >= C.LEVEL_MEDIUM)
    return min(ordered[0] + 0.5 * risky_others, float(C.MAX_SCORE))


@dataclass
class ToolReport:
    name: str
    findings: list[Finding]
    score: float
    level: str


@dataclass
class ServerReport:
    name: str
    version: str
    tools: list[ToolReport]
    score: float
    level: str
    notes: list[Finding] = field(default_factory=list)  # e.g. removed tools

    def to_dict(self) -> dict:
        return {
            "server": self.name, "version": self.version, "score": self.score, "level": self.level,
            "tools": [{"name": t.name, "score": t.score, "level": t.level,
                       "findings": [f.to_dict() for f in t.findings]} for t in self.tools],
            "notes": [f.to_dict() for f in self.notes],
        }


def scan_tool(tool: Tool, rug_findings: list[Finding] = ()) -> ToolReport:
    findings = run_static_checks(tool) + list(rug_findings)
    score = tool_score(findings)
    return ToolReport(tool.name, findings, score, level_for(score))


def scan_server(server: Server, lock: dict | None = None) -> ServerReport:
    """Run checks 1-5 on every tool, plus check 6 when a lock is given."""
    rug = check_rug_pull(server, lock) if lock else []
    names = {t.name for t in server.tools}
    reports = [scan_tool(t, [f for f in rug if f.tool == t.name]) for t in server.tools]
    score = server_score([r.score for r in reports])
    return ServerReport(server.name, server.version, reports, score, level_for(score),
                        [f for f in rug if f.tool not in names])

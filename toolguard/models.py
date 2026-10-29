"""Plain data classes shared by every other module."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Tool:
    """One tool: a name, a description, an input schema and declared permissions."""

    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)

    def parameters(self) -> dict[str, dict]:
        """Return {parameter name: parameter schema}."""
        return (self.input_schema or {}).get("properties", {}) or {}

    def texts(self) -> list[tuple[str, str]]:
        """All human-readable text an AI model would see: (location, text) pairs."""
        out = [("description", self.description)]
        for pname, pschema in self.parameters().items():
            if isinstance(pschema, dict) and pschema.get("description"):
                out.append((f"param:{pname}", str(pschema["description"])))
        return out

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "permissions": self.permissions,
        }


@dataclass
class Server:
    """A named collection of tools (what an MCP server exposes)."""

    name: str
    tools: list[Tool]
    version: str = ""
    source: str = ""


@dataclass
class Finding:
    """One problem found in one tool, with a plain-English reason."""

    check: str  # e.g. "hidden_instructions"
    severity: str  # "low" | "medium" | "high"
    tool: str
    reason: str
    evidence: str = ""  # the suspicious text (used for highlighting)
    location: str = "description"

    @property
    def is_flag(self) -> bool:
        """Only medium/high findings count as a 'flag'; low is informational."""
        return self.severity in ("medium", "high")

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity,
            "tool": self.tool,
            "reason": self.reason,
            "evidence": self.evidence,
            "location": self.location,
        }

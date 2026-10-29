"""Check 6 (rug pull): fingerprint tool definitions, save them, and diff later.

A 'rug pull' is when a tool is approved while it looks safe and is changed afterwards.
We store a SHA-256 hash of each *normalized* tool definition in a lockfile. Normalizing
means formatting noise (whitespace, key order) cannot change the hash, but a real
change to the name, description, schema or permissions always does.
"""
import difflib
import hashlib
import json
from pathlib import Path

from . import config as C
from .checks import run_static_checks
from .models import Finding, Server, Tool

LOCK_VERSION = 1


# ------------------------------------------------------------ normalization
def normalize_text(text) -> str:
    """Collapse all runs of whitespace to one space and trim the ends."""
    return " ".join(str(text).split())


def _normalize_schema(obj, key=""):
    if isinstance(obj, dict):
        return {k: _normalize_schema(v, k) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        items = [_normalize_schema(v) for v in obj]
        return sorted(items, key=str) if key == "required" else items
    if key == "description" and isinstance(obj, str):
        return normalize_text(obj)
    return obj


def normalize_tool(tool: Tool) -> dict:
    """The parts of a tool that matter. (The server 'version' is deliberately left out.)"""
    return {
        "name": tool.name,
        "description": normalize_text(tool.description),
        "inputSchema": _normalize_schema(tool.input_schema or {}),
        "permissions": sorted(set(tool.permissions)),
    }


def fingerprint(definition: dict) -> str:
    blob = json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def tool_from_definition(definition: dict) -> Tool:
    return Tool(definition["name"], definition["description"], definition["inputSchema"], definition["permissions"])


# ----------------------------------------------------------------- lockfile
def create_lock(servers: list[Server]) -> dict:
    lock = {"toolguard_lock": LOCK_VERSION, "servers": {}}
    for server in servers:
        entries = {}
        for tool in server.tools:
            definition = normalize_tool(tool)
            entries[tool.name] = {"hash": fingerprint(definition), "definition": definition}
        lock["servers"][server.name] = {"version": server.version, "tools": entries}
    return lock


def save_lock(lock: dict, path) -> None:
    Path(path).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_lock(path) -> dict:
    lock = json.loads(Path(path).read_text(encoding="utf-8"))
    if lock.get("toolguard_lock") != LOCK_VERSION:
        raise ValueError(f"{path}: not a ToolGuard lockfile (version {LOCK_VERSION})")
    return lock


# --------------------------------------------------------------------- diff
def word_diff(old: str, new: str) -> str:
    """Inline diff such as 'Returns the [-old-] {+new+} forecast'."""
    a, b = old.split(), new.split()
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op == "equal":
            out.append(" ".join(a[i1:i2]))
            continue
        if i2 > i1:
            out.append("[-" + " ".join(a[i1:i2]) + "-]")
        if j2 > j1:
            out.append("{+" + " ".join(b[j1:j2]) + "+}")
    return " ".join(out)


def _params(definition: dict) -> dict:
    return definition["inputSchema"].get("properties", {}) or {}


def _is_minor(old: str, new: str) -> bool:
    """A typo-level edit: nearly identical text and almost no new text."""
    similarity = difflib.SequenceMatcher(None, old, new, autojunk=False).ratio()
    return similarity >= C.MINOR_EDIT_SIMILARITY and len(new) - len(old) <= C.MINOR_EDIT_MAX_GROWTH


def compare_definitions(old: dict, new: dict) -> tuple[str, list[str], str]:
    """Return (severity, short reasons, readable diff) for two different definitions.

    Policy (decided before evaluating):
      high   - permissions were added, or the new version trips checks 1-5 in a way the old one did not
      medium - parameters added/removed, schema changed, or the description was materially rewritten
      low    - typo-level wording edit, or permissions only reduced
    Formatting/whitespace/key-order/version-only changes never reach here (their hash is equal).
    """
    reasons, diff_lines, severity = [], [], "low"

    def raise_to(level):
        nonlocal severity
        severity = max(severity, level, key=["low", "medium", "high"].index)

    added_perms = sorted(set(new["permissions"]) - set(old["permissions"]))
    removed_perms = sorted(set(old["permissions"]) - set(new["permissions"]))
    if added_perms:
        reasons.append(f"new permissions: {', '.join(added_perms)}")
        diff_lines.append(f"permissions: {{+{', '.join(added_perms)}+}}")
        raise_to("high")
    if removed_perms:
        reasons.append(f"permissions removed: {', '.join(removed_perms)}")
        diff_lines.append(f"permissions: [-{', '.join(removed_perms)}-]")

    if old["description"] != new["description"]:
        diff_lines.append("description: " + word_diff(old["description"], new["description"]))
        if _is_minor(old["description"], new["description"]):
            reasons.append("small wording change in the description")
        else:
            reasons.append("description was rewritten")
            raise_to("medium")

    old_p, new_p = _params(old), _params(new)
    for name in sorted(set(new_p) - set(old_p)):
        reasons.append(f"new parameter '{name}'")
        diff_lines.append(f"param {name}: {{+added: {new_p[name].get('description', '')}+}}")
        raise_to("medium")
    for name in sorted(set(old_p) - set(new_p)):
        reasons.append(f"parameter '{name}' removed")
        diff_lines.append(f"param {name}: [-removed-]")
        raise_to("medium")
    for name in sorted(set(old_p) & set(new_p)):
        o, n = old_p[name], new_p[name]
        if o == n:
            continue
        od, nd = o.get("description", ""), n.get("description", "")
        if {k: v for k, v in o.items() if k != "description"} != {k: v for k, v in n.items() if k != "description"}:
            reasons.append(f"parameter '{name}' changed type or constraints")
            raise_to("medium")
        if od != nd:
            diff_lines.append(f"param {name}: " + word_diff(od, nd))
            if _is_minor(od, nd):
                reasons.append(f"small wording change in parameter '{name}'")
            else:
                reasons.append(f"description of parameter '{name}' was rewritten")
                raise_to("medium")
    if old["inputSchema"].get("required") != new["inputSchema"].get("required"):
        reasons.append("required parameters changed")
        raise_to("medium")

    # Did the change introduce something checks 1-5 now catch?
    key = lambda f: (f.check, f.evidence)  # noqa: E731
    before = {key(f) for f in run_static_checks(tool_from_definition(old)) if f.is_flag}
    fresh = [f for f in run_static_checks(tool_from_definition(new)) if f.is_flag and key(f) not in before]
    if fresh:
        names = sorted({f.check.replace("_", " ") for f in fresh})
        reasons.append("the new version now trips: " + ", ".join(names))
        raise_to("high")
    return severity, reasons, "\n".join(diff_lines)


def check_rug_pull(server: Server, lock: dict) -> list[Finding]:
    """Compare a server with its lockfile entry. Returns rug_pull findings."""
    entry = lock.get("servers", {}).get(server.name)
    if entry is None:
        return []  # never locked: nothing to compare against
    findings, current = [], {t.name: t for t in server.tools}
    for name, tool in current.items():
        definition = normalize_tool(tool)
        locked = entry["tools"].get(name)
        if locked is None:
            findings.append(Finding("rug_pull", "low", name, "New tool that was not present when the server was locked.",
                                    "", "tool"))
        elif fingerprint(definition) != locked["hash"]:
            severity, reasons, diff = compare_definitions(locked["definition"], definition)
            findings.append(Finding("rug_pull", severity, name,
                                    "Changed since it was locked: " + "; ".join(reasons) + ".", diff, "tool"))
    for name in entry["tools"]:
        if name not in current:
            findings.append(Finding("rug_pull", "low", name, "Tool was removed since the server was locked.", "", "tool"))
    return findings

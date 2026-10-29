"""Read tool-definition JSON files into Server / Tool objects."""
import json
from pathlib import Path

from .models import Server, Tool


def parse_server(data: dict, source: str = "") -> Server:
    if not isinstance(data, dict) or "tools" not in data:
        raise ValueError(f"{source or 'input'}: expected an object with a 'tools' list")
    tools = []
    for raw in data["tools"]:
        if "name" not in raw:
            raise ValueError(f"{source or 'input'}: every tool needs a 'name'")
        tools.append(Tool(
            name=raw["name"],
            description=raw.get("description", "") or "",
            input_schema=raw.get("inputSchema") or raw.get("input_schema") or {},
            permissions=list(raw.get("permissions", []) or []),
        ))
    return Server(name=data.get("server") or data.get("name") or Path(source).stem or "unnamed",
                  tools=tools, version=str(data.get("version", "")), source=source)


def load_server(path) -> Server:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise ValueError(f"{path}: not valid JSON ({err})") from err
    return parse_server(data, str(path))


def load_path(path) -> list[Server]:
    """Load one server file, or every *.json file directly inside a folder."""
    path = Path(path)
    if path.is_dir():
        files = sorted(path.glob("*.json"))
        if not files:
            raise ValueError(f"{path}: no .json files found")
        return [load_server(f) for f in files]
    return [load_server(path)]

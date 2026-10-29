"""Small helpers shared by the two data generators."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def make_tool(name, desc, params="", perms=""):
    """Build a tool dict from compact strings.

    params: "city:string:City name;units?:string:metric or imperial"  ('?' = optional)
    perms:  "file:read,file:write"
    """
    props, required = {}, []
    for chunk in filter(None, params.split(";")):
        pname, ptype, pdesc = chunk.split(":", 2)
        if pname.endswith("?"):
            pname = pname[:-1]
        else:
            required.append(pname)
        props[pname] = {"type": ptype, "description": pdesc}
    return {
        "name": name,
        "description": desc,
        "inputSchema": {"type": "object", "properties": props, "required": required},
        "permissions": [p for p in perms.split(",") if p],
    }


def make_server(name, tools, version="1.0.0"):
    return {"server": name, "version": version, "tools": tools}


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

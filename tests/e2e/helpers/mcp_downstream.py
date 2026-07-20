"""A minimal, self-contained downstream MCP server for the gateway `wrap` e2e tests.

Speaks MCP JSON-RPC over stdio (initialize / tools/list / tools/call). It is the
server the gateway wraps, so it is the TRIPWIRE: every `tools/call` that actually
reaches it appends one line to the file named by ``AUTHS_TRIPWIRE``. A refused call
never reaches the downstream, so the tripwire line count is exactly the number of
calls the gateway FORWARDED — the ground truth every gate-bounds test asserts against.

It advertises the reference filesystem-server tool family (read + write) so the
capability map (`fs.read` / `fs.write`) and the scope boundary can be exercised.
No real filesystem access — each tool returns a deterministic stub so the tests stay
hermetic. A metered call (`_auths_cost_cents` + `_auths_rail` in its arguments) is
echoed straight back; the gateway meters it from those declared fields.
"""

import json
import os
import sys

READ_TOOLS = [
    "read_file",
    "read_text_file",
    "read_media_file",
    "read_multiple_files",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "get_file_info",
    "search_files",
]
WRITE_TOOLS = ["write_file", "edit_file", "create_directory", "move_file"]


def _tripwire(tool: str) -> None:
    """Record that a call actually reached the downstream (the gateway forwarded it)."""
    path = os.environ.get("AUTHS_TRIPWIRE")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(tool + "\n")


def _tool_defs():
    defs = []
    for name in READ_TOOLS:
        defs.append({
            "name": name,
            "description": f"{name} (read family)",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": True},
        })
    for name in WRITE_TOOLS:
        defs.append({
            "name": name,
            "description": f"{name} (write family)",
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": False},
        })
    return defs


def _handle(msg):
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": mid,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "e2e-downstream", "version": "0"},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": _tool_defs()}}
    if method == "tools/call":
        params = msg.get("params", {})
        tool = params.get("name", "")
        args = params.get("arguments", {}) or {}
        _tripwire(tool)
        # A metered downstream echoes the declared cost so the gateway meters it; a plain
        # read/write returns a deterministic stub. Either way the body is one text block.
        body = {"tool": tool, "ok": True}
        if "_auths_cost_cents" in args:
            body["cost_cents"] = args["_auths_cost_cents"]
        return {
            "jsonrpc": "2.0", "id": mid,
            "result": {"content": [{"type": "text", "text": json.dumps(body)}]},
        }
    if mid is not None:
        return {
            "jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reply = _handle(msg)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

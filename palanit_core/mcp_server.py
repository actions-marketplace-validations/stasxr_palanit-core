"""PALANIT as an MCP server.

Exposes the Palanit Core scanner as Model Context Protocol tools, so an agent (or
an MCP client like Claude Desktop / Cursor / Cline) can scan a config on demand.

Requires the optional dependency:  pip install "palanit-core[mcp]"
Run:  palanit-mcp     (stdio transport)
"""
from __future__ import annotations

import json
from typing import Any

from . import __version__
from .engine import scan_data


def _server_class():
    """Return the MCP server class across SDK versions.

    mcp 2.x renamed FastMCP -> MCPServer; mcp 1.x uses FastMCP. The decorator
    (`.tool()`) and `.run()` ergonomics are the same, so either works here.
    """
    try:
        from mcp.server.mcpserver import MCPServer  # mcp >= 2.0

        return MCPServer
    except Exception:
        pass
    try:
        from mcp.server.fastmcp import FastMCP  # mcp 1.x

        return FastMCP
    except Exception as exc:  # pragma: no cover - optional dep missing
        raise SystemExit(
            "The MCP server needs the optional 'mcp' dependency.\n"
            "Install it with:  pip install \"palanit-core[mcp]\"\n"
            f"(import error: {exc})"
        )


def _build():
    mcp = _server_class()("palanit")

    @mcp.tool()
    def scan_mcp_config(config: str) -> dict[str, Any]:
        """Scan an MCP server config or tool manifest for security issues.

        Pass the config as a JSON string (an object with "mcpServers"/"servers",
        or a "tools" array, or a single tool object). Returns findings with
        severity, location, evidence and remediation — the same engine as the
        Palanit Core CLI. Nothing is stored.
        """
        try:
            raw = json.loads(config)
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"invalid JSON: {exc}"}
        result = scan_data(raw, filename="mcp-tool-input.json")
        return {"ok": True, "result": result.to_dict()}

    @mcp.tool()
    def list_rules() -> list[dict[str, str]]:
        """List the detection rules Palanit Core applies."""
        from . import rules as rules_mod

        return [
            {"id": rid, "title": title}
            for rid, title, _fn in sorted(rules_mod.all_rules())
        ]

    @mcp.tool()
    def version() -> str:
        """Return the Palanit Core version."""
        return __version__

    return mcp


def main() -> None:
    _build().run()


if __name__ == "__main__":
    main()

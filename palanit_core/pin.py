"""Tool-definition pinning — defeats the post-approval description swap.

A scan at install time only sees the tool text you approved. A hostile server
can swap a tool's description (or input schema) *after* that approval — a
"rug pull" — and standard clients never re-check. PALANIT pins a hash of each
tool's declared text at approval time; a later scan with that baseline fails
*closed* on any change, so a swap costs the attacker the tool instead of
silently succeeding.

    palanit pin mcp.json                      # record the approved baseline
    palanit scan mcp.json --baseline .palanit.lock.json   # fail closed on drift
"""
from __future__ import annotations

import hashlib
import json

from .loaders import Normalized, ToolDef

LOCK_SCHEMA = "palanit.lock.v1"


def tool_key(t: ToolDef) -> str:
    """A stable identity for a tool across scans (server-scoped)."""
    name = t.name or t.path or "tool"
    return f"{t.server}::{name}" if t.server else name


def tool_hash(t: ToolDef) -> str:
    """SHA-256 over the canonical, declared definition a client would trust:
    the name, the description and the input schema."""
    payload = {"name": t.name, "description": t.description, "schema": t.schema or {}}
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def build_baseline(norm: Normalized) -> dict[str, str]:
    return {tool_key(t): tool_hash(t) for t in norm.tools}


def make_lock(norm: Normalized, core_version: str) -> dict:
    return {"schema": LOCK_SCHEMA, "core_version": core_version, "tools": build_baseline(norm)}


def load_lock(path: str) -> dict[str, str]:
    """Load a baseline. Accepts a full lock ({"tools": {...}}) or a bare
    {key: hash} map."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and isinstance(data.get("tools"), dict):
        data = data["tools"]
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}

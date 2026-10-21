"""Scan orchestration: load targets, run rules, collect findings."""
from __future__ import annotations

import json
import os

from . import rules as rules_mod
from .loaders import load_json, normalize, walk_strings
from .models import ScanResult


def scan_data(raw, filename: str = "<data>", baseline: dict | None = None) -> ScanResult:
    """Scan an already-parsed JSON structure.

    Pass `baseline` (a {tool_key: hash} map from `palanit pin`) to enable
    tool-definition drift detection — see palanit_core.pin.
    """
    result = ScanResult(targets=[filename])
    norm = normalize(raw)
    result.scanned_servers = len(norm.servers)
    result.scanned_tools = len(norm.tools)
    result.scanned_strings = len(walk_strings(raw))
    ctx = rules_mod.Context(norm=norm, filename=filename, baseline=baseline)
    for rule_id, _title, fn in rules_mod.all_rules():
        try:
            for finding in fn(ctx):
                result.add(finding)
        except Exception as exc:  # a broken rule must never crash the scan
            result.errors.append(f"rule {rule_id} failed: {exc}")
    return result


def scan_files(paths: list[str], baseline: dict | None = None) -> ScanResult:
    """Scan one or more JSON files, merging findings into one result."""
    merged = ScanResult()
    for path in paths:
        name = os.path.basename(path)
        merged.targets.append(path)
        try:
            raw = load_json(path)
        except FileNotFoundError:
            merged.errors.append(f"{name}: file not found")
            continue
        except json.JSONDecodeError as exc:
            merged.errors.append(f"{name}: invalid JSON ({exc})")
            continue
        sub = scan_data(raw, filename=name, baseline=baseline)
        merged.findings.extend(sub.findings)
        merged.scanned_servers += sub.scanned_servers
        merged.scanned_tools += sub.scanned_tools
        merged.scanned_strings += sub.scanned_strings
        merged.errors.extend(sub.errors)
    return merged

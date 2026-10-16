"""Render scan results for humans (ANSI) and machines (JSON)."""
from __future__ import annotations

import json
import sys

from .models import ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",  # white on red
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def _use_color(no_color: bool) -> bool:
    if no_color or "NO_COLOR" in __import__("os").environ:
        return False
    return sys.stdout.isatty()


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


def to_text(result: ScanResult, no_color: bool = False) -> str:
    color = _use_color(no_color)

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: list[str] = []
    lines.append(c(_BOLD, "PALANIT · agent surface scan"))
    lines.append(c(_DIM, "targets: " + ", ".join(result.targets or ["<none>"])))
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append(c("\033[92m", "✓ No findings. (This is not proof of safety — see docs.)"))
    else:
        for f in findings:
            badge = f" {f.severity.label:^8} "
            lines.append(c(_COLORS[f.severity], badge) + "  " + c(_BOLD, f.title) + c(_DIM, f"  [{f.rule_id}]"))
            lines.append(f"    {f.message}")
            if f.location:
                lines.append(c(_DIM, f"    ↳ {f.location}"))
            if f.evidence:
                lines.append(c(_DIM, f"    evidence: {f.evidence}"))
            lines.append(c("\033[92m", f"    fix: {f.remediation}"))
            lines.append("")

    counts = result.counts()
    summary = " · ".join(
        f"{counts[s.label]} {s.label.lower()}"
        for s in sorted(Severity, reverse=True)
        if counts[s.label]
    )
    lines.append(c(_DIM, "─" * 48))
    scanned = f"{result.scanned_servers} servers · {result.scanned_tools} tools · {result.scanned_strings} strings"
    lines.append(c(_DIM, f"scanned: {scanned}"))
    lines.append(
        c(_BOLD, f"{len(findings)} finding(s)") + (f"  ({summary})" if summary else "")
    )
    for err in result.errors:
        lines.append(c(_COLORS[Severity.MEDIUM], f"! {err}"))
    return "\n".join(lines)

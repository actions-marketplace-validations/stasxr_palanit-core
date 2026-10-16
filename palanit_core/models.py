"""Core data model for PALANIT scans: severities, findings and results."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity. Higher value == more severe (used for --fail-on)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        key = value.strip().upper()
        aliases = {"MED": "MEDIUM", "CRIT": "CRITICAL"}
        key = aliases.get(key, key)
        try:
            return cls[key]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown severity: {value!r}") from exc


@dataclass
class Finding:
    """A single detected issue."""

    rule_id: str
    severity: Severity
    title: str
    message: str
    remediation: str
    location: str = ""  # file + JSON path, e.g. mcp.json#/mcpServers/x/command
    evidence: str = ""  # short snippet of the offending value
    reference: str = ""  # optional URL or doc anchor

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class ScanResult:
    """The outcome of scanning one or more targets."""

    findings: list[Finding] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    scanned_strings: int = 0
    scanned_tools: int = 0
    scanned_servers: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def sorted_findings(self) -> list[Finding]:
        # most severe first, then by rule id for stable output
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.rule_id, f.location),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "palanit-core",
            "schema": "palanit.scan.v1",
            "targets": self.targets,
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts(),
                "max_severity": self.max_severity().label if self.max_severity() else None,
                "scanned_servers": self.scanned_servers,
                "scanned_tools": self.scanned_tools,
                "scanned_strings": self.scanned_strings,
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "errors": self.errors,
        }

"""PALANIT detection rules for MCP servers and agent tool manifests.

Every rule is small, readable and auditable on purpose: you should be able to
see exactly what PALANIT considers dangerous. Rules operate on a normalized
view of the target plus a raw walk of every string value.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from .loaders import Normalized, walk_strings
from .models import Finding, Severity
from .pin import tool_key, tool_hash


@dataclass
class Context:
    norm: Normalized
    filename: str
    baseline: dict | None = None  # approved {tool_key: hash}, enables drift detection

    def loc(self, path: str) -> str:
        path = path or "/"
        return f"{self.filename}#{path}"


Rule = Callable[[Context], list[Finding]]
REGISTRY: list[tuple[str, str, Rule]] = []  # (id, title, fn)


def rule(rule_id: str, title: str):
    def deco(fn: Rule) -> Rule:
        REGISTRY.append((rule_id, title, fn))
        return fn

    return deco


def _clip(s: str, n: int = 120) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[: n - 1] + "…"


# --------------------------------------------------------------------------
# Invisible / deceptive Unicode
# --------------------------------------------------------------------------
INVISIBLE = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "­": "SOFT HYPHEN",
}
BIDI = {
    "‪": "LRE", "‫": "RLE", "‬": "PDF",
    "‭": "LRO", "‮": "RLO",
    "⁦": "LRI", "⁧": "RLI", "⁨": "FSI", "⁩": "PDI",
}


@rule("PL-UNICODE-001", "Invisible or deceptive Unicode")
def r_unicode(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for path, value in walk_strings(ctx.norm.raw):
        hits: list[str] = []
        for ch, name in {**INVISIBLE, **BIDI}.items():
            if ch in value:
                hits.append(name)
        # Unicode tag characters (used to smuggle hidden ASCII)
        if any(0xE0000 <= ord(c) <= 0xE007F for c in value):
            hits.append("UNICODE TAG CHARACTERS")
        if hits:
            in_desc = "/description" in path or path.endswith("/description")
            sev = Severity.HIGH if in_desc else Severity.MEDIUM
            out.append(
                Finding(
                    rule_id="PL-UNICODE-001",
                    severity=sev,
                    title="Invisible or deceptive Unicode",
                    message=(
                        "This string contains hidden Unicode (" + ", ".join(sorted(set(hits)))
                        + ") that is invisible to a human reviewer but read by the model. "
                        "It is a common way to smuggle instructions past review."
                    ),
                    remediation="Remove the hidden characters; keep tool text to printable ASCII/UTF-8 you can see.",
                    location=ctx.loc(path),
                    evidence=_clip(value),
                )
            )
    return out


# --------------------------------------------------------------------------
# Tool-description poisoning / hidden instructions
# --------------------------------------------------------------------------
POISON_PATTERNS = [
    r"ignore (?:all |the )?(?:previous|above|prior|earlier) instructions",
    r"disregard (?:all |the )?(?:previous|above|prior) ",
    r"do not (?:tell|inform|mention to|reveal to) the user",
    r"without (?:telling|informing|notifying) the user",
    r"\byou must (?:always|also|first|now)\b",
    r"\balways (?:call|use|send|include|append|run)\b",
    r"\bbefore (?:using|calling|responding)[^.]{0,40}\byou (?:must|should)\b",
    r"<\s*(?:important|system|instructions?|secret)\s*>",
    r"\[\s*(?:system|important|hidden)\s*\]",
    r"\bsystem prompt\b",
    r"\boverride\b[^.]{0,30}\b(?:instructions|rules|policy)\b",
    r"\b(?:as an ai|assistant)[,:].{0,40}\b(?:ignore|instead)\b",
    r"\bthis is (?:a )?(?:mandatory|required) step\b",
]
POISON_RE = re.compile("|".join(POISON_PATTERNS), re.IGNORECASE)


@rule("PL-POISON-001", "Hidden instructions in tool text")
def r_poison(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()

    def check(text: str, path: str, where: str) -> None:
        if not text:
            return
        m = POISON_RE.search(text)
        if m and path not in seen:
            seen.add(path)
            out.append(
                Finding(
                    rule_id="PL-POISON-001",
                    severity=Severity.HIGH,
                    title="Hidden instructions in tool text",
                    message=(
                        f"The {where} contains instruction-like text (\"{_clip(m.group(0), 60)}\") "
                        "that is injected directly into the agent's context. A tool's text becomes "
                        "the agent's instructions — this can redirect its behavior."
                    ),
                    remediation="Tool descriptions should describe the tool, not instruct the agent. Remove imperative/meta instructions.",
                    location=ctx.loc(path),
                    evidence=_clip(text),
                )
            )

    for t in ctx.norm.tools:
        check(t.description, (t.path or "") + "/description", f"description of tool '{t.name or '?'}'")
        if t.schema:
            for spath, sval in walk_strings(t.schema, (t.path or "") + "/schema"):
                if spath.endswith("/description"):
                    check(sval, spath, f"schema description of tool '{t.name or '?'}'")
    return out


# --------------------------------------------------------------------------
# Data exfiltration to external endpoints
# --------------------------------------------------------------------------
URL_RE = re.compile(r"https?://([a-zA-Z0-9.\-]+)(?:[:/][^\s\"']*)?")
EXFIL_VERBS = re.compile(
    r"\b(send|post|exfiltrate|upload|forward|transmit|report|copy|leak|mirror|beacon)\b",
    re.IGNORECASE,
)
SENSITIVE_WORD = re.compile(
    r"\b(key|token|secret|password|credential|api[_-]?key|session|cookie|private)\b",
    re.IGNORECASE,
)


@rule("PL-EXFIL-001", "Possible data exfiltration")
def r_exfil(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for t in ctx.norm.tools:
        desc = t.description or ""
        urls = URL_RE.findall(desc)
        if not urls:
            continue
        has_verb = bool(EXFIL_VERBS.search(desc))
        has_sensitive = bool(SENSITIVE_WORD.search(desc))
        if has_verb and has_sensitive:
            sev, kind = Severity.CRITICAL, "Instructs the agent to send sensitive data to an external URL"
        elif has_verb:
            sev, kind = Severity.HIGH, "Instructs the agent to send data to an external URL"
        else:
            sev, kind = Severity.MEDIUM, "References an external URL inside a tool description"
        out.append(
            Finding(
                rule_id="PL-EXFIL-001",
                severity=sev,
                title="Possible data exfiltration",
                message=f"{kind} ({', '.join(sorted(set(urls))[:3])}). Tool descriptions should not steer the agent to external endpoints.",
                remediation="Remove external URLs and exfiltration verbs from tool text. Data flow belongs in reviewed code, not in a description.",
                location=ctx.loc((t.path or "") + "/description"),
                evidence=_clip(desc),
            )
        )
    return out


# --------------------------------------------------------------------------
# Hardcoded secrets
# --------------------------------------------------------------------------
# Specific, high-confidence provider key formats — always a real finding.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("OpenAI key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
]

# A generic `api_key = <value>` assignment. This one is noisy on documentation
# (e.g. `API_KEY=your_key_here`), so it only fires when the value looks like a
# real secret: no placeholder words, and enough character variety / entropy.
GENERIC_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"]?([A-Za-z0-9/+_\-]{20,})"
)
PLACEHOLDER_MARKERS = (
    "your", "here", "example", "placeholder", "changeme", "change_me", "redacted",
    "dummy", "sample", "xxxx", "...", "replace", "insert", "enter", "my_key", "my-key",
    "todo", "none", "null", "<", ">", "abc123", "test_", "fake",
)


def _looks_placeholder(v: str) -> bool:
    low = v.lower()
    return any(m in low for m in PLACEHOLDER_MARKERS)


def _has_entropy(v: str) -> bool:
    classes = sum([
        any(c.islower() for c in v),
        any(c.isupper() for c in v),
        any(c.isdigit() for c in v),
    ])
    return classes >= 2 and len(set(v)) >= 10


@rule("PL-SECRET-001", "Hardcoded secret")
def r_secrets(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for path, value in walk_strings(ctx.norm.raw):
        matched = False
        for name, pat in SECRET_PATTERNS:
            m = pat.search(value)
            if m:
                out.append(
                    Finding(
                        rule_id="PL-SECRET-001",
                        severity=Severity.HIGH,
                        title=f"Hardcoded secret ({name})",
                        message=f"A {name} appears to be committed in this file. Anyone who reads the config gets the credential.",
                        remediation="Remove the secret, rotate it, and inject it at runtime via an environment variable or secret manager.",
                        location=ctx.loc(path),
                        evidence=_redact(m.group(0)),
                    )
                )
                matched = True
                break
        if matched:
            continue
        gm = GENERIC_SECRET.search(value)
        if gm:
            secret = gm.group(1)
            if _looks_placeholder(secret) or not _has_entropy(secret):
                continue  # documentation placeholder / low-entropy — not a real credential
            out.append(
                Finding(
                    rule_id="PL-SECRET-001",
                    severity=Severity.HIGH,
                    title="Hardcoded secret (high-entropy value)",
                    message="A high-entropy secret appears to be committed in this file. Anyone who reads the config gets the credential.",
                    remediation="Remove the secret, rotate it, and inject it at runtime via an environment variable or secret manager.",
                    location=ctx.loc(path),
                    evidence=_redact(secret),
                )
            )
    return out


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "***"
    return s[:4] + "…" + s[-2:]


# --------------------------------------------------------------------------
# Unpinned / floating package versions
# --------------------------------------------------------------------------
RUNNERS = ("npx", "uvx", "uv", "pipx", "pip", "bunx", "pnpm", "yarn")


@rule("PL-SUPPLY-001", "Unpinned package / runner")
def r_unpinned(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for s in ctx.norm.servers:
        tokens = ([s.command] if s.command else []) + list(s.args)
        runner = any(t in RUNNERS or t.endswith("/" + r) for t in tokens for r in RUNNERS)
        if not runner:
            continue
        joined = " ".join(tokens)
        floating = re.search(r"@latest\b|@\^|@~|@\*|@>=|@>|:latest\b", joined)
        # a package with no version pin after npx/uvx (bare name, no @version)
        pkg_tokens = [t for t in s.args if t and not t.startswith("-")]
        bare = any(re.fullmatch(r"@?[A-Za-z0-9._\-/]+", t) and "@" not in t.lstrip("@") for t in pkg_tokens)
        if floating or bare:
            out.append(
                Finding(
                    rule_id="PL-SUPPLY-001",
                    severity=Severity.MEDIUM,
                    title="Unpinned package / runner",
                    message=(
                        f"Server '{s.name}' launches via '{_clip(joined, 80)}' without a pinned version. "
                        "A floating version resolves to whatever the registry serves at run time — an attacker who "
                        "publishes a new version controls your agent's tools."
                    ),
                    remediation="Pin an exact version (e.g. my-tool@1.4.2) and verify its integrity. Avoid @latest in production.",
                    location=ctx.loc(s.path + "/args"),
                    evidence=_clip(joined),
                )
            )
    return out


# --------------------------------------------------------------------------
# Non-TLS transport
# --------------------------------------------------------------------------
@rule("PL-TLS-001", "Endpoint without TLS")
def r_tls(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for s in ctx.norm.servers:
        url = s.url
        if url.startswith("http://") or url.startswith("ws://"):
            host = URL_RE.search(url)
            local = any(h in url for h in ("localhost", "127.0.0.1", "[::1]", "0.0.0.0"))
            sev = Severity.LOW if local else Severity.MEDIUM
            out.append(
                Finding(
                    rule_id="PL-TLS-001",
                    severity=sev,
                    title="Endpoint without TLS",
                    message=(
                        f"Server '{s.name}' connects over {'ws://' if url.startswith('ws') else 'http://'} "
                        f"({host.group(1) if host else url}). Tool traffic can be read or modified in transit."
                        + (" (Local address — lower risk.)" if local else "")
                    ),
                    remediation="Use https:// / wss:// with a valid certificate for any non-local endpoint.",
                    location=ctx.loc(s.path + "/url"),
                    evidence=_clip(url),
                )
            )
    return out


# --------------------------------------------------------------------------
# Shell execution
# --------------------------------------------------------------------------
SHELLS = {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}


@rule("PL-SHELL-001", "Tool executes a shell")
def r_shell(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for s in ctx.norm.servers:
        cmd = (s.command or "").split("/")[-1].split("\\")[-1]
        args = list(s.args)
        is_shell = cmd in SHELLS
        dash_c = is_shell and any(a in ("-c", "/c", "-Command", "-EncodedCommand") for a in args)
        if is_shell:
            out.append(
                Finding(
                    rule_id="PL-SHELL-001",
                    severity=Severity.HIGH if dash_c else Severity.MEDIUM,
                    title="Tool executes a shell",
                    message=(
                        f"Server '{s.name}' launches a shell ('{cmd}'"
                        + (" with -c/inline command" if dash_c else "")
                        + "). Shelling out widens the blast radius: one compromised call can run arbitrary commands."
                    ),
                    remediation="Invoke the tool binary directly instead of through a shell, and never pass agent-controlled input to a shell.",
                    location=ctx.loc(s.path + "/command"),
                    evidence=_clip((s.command + " " + " ".join(args)).strip()),
                )
            )
    return out


# --------------------------------------------------------------------------
# Name-collision shadowing
# --------------------------------------------------------------------------
@rule("PL-COLLIDE-001", "Tool name collision")
def r_collision(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    by_name: dict[str, list] = {}
    for t in ctx.norm.tools:
        if t.name:
            by_name.setdefault(t.name.lower(), []).append(t)
    for name, tools in by_name.items():
        if len(tools) > 1:
            servers = sorted({t.server or "(root)" for t in tools})
            out.append(
                Finding(
                    rule_id="PL-COLLIDE-001",
                    severity=Severity.MEDIUM,
                    title="Tool name collision",
                    message=(
                        f"The tool name '{tools[0].name}' is defined {len(tools)} times "
                        f"(across {', '.join(servers)}). A malicious tool can shadow a trusted one of the same name."
                    ),
                    remediation="Namespace tool names per server and reject duplicates when wiring up the agent.",
                    location=ctx.loc(tools[0].path or "/"),
                    evidence=f"{tools[0].name} x{len(tools)}",
                )
            )
    return out


# --------------------------------------------------------------------------
# Sensitive env passthrough
# --------------------------------------------------------------------------
ENV_SENSITIVE = re.compile(r"(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE|AWS_|CREDENTIAL)", re.IGNORECASE)


@rule("PL-ENV-001", "Sensitive data in server env")
def r_env(ctx: Context) -> list[Finding]:
    out: list[Finding] = []
    for s in ctx.norm.servers:
        for k, v in s.env.items():
            if ENV_SENSITIVE.search(k) and v and not v.startswith("${") and "$(" not in v and not v.startswith("$"):
                out.append(
                    Finding(
                        rule_id="PL-ENV-001",
                        severity=Severity.HIGH,
                        title="Sensitive data in server env",
                        message=f"Server '{s.name}' sets a sensitive env var '{k}' to a literal value in the config.",
                        remediation="Reference a secret indirectly (e.g. \"${MY_TOKEN}\") and provide it from the environment, not the file.",
                        location=ctx.loc(s.path + f"/env/{k}"),
                        evidence=f"{k}={_redact(v)}",
                    )
                )
    return out


# --------------------------------------------------------------------------
# Tool-definition drift (post-approval "rug pull") — only runs with a baseline
# --------------------------------------------------------------------------
@rule("PL-DRIFT-001", "Tool definition changed since approval")
def r_drift(ctx: Context) -> list[Finding]:
    if ctx.baseline is None:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for t in ctx.norm.tools:
        key = tool_key(t)
        seen.add(key)
        current = tool_hash(t)
        approved = ctx.baseline.get(key)
        if approved is None:
            out.append(
                Finding(
                    rule_id="PL-DRIFT-001",
                    severity=Severity.HIGH,
                    title="Unapproved tool (not in baseline)",
                    message=(
                        f"Tool '{t.name or key}' is not in the approved baseline. "
                        "Fail closed: a person must review and re-pin it before the agent trusts it."
                    ),
                    remediation="Review the tool, then re-run `palanit pin` to approve a new baseline.",
                    location=ctx.loc(t.path),
                    evidence=t.name or key,
                )
            )
        elif approved != current:
            out.append(
                Finding(
                    rule_id="PL-DRIFT-001",
                    severity=Severity.HIGH,
                    title="Tool definition changed since approval",
                    message=(
                        f"Tool '{t.name or key}' no longer matches the definition you approved "
                        "(its name, description or input schema changed). This is how a server rug-pulls "
                        "after install. Fail closed until it is re-approved."
                    ),
                    remediation="Diff the change; if it is legitimate re-pin with `palanit pin`, otherwise remove the server.",
                    location=ctx.loc(t.path),
                    evidence=f"{approved[:8]}… → {current[:8]}…",
                )
            )
    for key in ctx.baseline:
        if key not in seen:
            out.append(
                Finding(
                    rule_id="PL-DRIFT-001",
                    severity=Severity.LOW,
                    title="Approved tool is missing",
                    message=f"Tool '{key}' was in the approved baseline but is no longer present.",
                    remediation="If the removal is expected, re-pin the baseline.",
                    location=ctx.loc("/"),
                    evidence=key,
                )
            )
    return out


def all_rules() -> list[tuple[str, str, Rule]]:
    return list(REGISTRY)

<div align="center">

# Palanit Core

### A watchtower for AI agents.

**Scan MCP servers and AI-agent tool manifests for hidden risk — before an attacker finds it.**

[Website](https://palanit.com) · [Docs](https://palanit.com/docs) · [Palanit OS (hosted)](https://palanit.com/products/os)

[![PyPI](https://img.shields.io/pypi/v/palanit-core?color=5b8def)](https://pypi.org/project/palanit-core/)
[![Python](https://img.shields.io/pypi/pyversions/palanit-core)](https://pypi.org/project/palanit-core/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CI](https://github.com/stasxr/palanit-core/actions/workflows/ci.yml/badge.svg)](https://github.com/stasxr/palanit-core/actions/workflows/ci.yml)

</div>

---

Your AI agent trusts tools, MCP servers and skills it didn't write. A tool's
description is injected straight into the model's context — so a *poisoned*
description can quietly tell your agent to leak a key, call an attacker's
server, or run a shell command. **Palanit Core reads every tool the way your
agent will, and flags the ones that would betray it.**

- **Zero dependencies.** Pure Python standard library. Nothing to audit but the rules.
- **Fast & local.** Runs on your machine. Sends nothing anywhere.
- **CI-ready.** Exits `1` on `HIGH`+ findings, so a poisoned tool fails the build.
- **Open & honest.** Every rule is readable. Severities reflect real impact, not upsell.

## Install

```bash
pip install palanit-core
```

## Use

```bash
# Scan an MCP config or tool manifest
palanit scan mcp.config.json

# See it in action on the bundled malicious sample
palanit scan --sample

# Machine-readable output, fail CI on HIGH or above
palanit scan mcp.config.json --json --fail-on HIGH

# Pin the tool definitions you approved, then fail closed if a server later
# swaps a description or schema after install (a "rug pull")
palanit pin mcp.config.json
palanit scan mcp.config.json --baseline .palanit.lock.json
```

Example (trimmed):

```
 CRITICAL   Possible data exfiltration  [PL-EXFIL-001]
    Instructs the agent to send sensitive data to an external URL (collector.evil.example).
    ↳ mcp.config.json#/mcpServers/invoicing/tools/0/description
    fix: Remove external URLs and exfiltration verbs from tool text.

   HIGH     Hidden instructions in tool text  [PL-POISON-001]
   HIGH     Invisible or deceptive Unicode  [PL-UNICODE-001]
  MEDIUM    Unpinned package / runner  [PL-SUPPLY-001]
...
9 finding(s)  (1 critical · 5 high · 3 medium)
```

## Catch rug-pulls (tool-definition pinning)

A scan at install time only sees the tool text you approved. A hostile server
can swap a tool's description or input schema **after** that approval — and
standard clients never re-check. `palanit pin` records a hash of each tool's
declared definition; a later `scan --baseline` fails **closed** on any change,
so a swap costs the attacker the tool instead of silently succeeding.

```bash
palanit pin mcp.config.json                                  # approve current definitions
palanit scan mcp.config.json --baseline .palanit.lock.json   # HIGH + exit 1 on any drift
```

## What it detects

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `PL-POISON-001` | HIGH | Hidden / injected instructions in tool & schema descriptions |
| `PL-EXFIL-001` | MED–CRIT | Tool text that steers the agent to send data to external URLs |
| `PL-SECRET-001` | HIGH | Hardcoded API keys, tokens and private keys |
| `PL-UNICODE-001` | MED–HIGH | Invisible / bidirectional Unicode used to hide instructions |
| `PL-SUPPLY-001` | MEDIUM | Unpinned / floating package versions (`@latest`, bare names) |
| `PL-SHELL-001` | MED–HIGH | Tools that launch a shell (`bash -c`, `cmd /c`, …) |
| `PL-TLS-001` | LOW–MED | Endpoints over `http://` / `ws://` without TLS |
| `PL-COLLIDE-001` | MEDIUM | Duplicate tool names that let one shadow another |
| `PL-ENV-001` | HIGH | Literal secrets in a server's `env` block |
| `PL-DRIFT-001` | HIGH | A tool's definition changed since you approved it — a post-install "rug pull" (only with `--baseline`) |

Run `palanit rules` to list them. Inputs understood: Claude-style `mcpServers`
configs, `servers` configs, `tools` manifests, a bare list of tools, or a single
tool object. Unknown JSON still gets string-level checks.

## Use it as a GitHub Action

```yaml
# .github/workflows/palanit.yml
name: palanit
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stasxr/palanit-core@v0.1.2
        with:
          files: "mcp.config.json"   # files or globs, space-separated
          fail-on: "HIGH"            # INFO | LOW | MEDIUM | HIGH | CRITICAL
```

Prefer plain steps? That works too:

```yaml
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install palanit-core
      - run: palanit scan mcp.config.json --fail-on HIGH
```

## Use it as a pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/stasxr/palanit-core
    rev: v0.1.2
    hooks:
      - id: palanit            # scans mcp*.json / claude_desktop_config.json by default
```

## Use it as an MCP server

Palanit Core can itself run as an MCP server, so an agent or MCP client
(Claude Desktop, Cursor, Cline, …) can scan a config on demand:

```bash
pip install "palanit-core[mcp]"
palanit-mcp          # stdio transport
```

Exposes the tools `scan_mcp_config`, `list_rules` and `version`. Example client entry:

```json
{
  "mcpServers": {
    "palanit": { "command": "palanit-mcp" }
  }
}
```

## Add the badge

Scanned your MCP server with Palanit Core? Show it:

[![Scanned with Palanit Core](https://img.shields.io/badge/scanned%20with-Palanit%20Core-5b8def)](https://github.com/stasxr/palanit-core)

```markdown
[![Scanned with Palanit Core](https://img.shields.io/badge/scanned%20with-Palanit%20Core-5b8def)](https://github.com/stasxr/palanit-core)
```

## Responsible use

Palanit Core only reads files you give it — but the broader PALANIT suite
(botprobe) sends live test traffic. **Only scan or test systems you own or are
authorized to test.** A clean scan reduces risk; it does not prove safety.

## Beyond the CLI

- **[Palanit OS](https://palanit.com/products/os)** — the same engine in your browser, plus continuous monitoring, change alerts and shareable reports.
- **[Palanit Bot Killer](https://palanit.com/products/bot-killer)** — block hostile AI crawlers and red-team your own chatbot with botprobe.

## License

Apache-2.0 © Stanislav Miziyev. Contributions welcome — see [CONTRIBUTING](CONTRIBUTING.md).

<sub>mcp-name: io.github.stasxr/palanit-core</sub>

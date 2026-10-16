<div align="center">

# Palanit Core

### A watchtower for AI agents.

**Scan MCP servers and AI-agent tool manifests for hidden risk — before an attacker finds it.**

[Website](https://palanit.com) · [Docs](https://palanit.com/docs) · [Palanit OS (hosted)](https://palanit.com/products/os)

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

Run `palanit rules` to list them. Inputs understood: Claude-style `mcpServers`
configs, `servers` configs, `tools` manifests, a bare list of tools, or a single
tool object. Unknown JSON still gets string-level checks.

## Use it in CI

```yaml
# .github/workflows/palanit.yml
name: palanit
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install palanit-core
      - run: palanit scan mcp.config.json --fail-on HIGH
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

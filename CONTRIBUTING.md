# Contributing to Palanit Core

Thanks for helping make AI agents safer to run. Palanit Core is deliberately
small and dependency-free — that's a feature, please keep it that way.

## Ground rules

- **No runtime dependencies.** The scanner must run with a stock Python 3.9+.
- **Rules are readable.** Each rule lives in `palanit_core/rules.py`, is a few
  lines, and explains *what* it catches and *how to fix it*. If a maintainer
  can't understand a rule at a glance, neither can a user who's trusting it.
- **Honest severities.** Rate by real-world impact. Don't inflate.
- **Add a test.** Every new rule needs a positive and (ideally) a negative case
  in `tests/test_rules.py`.

## Dev loop

```bash
git clone https://github.com/stasxr/palanit-core
cd palanit-core
python3 tests/test_rules.py        # run tests (no deps required)
python3 -m palanit_core scan --sample
```

## Proposing a new rule

Open an issue describing the risk, a minimal example config that triggers it,
and the real-world impact. Then send a PR with the rule + tests.

## Security

Found a vulnerability in PALANIT itself? Please follow our
[responsible disclosure policy](https://palanit.com/legal/responsible-disclosure)
and email **stas.m@palanit.com** — don't open a public issue for it.

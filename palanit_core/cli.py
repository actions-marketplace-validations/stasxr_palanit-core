"""PALANIT Core command-line interface.

Usage:
  palanit scan <file...> [--json] [--fail-on LEVEL] [--no-color]
  palanit scan --sample
  palanit rules
  palanit version
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .engine import scan_files
from .models import Severity
from .report import to_json, to_text
from . import rules as rules_mod

SAMPLE = os.path.join(os.path.dirname(__file__), "samples", "malicious.mcp.json")


def _cmd_scan(args: argparse.Namespace) -> int:
    paths = list(args.files)
    if args.sample:
        paths.append(SAMPLE)
    if not paths:
        print("palanit: no files to scan. Pass a file, or --sample.", file=sys.stderr)
        return 2

    result = scan_files(paths)

    if args.json:
        print(to_json(result))
    else:
        print(to_text(result, no_color=args.no_color))

    try:
        threshold = Severity.parse(args.fail_on)
    except ValueError:
        print(f"palanit: invalid --fail-on value {args.fail_on!r}", file=sys.stderr)
        return 2

    top = result.max_severity()
    if top is not None and top >= threshold:
        return 1
    return 0


def _cmd_rules(_args: argparse.Namespace) -> int:
    for rule_id, title, _fn in sorted(rules_mod.all_rules()):
        print(f"{rule_id:<16} {title}")
    return 0


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"palanit-core {__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="palanit",
        description="PALANIT — scan MCP servers and AI-agent tool manifests for hidden risk.",
        epilog="Only scan systems you own or are authorized to test.",
    )
    p.add_argument("-V", "--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan one or more JSON files")
    s.add_argument("files", nargs="*", help="MCP config or tool manifest JSON file(s)")
    s.add_argument("--json", action="store_true", help="machine-readable JSON output")
    s.add_argument("--fail-on", default="HIGH", metavar="LEVEL",
                   help="exit 1 if any finding is at this severity or above "
                        "(INFO|LOW|MEDIUM|HIGH|CRITICAL; default HIGH)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    s.add_argument("--sample", action="store_true", help="also scan the bundled malicious sample")
    s.set_defaults(func=_cmd_scan)

    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(func=_cmd_rules)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=_cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        return _cmd_version(args)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

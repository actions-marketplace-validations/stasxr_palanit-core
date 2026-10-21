"""PALANIT Core command-line interface.

Usage:
  palanit scan <file...> [--json] [--fail-on LEVEL] [--no-color]
  palanit scan --sample
  palanit rules
  palanit version
"""
from __future__ import annotations

import argparse
import json
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

    baseline = None
    if getattr(args, "baseline", None):
        from .pin import load_lock
        try:
            baseline = load_lock(args.baseline)
        except FileNotFoundError:
            print(f"palanit: baseline not found: {args.baseline}", file=sys.stderr)
            return 2
        except json.JSONDecodeError as exc:
            print(f"palanit: invalid baseline {args.baseline!r}: {exc}", file=sys.stderr)
            return 2

    result = scan_files(paths, baseline=baseline)

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


def _cmd_pin(args: argparse.Namespace) -> int:
    from .loaders import load_json, normalize
    from .pin import build_baseline, LOCK_SCHEMA

    if not args.files:
        print("palanit: no files to pin. Pass an MCP config or tool manifest.", file=sys.stderr)
        return 2
    merged: dict[str, str] = {}
    for path in args.files:
        try:
            raw = load_json(path)
        except FileNotFoundError:
            print(f"palanit: {path}: file not found", file=sys.stderr)
            return 2
        except json.JSONDecodeError as exc:
            print(f"palanit: {path}: invalid JSON ({exc})", file=sys.stderr)
            return 2
        merged.update(build_baseline(normalize(raw)))

    out = args.output or ".palanit.lock.json"
    lock = {"schema": LOCK_SCHEMA, "core_version": __version__, "tools": merged}
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(lock, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print(f"Pinned {len(merged)} tool definition(s) to {out}")
    print(f"Detect later changes with:  palanit scan {' '.join(args.files)} --baseline {out}")
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
    s.add_argument("--baseline", metavar="LOCK",
                   help="compare tool definitions against a pinned baseline (from `palanit pin`) "
                        "and fail closed on any post-approval drift")
    s.set_defaults(func=_cmd_scan)

    pn = sub.add_parser("pin", help="record an approved baseline of tool definitions (anti rug-pull)")
    pn.add_argument("files", nargs="*", help="MCP config or tool manifest JSON file(s)")
    pn.add_argument("-o", "--output", metavar="LOCK",
                    help="baseline file to write (default .palanit.lock.json)")
    pn.set_defaults(func=_cmd_pin)

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

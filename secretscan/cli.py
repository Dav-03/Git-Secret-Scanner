import argparse
import json
import sys
import time
from pathlib import Path

from .filters import load_baseline, load_ignore_file, write_baseline
from .gitSource import GitError, history, staged
from .hooks import install_hook
from .report import to_text, tool_version
from .rules import RuleError, load_config
from .scanner import scan

CLEAN = 0
FINDINGS = 1
ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscan", description="Scan git history for secrets"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {tool_version()}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Scan a repository")
    p.add_argument(
        "path", nargs="?", default=".", help="Repository path (default: .)"
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--history", action="store_true", help="Scan all commits (default)"
    )
    mode.add_argument(
        "--staged", action="store_true", help="Scan staged changes only"
    )
    p.add_argument(
        "--config", type=Path, help="Custom rules TOML (default: built-in)"
    )
    p.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB",
        help="Skip paths matching GLOB (repeatable)",
    )
    p.add_argument(
        "--baseline", type=Path, metavar="FILE",
        help="Ignore findings whose fingerprints are in FILE",
    )
    p.add_argument(
        "--write-baseline", type=Path, metavar="FILE",
        help="Save current findings' fingerprints to FILE and exit 0",
    )
    p.add_argument(
        "-o", "--output", type=Path, metavar="FILE",
        help="Write the report to FILE instead of stdout",
    )

    h = sub.add_parser(
        "install-hook", help="Install a pre-commit hook in a repository"
    )
    h.add_argument(
        "path", nargs="?", default=".", help="Repository path (default: .)"
    )
    h.add_argument(
        "--force", action="store_true", help="Overwrite an existing hook"
    )
    return parser


def _scan(args: argparse.Namespace) -> int:
    source = staged if args.staged else history
    start = time.perf_counter()
    try:
        config = load_config(args.config)
        excludes = [*load_ignore_file(args.path), *args.exclude]
        baseline = load_baseline(args.baseline) if args.baseline else None
        groups = scan(source(args.path), config, excludes, baseline)

        if args.write_baseline:
            write_baseline(args.write_baseline, groups)
            print(
                f"wrote {len(groups)} fingerprint(s) to "
                f"{args.write_baseline}",
                file=sys.stderr,
            )
            return CLEAN

        report = to_text(groups)
        if args.output:
            args.output.write_text(report, encoding="utf-8")
        else:
            sys.stdout.write(report)
    except (GitError, RuleError, OSError, json.JSONDecodeError,
            ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return ERROR

    elapsed = time.perf_counter() - start
    print(f"{len(groups)} finding(s) in {elapsed:.2f}s", file=sys.stderr)
    if groups and args.staged:
        print(
            "commit blocked: remove the secret(s) above, or bypass with "
            "git commit --no-verify",
            file=sys.stderr,
        )
    return FINDINGS if groups else CLEAN


def _install_hook(args: argparse.Namespace) -> int:
    try:
        hook = install_hook(args.path, force=args.force)
    except (GitError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return ERROR
    print(f"installed pre-commit hook: {hook}", file=sys.stderr)
    return CLEAN


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "install-hook":
        return _install_hook(args)
    return _scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
import argparse
import sys
import time

from .gitSource import GitError, history, staged


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscan", description="Scan git history for secrets"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository")
    scan.add_argument(
        "path", nargs="?", default=".", help="Repository path (default: .)"
    )
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument(
        "--history", action="store_true", help="Scan all commits (default)"
    )
    mode.add_argument(
        "--staged", action="store_true", help="Scan staged changes only"
    )
    scan.add_argument(
        "-v", "--verbose", action="store_true", help="Print every added line"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    source = staged if args.staged else history
    start = time.perf_counter()
    commits: set[str] = set()
    lines = 0
    try:
        for added in source(args.path):
            commits.add(added.commit)
            lines += 1
            if args.verbose:
                print(
                    f"{added.commit[:8]} {added.path}:{added.line_number}: {added.text}"
                )
    except GitError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    elapsed = time.perf_counter() - start
    print(
        f"scanned {lines} added lines across {len(commits)} commits in {elapsed:.2f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

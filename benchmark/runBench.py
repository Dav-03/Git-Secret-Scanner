import argparse
import json
import platform
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from dummyRepo import build  # noqa: E402

from secretscan.gitSource import history  # noqa: E402
from secretscan.rules import load_config  # noqa: E402
from secretscan.scanner import scan  # noqa: E402

CORPORA = HERE / "corpora"
CONFIG = load_config()


def corpus(commits: int, secrets: int, decoys: int) -> Path:
    path = CORPORA / f"c{commits}"
    if not path.exists():
        build(path, commits, secrets, decoys)
    return path


def timed_scan(repo: Path) -> tuple[list[str], float]:
    start = time.perf_counter()
    found = [g.first.secret for g in scan(history(repo), CONFIG)]
    return found, time.perf_counter() - start


def accuracy(repo: Path) -> list[str]:
    truth = json.loads(Path(f"{repo}.truth.json").read_text())
    planted = set(truth["secrets"])
    found, _ = timed_scan(repo)

    detected = [p for p in planted if any(p in f for f in found)]
    false_pos = [f for f in found if not any(p in f for p in planted)]
    precision = (len(found) - len(false_pos)) / len(found) if found else 1

    lines = [
        "## Accuracy", "",
        f"{len(planted)} planted secrets, {len(truth['decoys'])} decoys "
        f"({dict(Counter(truth['decoys']))}).", "",
        "| Detected | Detection rate | Findings | False positives "
        "| Precision |",
        "|---|---|---|---|---|",
        f"| {len(detected)}/{len(planted)} "
        f"| {len(detected) / len(planted):.1%} | {len(found)} "
        f"| {len(false_pos)} | {precision:.1%} |",
    ]
    if false_pos:
        lines += ["", "False positives (first 5):", ""]
        lines += [f"- `{f}`" for f in false_pos[:5]]
    return lines


def count_commits(repo: Path) -> int:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "--all", "--count"],
        capture_output=True, text=True, check=True,
    )
    return int(out.stdout)


def runtime(sizes: list[int], real_repos: list[Path]) -> list[str]:
    lines = ["## Runtime", "", "| Repo | Commits | Scan time |",
             "|---|---|---|"]
    targets = [("synthetic", corpus(n, n // 10, n // 5)) for n in sizes]
    targets += [(repo.name, repo) for repo in real_repos]
    for label, repo in targets:
        _, seconds = timed_scan(repo)
        lines.append(f"| {label} | {count_commits(repo):,} "
                     f"| {seconds:.2f}s |")
    return lines


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sizes", type=int, nargs="+",
                   default=[100, 1000, 10000, 50000])
    p.add_argument("--repo", type=Path, action="append", default=[],
                   help="real repo to time (repeatable)")
    a = p.parse_args()

    report = [
        "# Benchmark results", "",
        f"{platform.system()}, Python {platform.python_version()}.", "",
        *accuracy(corpus(2000, 200, 400)), "",
        *runtime(a.sizes, a.repo),
    ]
    text = "\n".join(report) + "\n"
    (HERE / "results.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
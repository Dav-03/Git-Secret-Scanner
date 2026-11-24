import subprocess
from collections.abc import Iterator
from pathlib import Path

from diffParser import PREFIX, parse_difference
from model import STAGED, addedLine

GIT = ["git", "-c", "core.quotepath=off"]
DIFF_OPTIONS = ["--unified=0", "--no-color", "--no-ext-diff", "--no-textconv"]

class GitError(RuntimeError):
    pass

def ensureRepo(repo: str | Path) -> Path:
    repo = Path(repo).resolve()
    try:
        subprocess.run(
            [*GIT, "-C", str(repo), "rev-parse", "--git-dir"],
            check=True,
            capture_output=True,
            text=True
        )
    except FileNotFoundError as error:
        raise GitError("git execuatable was not found on path") from error
    except subprocess.CalledProcessError as error:
        raise GitError(f"not a git repo: {repo}") from error
    return repo


def stream(repo: Path, args: list[str]) -> Iterator[str]:
    process = subprocess.Popen(
        [*GIT, "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert process.stdout is not None and process.stderr is not None
    try:
        yield from process.stdout
    finally:
        process.stdout.close()
        error = process.stderr.read()
        process.stderr.close()
        code = process.wait()
    if code != 0:
        raise GitError(f"git {' '.join(args[:2])} failed ({code}): {error.strip()}")
    

# Scans for changes from previous commits
def history(repo: Path | str) -> Iterator[addedLine]:
    repo = ensureRepo(repo)
    args = ["log", "-p", "--all", f"--format={PREFIX}%H", *DIFF_OPTIONS]
    yield from parse_difference(stream(repo, args), default_commit="")


# Scans for changes that have been staged but not committed
def staged(repo: Path | str) -> Iterator[addedLine]:
    repo = ensureRepo(repo)
    args = ["diff", "--cached", *DIFF_OPTIONS]
    yield from parse_difference(stream(repo, args), default_commit=STAGED)
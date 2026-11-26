import subprocess
import sys
from pathlib import Path

from .gitSource import GitError, ensureRepo

MARKER = "# installed by secretscan"


def hook_script() -> str:
    python = Path(sys.executable).as_posix()
    return (
        "#!/bin/sh\n"
        f"{MARKER}\n"
        "# Bypass once with: git commit --no-verify\n"
        f'exec "{python}" -m secretscan scan --staged\n'
    )


def hooks_dir(repo: Path) -> Path:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--git-path", "hooks"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    path = Path(out)
    return path if path.is_absolute() else repo / path


def install_hook(repo: str | Path, force: bool = False) -> Path:
    repo = ensureRepo(repo)
    hook = hooks_dir(repo) / "pre-commit"

    if hook.exists() and not force:
        existing = hook.read_text("utf-8", errors="replace")
        if MARKER not in existing:
            raise GitError(
                f"{hook} already exists and was not installed by "
                "secretscan; use --force to overwrite"
            )

    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(hook_script(), encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    return hook
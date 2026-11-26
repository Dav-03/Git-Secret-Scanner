import subprocess
from pathlib import Path

import pytest

from secretscan.cli import main
from tests.fakes import fake
from secretscan.gitSource import GitError
from secretscan.hooks import MARKER, hooks_dir, install_hook


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        capture_output=True, text=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def stage(repo: Path, name: str, content: str) -> None:
    (repo / name).write_text(content, encoding="utf-8")
    git(repo, "add", name)


def commit_count(repo: Path) -> int:
    out = git(repo, "rev-list", "--count", "--all").stdout.strip()
    return int(out or 0)


def test_install_writes_hook(repo: Path):
    hook = install_hook(repo)
    assert hook == hooks_dir(repo) / "pre-commit"
    assert MARKER in hook.read_text()


def test_hook_blocks_commit_with_secret(repo: Path):
    install_hook(repo)
    stage(repo, "app.py", fake("aws-access-key-id") + "\n")

    result = git(repo, "commit", "-q", "-m", "leak")

    assert result.returncode != 0
    assert "aws-access-key-id" in result.stdout + result.stderr
    assert commit_count(repo) == 0


def test_hook_allows_clean_commit(repo: Path):
    install_hook(repo)
    stage(repo, "app.py", "print('hello')\n")

    assert git(repo, "commit", "-q", "-m", "clean").returncode == 0
    assert commit_count(repo) == 1


def test_no_verify_bypasses_hook(repo: Path):
    install_hook(repo)
    stage(repo, "app.py", fake("aws-access-key-id") + "\n")

    result = git(repo, "commit", "-q", "--no-verify", "-m", "bypass")
    assert result.returncode == 0


def test_reinstall_is_allowed(repo: Path):
    install_hook(repo)
    install_hook(repo)


def test_foreign_hook_not_overwritten(repo: Path):
    hook = hooks_dir(repo) / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho mine\n")

    with pytest.raises(GitError, match="--force"):
        install_hook(repo)
    install_hook(repo, force=True)
    assert MARKER in hook.read_text()


def test_respects_core_hooks_path(repo: Path):
    git(repo, "config", "core.hooksPath", "custom-hooks")
    assert install_hook(repo) == repo / "custom-hooks" / "pre-commit"


def test_cli_install_hook(repo: Path):
    assert main(["install-hook", str(repo)]) == 0


def test_cli_install_hook_not_a_repo(tmp_path: Path):
    assert main(["install-hook", str(tmp_path)]) == 2
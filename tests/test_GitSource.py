import subprocess
from pathlib import Path

import pytest

from secretscan.gitSource import GitError, history, staged
from secretscan.model import STAGED


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(repo),
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def commit_file(repo: Path, name: str, content: str, msg: str = "c") -> str:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(content, encoding="utf-8")
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


def test_history_finds_secret_removed_later(repo: Path):
    sha1 = commit_file(repo, "app.py", "token = 'abc'\n")
    commit_file(repo, "app.py", "token = None\n")

    found = []
    for a in history(repo):
        if "abc" in a.text:
            found.append(a)

    assert len(found) == 1
    assert found[0].commit == sha1
    assert (found[0].path, found[0].line_number) == ("app.py", 1)


def test_history_includes_other_branches(repo: Path):
    commit_file(repo, "a.txt", "main\n")
    git(repo, "checkout", "-q", "-b", "feature")
    commit_file(repo, "b.txt", "on-feature\n")
    git(repo, "checkout", "-q", "main")

    assert "on-feature" in [a.text for a in history(repo)]


def test_nested_and_unicode_paths(repo: Path):
    commit_file(repo, "src/conf/ñame.env", "X=1\n")
    assert [a.path for a in history(repo)] == ["src/conf/ñame.env"]


def test_empty_repo(repo: Path):
    assert list(history(repo)) == []


def test_staged_only(repo: Path):
    commit_file(repo, "a.txt", "committed\n")
    (repo / "a.txt").write_text("committed\nstaged\n", encoding="utf-8")
    git(repo, "add", "a.txt")
    (repo / "a.txt").write_text(
        "committed\nstaged\nunstaged\n", encoding="utf-8"
    )

    lines = list(staged(repo))
    assert [(a.commit, a.text, a.line_number) for a in lines] == [
        (STAGED, "staged", 2)
    ]


def test_not_a_repo(tmp_path: Path):
    with pytest.raises(GitError):
        list(history(tmp_path))

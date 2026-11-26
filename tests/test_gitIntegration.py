import subprocess
import time
from pathlib import Path

import pytest

from secretscan.gitSource import history
from secretscan.rules import load_config
from secretscan.scanner import scan
from tests.fakes import ALNUM, fake, rand

CONFIG = load_config()


def git(repo: Path, *args: str, check: bool = True) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=check, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "core.autocrlf", "false")
    return tmp_path


def write(repo: Path, name: str, content: str | bytes) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_bytes(content.encode("utf-8"))


def commit(repo: Path, msg: str = "c") -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


def secrets_found(repo: Path):
    return scan(history(repo), CONFIG)


def test_pure_rename_adds_no_lines(repo: Path):
    write(repo, "a.py", "x = 1\n")
    commit(repo)
    git(repo, "mv", "a.py", "b.py")
    rename_sha = commit(repo)

    assert [a for a in history(repo) if a.commit == rename_sha] == []


def test_rename_with_edit_reports_new_path(repo: Path):
    write(repo, "a.py", "x = 1\n")
    commit(repo)
    git(repo, "mv", "a.py", "b.py")
    write(repo, "b.py", "x = 1\n" + fake("aws-access-key-id") + "\n")
    commit(repo)

    (group,) = secrets_found(repo)
    assert (group.first.path, group.first.line_number) == ("b.py", 2)


def test_secret_in_deleted_file_still_found(repo: Path):
    write(repo, "creds.env", fake("aws-access-key-id") + "\n")
    added = commit(repo)
    (repo / "creds.env").unlink()
    commit(repo, "remove creds")

    (group,) = secrets_found(repo)
    assert group.first.commit == added


def test_binary_file_is_skipped(repo: Path):
    # Known limitation: git shows no diff for binary files, so secrets
    # inside them are not scanned.
    secret = fake("aws-access-key-id").encode()
    write(repo, "blob.bin", b"\x00\x01" + secret + b"\x00")
    commit(repo)

    assert list(history(repo)) == []


def test_crlf_line_endings_are_stripped(repo: Path):
    write(repo, "win.py", "a = 1\r\n" + fake("aws-access-key-id") + "\r\n")
    commit(repo)

    lines = list(history(repo))
    assert all(not a.text.endswith("\r") for a in lines)
    assert len(secrets_found(repo)) == 1


def test_autocrlf_true(repo: Path):
    git(repo, "config", "core.autocrlf", "true")
    write(repo, "win.py", fake("aws-access-key-id") + "\r\n")
    commit(repo)

    assert len(secrets_found(repo)) == 1


def test_non_utf8_file_does_not_crash(repo: Path):
    write(repo, "latin.txt", "caf\xe9 = 1\n".encode("latin-1"))
    write(repo, "ok.py", fake("aws-access-key-id") + "\n")
    commit(repo)

    assert len(secrets_found(repo)) == 1


def test_no_trailing_newline(repo: Path):
    write(repo, "last.py", fake("aws-access-key-id"))
    commit(repo)

    assert len(secrets_found(repo)) == 1


def test_empty_file(repo: Path):
    write(repo, "empty.py", "")
    commit(repo)

    assert list(history(repo)) == []


def test_long_minified_line(repo: Path):
    filler = "var a=1;" * 25_000  # ~200 KB on one line
    write(repo, "bundle.js", filler + fake("github-token") + ";" + filler)
    commit(repo)

    start = time.perf_counter()
    (group,) = secrets_found(repo)
    assert group.first.rule_id == "github-token"
    assert time.perf_counter() - start < 5


def test_many_commits(repo: Path):
    for i in range(50):
        write(repo, "log.txt", f"line {i}\n")
        commit(repo, f"c{i}")
    write(repo, "app.py", fake("aws-access-key-id") + "\n")
    commit(repo)

    assert len(list(history(repo))) == 51
    assert len(secrets_found(repo)) == 1


def test_commit_on_two_branches_counted_once(repo: Path):
    write(repo, "app.py", fake("aws-access-key-id") + "\n")
    commit(repo)
    git(repo, "branch", "other")

    (group,) = secrets_found(repo)
    assert group.count == 1


def test_secret_on_unmerged_branch_found(repo: Path):
    write(repo, "a.py", "x = 1\n")
    commit(repo)
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, "b.py", fake("github-token") + "\n")
    commit(repo)
    git(repo, "checkout", "-q", "main")

    assert len(secrets_found(repo)) == 1


@pytest.mark.xfail(
    strict=True,
    reason="Known gap: git log -p shows no diff for merge commits, so a "
    "secret added only while resolving a conflict is missed.",
)
def test_secret_added_in_merge_resolution(repo: Path):
    write(repo, "conf.py", "key = 1\n")
    commit(repo)
    git(repo, "checkout", "-q", "-b", "feature")
    write(repo, "conf.py", "key = 2\n")
    commit(repo)
    git(repo, "checkout", "-q", "main")
    write(repo, "conf.py", "key = 3\n")
    commit(repo)
    git(repo, "merge", "-q", "feature", check=False)  # conflicts

    secret = 'api_key = "' + rand(ALNUM, 32) + '"\n'
    write(repo, "conf.py", secret)
    commit(repo, "merge feature")

    assert len(secrets_found(repo)) == 1
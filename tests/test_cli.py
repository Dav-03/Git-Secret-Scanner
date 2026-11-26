import subprocess
from pathlib import Path

from secretscan.cli import main
from tests.fakes import fake


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t",
         "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=True, capture_output=True,
    )


def make_repo(tmp_path: Path, content: str) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app.py").write_text(content, encoding="utf-8")
    git(tmp_path, "add", "app.py")
    git(tmp_path, "commit", "-q", "-m", "c")
    return tmp_path


def test_clean_repo_exits_0(tmp_path: Path):
    repo = make_repo(tmp_path, "print('hello')\n")
    assert main(["scan", str(repo)]) == 0


def test_secret_exits_1_and_is_redacted(tmp_path: Path, capsys):
    secret_line = fake("aws-access-key-id")
    repo = make_repo(tmp_path, secret_line + "\n")

    assert main(["scan", str(repo)]) == 1

    out = capsys.readouterr().out
    secret = secret_line.split("'")[1]
    assert "aws-access-key-id" in out
    assert secret not in out


def test_not_a_repo_exits_2(tmp_path: Path):
    assert main(["scan", str(tmp_path)]) == 2


def test_repeated_secret_reported_once(tmp_path: Path, capsys):
    secret_line = fake("aws-access-key-id")
    repo = make_repo(tmp_path, secret_line + "\n")
    (repo / "other.py").write_text(secret_line + "\n", encoding="utf-8")
    git(repo, "add", "other.py")
    git(repo, "commit", "-q", "-m", "c2")

    assert main(["scan", str(repo)]) == 1
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    assert "(+1 more)" in out[0]


def test_baseline_flow(tmp_path: Path):
    repo = make_repo(tmp_path / "repo", fake("aws-access-key-id") + "\n")
    baseline = tmp_path / "baseline.json"

    assert main(["scan", str(repo), "--write-baseline", str(baseline)]) == 0
    assert main(["scan", str(repo), "--baseline", str(baseline)]) == 0


def test_ignore_file_in_repo(tmp_path: Path):
    repo = make_repo(tmp_path, fake("aws-access-key-id") + "\n")
    (repo / ".secretscanignore").write_text("app.py\n", encoding="utf-8")
    assert main(["scan", str(repo)]) == 0
import subprocess
from pathlib import Path
import pytest
from secretscan import gitSource
from secretscan.cli import main
from secretscan.diffParser import parse_difference
from secretscan.gitSource import GitError, ensureRepo, stream
from secretscan.model import Found
from secretscan.rules import RuleError, load_config, load_rules

def test_context_lines_advance_line_numbers():
    # Not produced with --unified=0, but the parser must still count them.
    diff = (
        "COMMIT:abc\n"
        "diff --git a/f b/f\n--- a/f\n+++ b/f\n"
        "@@ -1,3 +1,4 @@\n"
        " one\n"
        "+two\n"
        " three\n"
        "+four\n"
    )
    lines = list(parse_difference(diff.splitlines(True), ""))
    assert [(a.line_number, a.text) for a in lines] == [
        (2, "two"),
        (4, "four"),
    ]


def test_unparseable_hunk_header_is_ignored():
    diff = (
        "COMMIT:abc\n"
        "diff --git a/f b/f\n--- a/f\n+++ b/f\n"
        "@@ garbage @@\n"
        "+not counted\n"
    )
    assert list(parse_difference(diff.splitlines(True), "")) == []

def test_short_secret_fully_redacted():
    f = Found("r", "c", "p", 1, "abcd1234")
    assert f.redacted() == "********"


def write_toml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "rules.toml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("this is = not [valid toml", "invalid TOML"),
        ("", "no rules"),
        ("[[rules]]\nregex = 'x'\nsecret_group = 0\n", "missing 'id'"),
        ("[[rules]]\nid = 'a'\n", "missing 'regex'"),
        (
            "[[rules]]\nid = 'a'\nregex = 'x'\nsecret_group = 0\n"
            "[allowlist]\npaths = [1, 2]\n",
            "must be strings",
        ),
    ],
)
def test_bad_config_raises(tmp_path: Path, text: str, match: str):
    with pytest.raises(RuleError, match=match):
        load_config(write_toml(tmp_path, text))


def test_custom_config_without_allowlist(tmp_path: Path):
    path = write_toml(
        tmp_path, "[[rules]]\nid = 'a'\nregex = '(x+)'\n"
    )
    config = load_config(path)
    assert [r.id for r in config.rules] == ["a"]
    assert config.allowlist.paths == ()


def test_bundled_rules_load():
    assert len(load_rules()) >= 9


def test_git_missing_from_path(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        gitSource, "GIT", ["definitely-not-git-xyz", "-c", "a=b"]
    )
    with pytest.raises(GitError, match="not found"):
        ensureRepo(tmp_path)


def test_git_command_failure_raises(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    with pytest.raises(GitError, match="failed"):
        list(stream(tmp_path, ["log", "--not-a-real-flag"]))


def test_cli_missing_config_exits_2(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    code = main(["scan", str(tmp_path), "--config", str(tmp_path / "x")])
    assert code == 2


def test_cli_broken_baseline_exits_2(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    bad = tmp_path / "baseline.json"
    bad.write_text("{not json")
    assert main(["scan", str(tmp_path), "--baseline", str(bad)]) == 2


def test_cli_staged_clean_exits_0(tmp_path: Path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert main(["scan", str(tmp_path), "--staged"]) == 0
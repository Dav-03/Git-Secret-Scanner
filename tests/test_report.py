from pathlib import Path

import pytest

from secretscan.cli import main
from tests.fakes import fake
from secretscan.model import addedLine
from secretscan.report import to_text
from secretscan.rules import load_config
from secretscan.scanner import scan
from tests.test_cli import make_repo

CONFIG = load_config()


def groups_for(text: str, commit: str = "abc12345deadbeef"):
    return scan([addedLine(commit, "src/app.py", 7, text)], CONFIG)


def test_text_format():
    out = to_text(groups_for(fake("aws-access-key-id")))
    assert out.startswith("abc12345 src/app.py:7 [aws-access-key-id] AKIA")


def test_text_does_not_leak_secret():
    text = fake("aws-access-key-id")
    assert text.split("'")[1] not in to_text(groups_for(text))


def test_empty_text_is_empty():
    assert to_text([]) == ""


def test_cli_output_to_file(tmp_path: Path):
    repo = make_repo(tmp_path / "repo", fake("aws-access-key-id") + "\n")
    out = tmp_path / "report.txt"

    assert main(["scan", str(repo), "-o", str(out)]) == 1
    assert "[aws-access-key-id]" in out.read_text()


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("secretscan ")
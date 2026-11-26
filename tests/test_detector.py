from pathlib import Path

import pytest

from secretscan.detector import detect
from tests.fakes import ALNUM, fake, rand
from secretscan.model import addedLine
from secretscan.rules import RuleError, load_rules

RULES = load_rules()


def line(text: str, n: int = 1) -> addedLine:
    return addedLine("abc123", "app.py", n, text)


def scan(text: str):
    return list(detect([line(text)], RULES))


@pytest.mark.parametrize("rule_id", [r.id for r in RULES])
def test_every_rule_fires_on_its_fake_secret(rule_id):
    found = scan(fake(rule_id))
    assert [f.rule_id for f in found] == [rule_id]


def test_specific_rule_wins_over_generic():
    token = "ghp_" + rand(ALNUM, 36)
    found = scan(f'api_key = "{token}"')
    assert [(f.rule_id, f.secret) for f in found] == [("github-token", token)]


@pytest.mark.parametrize(
    "text",
    [
        'token = os.environ["TOKEN"]',
        "password = get_password()",
        'password = "changeme"',
        'api_key = "your_api_key_here"',
        "secret_key: str",
        "def get_token(self):",
        'author_email="someone.longname@example.com"',
    ],
)
def test_no_false_positive(text):
    assert scan(text) == []


def test_two_secrets_on_one_line():
    aws = "AKIA" + rand("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16)
    gh = "ghp_" + rand(ALNUM, 36)
    found = scan(f"{aws} {gh}")
    assert sorted(f.rule_id for f in found) == [
        "aws-access-key-id",
        "github-token",
    ]


def test_finding_keeps_location():
    found = list(detect([line(fake("aws-access-key-id"), n=42)], RULES))
    assert (found[0].commit, found[0].path, found[0].line_number) == (
        "abc123",
        "app.py",
        42,
    )


def test_redacted_hides_secret():
    found = scan(fake("aws-access-key-id"))
    assert found[0].secret not in found[0].redacted()
    assert found[0].redacted().startswith("AKIA")


def test_invalid_regex_raises(tmp_path: Path):
    bad = tmp_path / "rules.toml"
    bad.write_text("[[rules]]\nid = 'bad'\nregex = '(unclosed'\n")
    with pytest.raises(RuleError, match="invalid regex"):
        load_rules(bad)


def test_duplicate_ids_raise(tmp_path: Path):
    bad = tmp_path / "rules.toml"
    bad.write_text(
        "[[rules]]\nid = 'a'\nregex = 'x'\nsecret_group = 0\n"
        "[[rules]]\nid = 'a'\nregex = 'y'\nsecret_group = 0\n"
    )
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(bad)


def test_bad_secret_group_raises(tmp_path: Path):
    bad = tmp_path / "rules.toml"
    bad.write_text("[[rules]]\nid = 'a'\nregex = 'no-groups'\n")
    with pytest.raises(RuleError, match="secret_group"):
        load_rules(bad)
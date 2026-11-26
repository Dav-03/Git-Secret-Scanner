from pathlib import Path

import pytest

from tests.fakes import ALNUM, fake, rand
from secretscan.filters import (
    dedupe,
    fingerprint,
    load_baseline,
    load_ignore_file,
    path_excluded,
    write_baseline,
)
from secretscan.model import Found, addedLine
from secretscan.rules import load_config
from secretscan.scanner import scan

CONFIG = load_config()


def line(text: str, path: str = "app.py", commit: str = "c1", n: int = 1):
    return addedLine(commit, path, n, text)


def found(secret: str, commit: str = "c1", path: str = "a.py") -> Found:
    return Found("generic-secret", commit, path, 1, secret)


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("package-lock.json", "package-lock.json", True),
        ("web/package-lock.json", "package-lock.json", True),
        ("static/app.min.js", "*.min.js", True),
        ("vendor/lib/x.py", "vendor/*", True),
        ("src/vendor/x.py", "*/vendor/*", True),
        ("src/app.py", "*.min.js", False),
        ("docs/config.rst", "docs/*", True),
        ("src/docs.py", "docs/*", False),
    ],
)
def test_path_excluded(path, pattern, expected):
    assert path_excluded(path, [pattern]) is expected


def test_lockfile_secret_skipped():
    lines = [line(fake("aws-access-key-id"), path="package-lock.json")]
    assert scan(lines, CONFIG) == []


def test_extra_exclude():
    lines = [line(fake("aws-access-key-id"), path="docs/setup.md")]
    assert scan(lines, CONFIG, extra_excludes=["docs/*"]) == []
    assert len(scan(lines, CONFIG)) == 1


def test_inline_ignore_comment():
    text = fake("aws-access-key-id") + "  # secretscan:ignore"
    assert scan([line(text)], CONFIG) == []


@pytest.mark.parametrize(
    "text",
    [
        "aws = 'AKIAIOSFODNN7EXAMPLE'",  # AWS's documented example key
        'api_key = "your_api_key_goes_here_now"',
        'token = "${GITHUB_TOKEN_FROM_ENVIRONMENT}"',
        'secret = "{{ vault_secret_value_here }}"',
        'password = "<insert-password-here-please>"',
    ],
)
def test_placeholders_skipped(text):
    assert scan([line(text)], CONFIG) == []


def test_same_secret_across_commits_is_one_group():
    secret = rand(ALNUM, 32)
    groups = dedupe(
        [found(secret, "newest"), found(secret, "middle"),
         found(secret, "oldest")]
    )
    assert len(groups) == 1
    assert groups[0].count == 3
    assert groups[0].first.commit == "oldest"


def test_same_secret_in_two_files_is_one_group():
    secret = rand(ALNUM, 32)
    groups = dedupe([found(secret, path="a.py"), found(secret, path="b.py")])
    assert [g.count for g in groups] == [2]


def test_different_secrets_are_separate_groups():
    groups = dedupe([found(rand(ALNUM, 32)), found(rand(ALNUM, 32))])
    assert len(groups) == 2


def test_fingerprint_does_not_contain_secret():
    secret = rand(ALNUM, 32)
    fp = fingerprint(found(secret))
    assert secret not in fp
    assert len(fp) == 64


def test_baseline_roundtrip_hides_known_findings(tmp_path: Path):
    lines = [line(fake("aws-access-key-id"))]
    groups = scan(lines, CONFIG)
    assert len(groups) == 1

    baseline_file = tmp_path / "baseline.json"
    write_baseline(baseline_file, groups)
    baseline = load_baseline(baseline_file)

    assert scan(lines, CONFIG, baseline=baseline) == []
    new = [line(fake("github-token"))]
    assert len(scan(lines + new, CONFIG, baseline=baseline)) == 1


def test_baseline_file_has_no_secrets(tmp_path: Path):
    text = fake("aws-access-key-id")
    baseline_file = tmp_path / "baseline.json"
    write_baseline(baseline_file, scan([line(text)], CONFIG))
    secret = text.split("'")[1]
    assert secret not in baseline_file.read_text()



def test_ignore_file(tmp_path: Path):
    (tmp_path / ".secretscanignore").write_text(
        "# comment\ndocs/*\n\n*.pem  # trailing comment\n"
    )
    assert load_ignore_file(tmp_path) == ["docs/*", "*.pem"]


def test_missing_ignore_file(tmp_path: Path):
    assert load_ignore_file(tmp_path) == []
import pytest
from secretscan.model import addedLine
from secretscan.rules import load_config
from secretscan.scanner import scan
from tests.fakes import ALNUM, rand

CONFIG = load_config()


def rules_for(text: str, path: str = "app.cfg") -> list[str]:
    groups = scan([addedLine("c1", path, 1, text)], CONFIG)
    return [g.first.rule_id for g in groups]


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        # .env and shell exports
        ("export AWS_SECRET_ACCESS_KEY=" + rand(ALNUM, 39) + "1",
         "generic-secret-unquoted"),
        ("REDIS_PASSWORD=Redis" + "Pass1!", "password-env"),
        # AWS credentials file and YAML
        ("aws_secret_access_key = " + rand(ALNUM, 39) + "1",
         "generic-secret-unquoted"),
        ("  secret_key_base: " + rand("0123456789abcdef", 64),
         "generic-secret-unquoted"),
        # JSON configs
        ('    "pass": "hunter' + '22",', "password-assignment"),
        ('  "auth": "' + rand(ALNUM, 40) + '"', "generic-secret"),
        # connection strings and credential files
        ("uri: mongodb://app" + ":s3cret" + "Pass1@db.example.com/main",
         "url-credentials"),
        ("machine example.com login me " + "password pass" + "123",
         "netrc-password"),
        ("admin:" + "$apr1" + "$tp8glkbm$" + rand(ALNUM, 22),
         "password-hash"),
        # PHP / WordPress
        ("$dbpasswd = 'pass" + "123';", "password-assignment"),
        ("define('AUTH_KEY', '" + rand(ALNUM + "!@#<>", 64) + "');",
         "php-define-secret"),
        # FileZilla XML
        ("<Pass>" + rand(ALNUM, 20) + "</Pass>", "xml-password"),
    ],
)
def test_real_world_secret_found(text: str, rule: str):
    assert rules_for(text) == [rule]


@pytest.mark.parametrize(
    "text",
    [
        # Flask examples: placeholder words, not real passwords
        "app.config.from_mapping(SECRET_KEY='dev', PASSWORD='default')",
        'login(client, "test", password="test")',
        'password = "secret"',
        "PASSWORD=password",
        # code and references, not values
        "export S3_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY",
        "secret_key = settings.SECRET_KEY_FROM_ENVIRONMENT",
        "token = os.environ.get('API_TOKEN')",
        "author_email = 'someone.longname@example.com'",
        "url = https://example.com/path:with:colons",
        "define('DB_PASSWORD', 'put your unique phrase here');",
    ],
)
def test_real_world_non_secret_ignored(text: str):
    assert rules_for(text) == []
import secrets
import string

UPPER = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def rand(charset: str, n: int) -> str:
    return "".join(secrets.choice(charset) for _ in range(n))


def fake(rule_id: str) -> str:
    if rule_id == "aws-access-key-id":
        return f"aws_id = '{'AKIA' + rand(UPPER, 16)}'"
    if rule_id == "github-token":
        return f"GH={'ghp_' + rand(ALNUM, 36)}"
    if rule_id == "github-fine-grained-pat":
        return f"GH={'github_pat_' + rand(ALNUM + '_', 82)}"
    if rule_id == "slack-token":
        return f"SLACK={'xoxb-' + rand(string.digits, 12)}-{rand(ALNUM, 24)}"
    if rule_id == "stripe-live-key":
        return f"stripe = '{'sk_' + 'live_' + rand(ALNUM, 24)}'"
    if rule_id == "google-api-key":
        return f"k = '{'AIza' + rand(ALNUM + '_-', 35)}'"
    if rule_id == "private-key":
        return "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    if rule_id == "jwt":
        parts = [rand(ALNUM, 20) for _ in range(3)]
        return f"auth: eyJ{parts[0]}.eyJ{parts[1]}.{parts[2]}"
    if rule_id == "generic-secret":
        return f'api_key = "{rand(ALNUM, 32)}"'
    raise KeyError(f"no fake secret generator for rule '{rule_id}'")
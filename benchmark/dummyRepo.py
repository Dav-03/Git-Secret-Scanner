import json
import random
import string
import subprocess
import uuid
from pathlib import Path

UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"

# Filler vocabulary, free of secret-like words.
WORDS = ["user", "order", "item", "price", "count", "total", "name",
         "index", "result", "value", "data", "page", "size", "status"]


def make_secret(r: random.Random) -> tuple[str, str]:
    """A fake secret of a random rule type: (value, line of code)."""
    def rand(chars: str, n: int) -> str:
        return "".join(r.choice(chars) for _ in range(n))

    kind = r.choice(["aws", "github", "slack", "stripe", "google", "jwt",
                     "generic"])
    if kind == "aws":
        s = "AKIA" + rand(UPPER_DIGITS, 16)
        return s, f'AWS_ACCESS_KEY_ID = "{s}"'
    if kind == "github":
        s = "ghp_" + rand(ALNUM, 36)
        return s, f"client = Github('{s}')"
    if kind == "slack":
        s = "xoxb-" + rand(string.digits, 12) + "-" + rand(ALNUM, 24)
        return s, f"SLACK_BOT = '{s}'"
    if kind == "stripe":
        s = "sk_" + "live_" + rand(ALNUM, 24)
        return s, f'stripe.api_key = "{s}"'
    if kind == "google":
        s = "AIza" + rand(ALNUM + "_-", 35)
        return s, f"MAPS = '{s}'"
    if kind == "jwt":
        a, b, c = (rand(ALNUM, 24) for _ in range(3))
        s = f"eyJ{a}.eyJ{b}.{c}"
        return s, f"auth = 'Bearer {s}'"
    s = rand(ALNUM, r.randint(24, 40))
    return s, f'api_key = "{s}"'


def make_decoy(r: random.Random) -> tuple[str, str]:
    """Something that looks like a secret but isn't: (type, line)."""
    kind = r.choice(["uuid", "placeholder", "env-lookup", "aws-example",
                     "template", "hash"])
    if kind == "uuid":
        return kind, f'request_token = "{uuid.UUID(int=r.getrandbits(128))}"'
    if kind == "placeholder":
        return kind, 'api_key = "your_api_key_goes_here"'
    if kind == "env-lookup":
        return kind, 'token = os.environ["API_TOKEN"]'
    if kind == "aws-example":
        return kind, 'aws_key = "AKIAIOSFODNN7' + 'EXAMPLE"'
    if kind == "template":
        return kind, 'secret = "${SECRET_FROM_VAULT_STORE}"'
    digest = "".join(r.choice(HEX) for _ in range(40))
    return kind, f'revision = "{digest}"'


def filler(r: random.Random) -> str:
    a, b = r.choice(WORDS), r.choice(WORDS)
    n = r.randint(0, 999)
    return r.choice([
        f"{a}_{n} = compute_{b}({a}, {b})",
        f"def get_{a}_{b}(self):",
        f"    return self.{a} * {n}",
        f"# TODO: clean up {a} {b}",
    ])


def build(out: Path, commits: int, secrets: int, decoys: int,
          seed: int = 1) -> dict:
    r = random.Random(seed)
    files = [f"src/{w}.py" for w in WORDS]
    contents: dict[str, list[str]] = {f: [] for f in files}
    secret_commits = set(r.sample(range(commits), min(secrets, commits)))
    decoy_commits = [r.randrange(commits) for _ in range(decoys)]
    truth = {"secrets": [], "decoys": []}

    stream = bytearray()

    def data(text: str) -> None:
        raw = text.encode()
        stream.extend(f"data {len(raw)}\n".encode() + raw + b"\n")

    for i in range(commits):
        path = r.choice(files)
        lines = [filler(r) for _ in range(r.randint(2, 8))]
        if i in secret_commits:
            value, line = make_secret(r)
            lines.append(line)
            truth["secrets"].append(value)
        for _ in range(decoy_commits.count(i)):
            kind, line = make_decoy(r)
            lines.append(line)
            truth["decoys"].append(kind)
        r.shuffle(lines)
        # Cap file length so old lines (some secrets) get deleted later and
        # survive only in history, which a history scan must still catch.
        contents[path] = (contents[path] + lines)[-200:]

        stream.extend(f"commit refs/heads/main\nmark :{i + 1}\n".encode())
        stream.extend(
            f"committer Bench <b@b> {1_600_000_000 + i} +0000\n".encode()
        )
        data(f"commit {i}")
        stream.extend(f"M 100644 inline {path}\n".encode())
        data("\n".join(contents[path]) + "\n")

    out.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(out)], check=True)
    subprocess.run(["git", "-C", str(out), "fast-import", "--quiet"],
                   input=bytes(stream), check=True)
    Path(f"{out}.truth.json").write_text(json.dumps(truth, indent=2))
    return truth
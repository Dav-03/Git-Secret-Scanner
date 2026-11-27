import secrets
import string
import subprocess
import sys
import tempfile
from pathlib import Path

PAUSE = "--no-pause" not in sys.argv


def fake_aws_key() -> str:
    chars = string.ascii_uppercase + string.digits
    return "AKIA" + "".join(secrets.choice(chars) for _ in range(16))


def step(title: str) -> None:
    print(f"\n=== {title} ===")
    if PAUSE:
        input("(press Enter) ")


def run(repo: Path, shown: str, *args: str) -> int:
    print(f"$ {shown}")
    result = subprocess.run(args, cwd=repo, text=True,
                            capture_output=True)
    output = (result.stdout + result.stderr).rstrip()
    if output:
        print(output)
    return result.returncode


def git(repo: Path, *args: str) -> int:
    return run(repo, "git " + " ".join(args), "git",
               "-c", "user.name=Demo", "-c", "user.email=demo@example.com",
               "-c", "commit.gpgsign=false", *args)


def secretscan(repo: Path, *args: str) -> int:
    return run(repo, "secretscan " + " ".join(args),
               sys.executable, "-m", "secretscan", *args)


def main() -> None:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        repo = Path(tmp)
        git(repo, "init", "-q", "-b", "main")

        step("1. A developer commits an AWS key, then 'removes' it")
        (repo / "config.py").write_text(f'AWS_KEY = "{fake_aws_key()}"\n')
        git(repo, "add", "config.py")
        git(repo, "commit", "-q", "-m", "Add config")
        (repo / "config.py").write_text('AWS_KEY = os.environ["AWS_KEY"]\n')
        git(repo, "commit", "-q", "-am", "Remove hardcoded key")
        print("\nThe file is clean now:")
        print((repo / "config.py").read_text().rstrip())

        step("2. The scanner still finds it in history")
        code = secretscan(repo, "scan")
        print(f"exit code {code}: 1 means a secret was found")

        step("3. Install the pre-commit hook, then try to commit a new key")
        secretscan(repo, "install-hook")
        (repo / "deploy.py").write_text(f'KEY = "{fake_aws_key()}"\n')
        git(repo, "add", "deploy.py")
        code = git(repo, "commit", "-q", "-m", "Add deploy script")
        log = subprocess.run(["git", "log", "--oneline"], cwd=repo,
                             capture_output=True, text=True).stdout
        print(f"\ncommit exit code {code}; commits in repo: "
              f"{len(log.splitlines())} (the blocked one was not created)")

        step("4. The fix: rotate the key, then keep it out of code")
        print("Revoke the leaked key and issue a new one. Deleting the "
              "line\ndoes not help: every clone still has the old commit. "
              "Load keys\nfrom environment variables or a secrets manager.")


if __name__ == "__main__":
    main()
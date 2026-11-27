# Git Secret Scanner

A CLI tool that scans a git repository's **full commit history** for hardcoded
credentials: API keys, access tokens and private keys. It combines regex rules
for known key formats with Shannon entropy analysis to catch generic secrets,
and runs as a CLI, a pre-commit hook and a GitHub Action.

Built for a cybersecurity course project. Inspired by
[gitleaks](https://github.com/gitleaks/gitleaks), with a smaller scope.

## Why history matters

Deleting a secret in a new commit does not remove it from the repo. Anyone who
clones it can still read every earlier version. This tool scans every line
ever added on every branch, so it finds secrets that were "removed" too.

## Install

Requires Python 3.11+ and git.

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -e .
```

## Usage

```bash
secretscan scan                   # scan the full history of the current repo
secretscan scan path/to/repo
secretscan scan --staged          # scan only staged changes
secretscan scan --exclude "docs/*"
```

Example output (secrets are always redacted):

```
4f1c2a9e config/settings.py:12 [aws-access-key-id] AKIA****************
91b0d3e7 app.py:40 [generic-secret] 8kQz********************  (+2 more)
2 finding(s) in 0.41s
```

Each secret is reported once, at the commit that introduced it; `(+N more)`
counts its other occurrences.

**Exit codes:** `0` clean, `1` secrets found, `2` error.

### Suppressing false positives

| Method | Scope |
|---|---|
| `# secretscan:ignore` at the end of a line | that line |
| `.secretscanignore` in the repo root (one path glob per line) | matching paths |
| `--exclude GLOB` | matching paths, this run |
| `--write-baseline baseline.json`, then `--baseline baseline.json` | all current findings; only new ones are reported |

Baseline files store SHA-256 fingerprints, never the secrets themselves.

## Pre-commit hook

Block commits that add secrets:

```bash
secretscan install-hook
```

Or with the [pre-commit](https://pre-commit.com) framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/<you>/<repo>
    rev: v0.1.0
    hooks:
      - id: secretscan
```

Bypass once with `git commit --no-verify`.

## GitHub Action

```yaml
# .github/workflows/secrets.yml
on: [push, pull_request]
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # full history; the default is 1 commit
      - uses: <you>/<repo>@v0.1.0
```

## How it works

```
git log -p --all --unified=0  ->  diff parser  ->  added lines
  ->  path filters  ->  regex rules (+ entropy check)  ->  allowlist
  ->  one finding per secret  ->  redacted report
```

1. **History:** one streaming `git log -p --all` process. Only added lines are
   scanned: every secret enters history as an added line exactly once.
2. **Rules** (`secretscan/rules.toml`): AWS, GitHub, Slack, Stripe, Google,
   private keys, JWTs, and a generic `name = "value"` rule.
3. **Entropy:** the generic rule only fires if the value looks random (Shannon
   entropy >= 3.0 bits/char for hex, >= 3.5 otherwise, at least 16 chars).
   This separates `api_key = "8kQz..."` from `password = "changeme"`.
4. **Allowlist:** skips lockfiles and vendored code, and values containing
   placeholders like `example`, `your_` or `${`.

## Results

From `bench/run_bench.py` on generated repos with planted fake secrets and
decoys (full report in [bench/results.md](bench/results.md)):

| Metric | Result |
|---|---|
| Detection rate | 200/200 (100%) |
| Precision | 75.5% (all false positives were UUIDs) |
| Scan time, 10,000 commits | ~0.9s |
| Scan time, 50,000 commits | ~4.7s |

Reproduce with `python bench/run_bench.py`.

## Limitations

- **Binary files** are not scanned (git shows no diff for them).
- **Merge commits** are not scanned, so a secret added only while resolving a
  merge conflict is missed.
- **UUIDs** assigned to token-like names are flagged: their entropy clears the
  threshold.
- **Multi-line secrets** are matched by their first line only (e.g. the
  `-----BEGIN ... PRIVATE KEY-----` header).
- The benchmark corpus was written alongside the rules, so its numbers are an
  upper bound, not an independent measurement.

## If you find a real secret

Removing it from the code is not enough. **Rotate it first** (revoke the key
and issue a new one), then store it in environment variables or a secrets
manager. Rewriting history alone does not help, because clones and forks
keep the old commits.

## Development

```bash
pip install -e . --group dev
pytest -q --cov=secretscan
ruff check .
```

## License

MIT

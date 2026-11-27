import csv
import sys
from collections import defaultdict
from pathlib import Path
from secretscan.detector import detect
from secretscan.filters import filter_lines
from secretscan.gitSource import history
from secretscan.rules import load_config

REPO = Path(sys.argv[1])
VERBOSE = "-v" in sys.argv

answer: dict[str, tuple[int, int]] = {}
for row in csv.reader(open(REPO / ".leaky-meta/secrets.csv")):
    if row and not row[0].startswith("#") and len(row) >= 3 \
            and row[1].strip().isdigit():
        answer[row[0].strip()] = (int(row[1]), int(row[2]))

config = load_config()
lines = filter_lines(history(REPO), config.allowlist.paths)
flagged: dict[str, set[int]] = defaultdict(set)
rules_hit: dict[str, set[str]] = defaultdict(set)
for f in detect(lines, config.rules):
    if f.path.startswith(".leaky-meta"):
        continue
    stop = config.allowlist.stopwords
    if any(w in f.secret.lower() for w in stop):
        continue
    flagged[f.path].add(f.line_number)
    rules_hit[f.path].add(f.rule_id)

total_risk = sum(r for r, _ in answer.values())
risk_files = {p for p, (r, _) in answer.items() if r}
found = fp = 0
for path, nums in flagged.items():
    risk, info = answer.get(path, (0, 0))
    found += min(len(nums), risk)
    fp += max(0, len(nums) - risk - info)

covered = risk_files & set(flagged)
print(f"files covered: {len(covered)}/{len(risk_files)} "
      f"({len(covered) / len(risk_files):.0%})")
print(f"risk lines found: {found}/{total_risk} ({found / total_risk:.0%})")
print(f"likely false positives: {fp}")
if VERBOSE:
    for p in sorted(risk_files):
        risk, _ = answer[p]
        n = len(flagged.get(p, ()))
        mark = "ok " if n else "MISS"
        print(f"  {mark} {p}: {min(n, risk)}/{risk} "
              f"{sorted(rules_hit.get(p, []))}")
    extra = sorted(set(flagged) - risk_files)
    if extra:
        print("  flagged files with no listed risk:", extra)
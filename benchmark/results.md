# Benchmark results

Windows, Python 3.13.14.

## Accuracy

200 planted secrets, 400 decoys ({'env-lookup': 68, 'placeholder': 72, 'aws-example': 59, 'uuid': 69, 'template': 69, 'hash': 63}).

| Detected | Detection rate | Findings | False positives | Precision |
|---|---|---|---|---|
| 200/200 | 100.0% | 265 | 65 | 75.5% |

False positives (first 5):

- `34e608d7-4efa-8ce6-999e-44e80902409a`
- `4ed33a14-5b54-a745-d1ee-f6f26400ff44`
- `b5d496fa-14b2-e6e2-bfed-ff2caeb171ef`
- `21ccabed-2163-ed52-630b-9047dbba026f`
- `d5c09090-ac09-5132-2327-c7da1e62dd77`

## Runtime

| Repo | Commits | Scan time |
|---|---|---|
| synthetic | 100 | 0.08s |
| synthetic | 1,000 | 0.17s |
| synthetic | 10,000 | 1.05s |
| synthetic | 50,000 | 4.96s |

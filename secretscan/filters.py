import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from .model import Found, addedLine

INLINE_IGNORE = "secretscan:ignore"
IGNORE_FILE = ".secretscanignore"



def path_excluded(path: str, globs: Iterable[str]) -> bool:
    """Patterns without '/' match the file name; others the full path."""
    name = PurePosixPath(path).name
    for pattern in globs:
        target = path if "/" in pattern else name
        if fnmatchcase(target, pattern):
            return True
    return False


def filter_lines(
    lines: Iterable[addedLine], path_globs: Iterable[str]) -> Iterator[addedLine]:
    globs = tuple(path_globs)
    for line in lines:
        if INLINE_IGNORE in line.text:
            continue
        if globs and path_excluded(line.path, globs):
            continue
        yield line


def load_ignore_file(repo: str | Path) -> list[str]:
    file = Path(repo) / IGNORE_FILE
    if not file.is_file():
        return []
    globs = []
    for raw in file.read_text("utf-8").splitlines():
        entry = raw.split("#", 1)[0].strip()
        if entry:
            globs.append(entry)
    return globs



def has_stopword(secret: str, stopwords: Iterable[str]) -> bool:
    lower = secret.lower()
    return any(word in lower for word in stopwords)


def drop_stopwords(
    findings: Iterable[Found], stopwords: Iterable[str]) -> Iterator[Found]:
    words = tuple(stopwords)
    for f in findings:
        if not has_stopword(f.secret, words):
            yield f



def fingerprint(f: Found) -> str:
    """Stable ID for a secret. Hashed so baselines never store secrets."""
    return hashlib.sha256(f"{f.rule_id}:{f.secret}".encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Group:
    fingerprint: str
    first: Found
    count: int


def dedupe(findings: Iterable[Found]) -> list[Group]:
    
    firsts: dict[str, Found] = {}
    counts: dict[str, int] = {}
    for f in findings:
        fp = fingerprint(f)
        firsts[fp] = f
        counts[fp] = counts.get(fp, 0) + 1
    return [Group(fp, firsts[fp], counts[fp]) for fp in firsts]



def load_baseline(path: Path) -> set[str]:
    data = json.loads(Path(path).read_text("utf-8"))
    fingerprints = data.get("fingerprints", [])
    if not all(isinstance(fp, str) for fp in fingerprints):
        raise ValueError(f"invalid baseline file: {path}")
    return set(fingerprints)


def write_baseline(path: Path, groups: Iterable[Group]) -> None:
    data = {"fingerprints": sorted(g.fingerprint for g in groups)}
    Path(path).write_text(json.dumps(data, indent=2) + "\n", "utf-8")
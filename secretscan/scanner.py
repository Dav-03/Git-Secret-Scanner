from collections.abc import Iterable

from .detector import detect
from .filters import Group, dedupe, drop_stopwords, filter_lines
from .model import addedLine
from .rules import Config


def scan(
    lines: Iterable[addedLine],
    config: Config,
    extra_excludes: Iterable[str] = (),
    baseline: set[str] | None = None,
) -> list[Group]:
    globs = (*config.allowlist.paths, *extra_excludes)
    kept = filter_lines(lines, globs)
    findings = drop_stopwords(detect(kept, config.rules), config.allowlist.stopwords)
    groups = dedupe(findings)
    if baseline:
        groups = [g for g in groups if g.fingerprint not in baseline]
    return groups
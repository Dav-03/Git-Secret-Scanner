from collections.abc import Iterable, Iterator

from .entropy import is_high_entropy, shannon_entropy
from .model import Found, addedLine
from .rules import Rule


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < t_end and t_start < end for t_start, t_end in taken)


def detect_line(line: addedLine, rules: list[Rule]) -> Iterator[Found]:
    lower = line.text.lower()
    taken: list[tuple[int, int]] = []  # spans already reported on this line

    for rule in rules:
        if rule.keywords and not any(k in lower for k in rule.keywords):
            continue

        for match in rule.pattern.finditer(line.text):
            secret = match.group(rule.secret_group)
            span = match.span(rule.secret_group)
            if not secret or _overlaps(span, taken):
                continue
            if rule.entropy and not is_high_entropy(secret):
                continue

            taken.append(span)
            yield Found(
                rule_id=rule.id,
                commit=line.commit,
                path=line.path,
                line_number=line.line_number,
                secret=secret,
                entropy=round(shannon_entropy(secret), 2),
            )


def detect(lines: Iterable[addedLine], rules: list[Rule]) -> Iterator[Found]:
    for line in lines:
        yield from detect_line(line, rules)
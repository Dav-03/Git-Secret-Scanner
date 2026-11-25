import re
from collections.abc import Iterable, Iterator

from .model import addedLine

PREFIX = "COMMIT:"
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def unquote(path: str) -> str:
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        path = (
            path[1:-1]
            .encode("latin-1", "backslashreplace")
            .decode("unicode_escape")
        )
        path = path.encode("latin-1", "replace").decode("utf-8", "replace")
    return path


def new_path(line: str) -> str | None:
    target = unquote(line[4:].rstrip("\n").split("\t", 1)[0])
    if target == "/dev/null":
        return None
    return target[2:] if target.startswith("b/") else target


def parse_difference(
    lines: Iterable[str], default_commit: str
) -> Iterator[addedLine]:
    commit = default_commit
    path = None
    in_header = False
    line_number = 0
    remaining = 0

    for raw_line in lines:
        line = raw_line.rstrip("\r\n")

        if remaining > 0:
            if line.startswith("+"):
                if path is not None:
                    yield addedLine(commit, path, line_number, line[1:])
                line_number += 1
                remaining -= 1
                continue
            if line.startswith(" "):
                line_number += 1
                remaining -= 1
                continue
            if line.startswith(("-", "\\")):
                continue
            remaining = 0

        # Reading git diff headers
        if line.startswith(PREFIX):
            commit = line[len(PREFIX) :].strip()
            path = None
            in_header = False
        elif line.startswith("diff --git ") or line.startswith("diff --cc "):
            path = None
            in_header = True
        elif in_header and line.startswith("+++ "):
            path = new_path(line)
        elif in_header and line.startswith("Binary files "):
            path = None
        elif line.startswith("@@"):
            m = HUNK_RE.match(line)
            if m:
                in_header = False
                line_number = int(m.group(1))
                if m.group(2) is not None:
                    remaining = int(m.group(2))
                else:
                    remaining = 1

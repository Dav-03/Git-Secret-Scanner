from importlib.metadata import PackageNotFoundError, version

from .filters import Group


def tool_version() -> str:
    try:
        return version("git-secret-scanner")
    except PackageNotFoundError:
        return "0.0.0"


def to_text(groups: list[Group]) -> str:
    lines = []
    for g in groups:
        f = g.first
        more = f"  (+{g.count - 1} more)" if g.count > 1 else ""
        lines.append(
            f"{f.commit[:8]} {f.path}:{f.line_number} "
            f"[{f.rule_id}] {f.redacted()}{more}"
        )
    return "\n".join(lines) + ("\n" if lines else "")
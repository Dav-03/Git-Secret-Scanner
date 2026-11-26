import re
import tomllib
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path


class RuleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    pattern: re.Pattern[str]
    keywords: tuple[str, ...]
    secret_group: int = 1
    entropy: bool = False


def _build_rule(raw: dict, index: int) -> Rule:
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise RuleError(f"rule #{index}: missing 'id'")

    regex = raw.get("regex")
    if not isinstance(regex, str) or not regex:
        raise RuleError(f"rule '{rule_id}': missing 'regex'")
    try:
        pattern = re.compile(regex)
    except re.error as e:
        raise RuleError(f"rule '{rule_id}': invalid regex: {e}") from e

    group = raw.get("secret_group", 1)
    if not isinstance(group, int) or not 0 <= group <= pattern.groups:
        raise RuleError(
            f"rule '{rule_id}': secret_group {group} out of range "
            f"(regex has {pattern.groups} groups)"
        )

    keywords = tuple(k.lower() for k in raw.get("keywords", []))
    return Rule(
        id=rule_id,
        pattern=pattern,
        keywords=keywords,
        secret_group=group,
        entropy=bool(raw.get("entropy", False)),
    )


@dataclass(frozen=True, slots=True)
class Allowlist:
    paths: tuple[str, ...] = ()
    stopwords: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Config:
    rules: list[Rule]
    allowlist: Allowlist


def _read_toml(path: Path | None) -> dict:
    if path is None:
        text = (files("secretscan") / "rules.toml").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise RuleError(f"invalid TOML: {e}") from e


def _build_allowlist(raw: dict) -> Allowlist:
    paths = raw.get("paths", [])
    stopwords = raw.get("stopwords", [])
    if not all(isinstance(p, str) for p in [*paths, *stopwords]):
        raise RuleError("allowlist entries must be strings")
    return Allowlist(
        paths=tuple(paths),
        stopwords=tuple(s.lower() for s in stopwords),
    )


def load_config(path: Path | None = None) -> Config:
    """Load rules and allowlist from `path`, or the bundled rules.toml."""
    data = _read_toml(path)
    return Config(
        rules=_build_rules(data),
        allowlist=_build_allowlist(data.get("allowlist", {})),
    )


def load_rules(path: Path | None = None) -> list[Rule]:
    """Load only the rules from `path`, or the bundled rules.toml."""
    return _build_rules(_read_toml(path))


def _build_rules(data: dict) -> list[Rule]:
    raw_rules = data.get("rules", [])
    if not raw_rules:
        raise RuleError("no rules defined")

    rules = [_build_rule(raw, i) for i, raw in enumerate(raw_rules)]
    ids = [r.id for r in rules]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise RuleError(f"duplicate rule ids: {sorted(duplicates)}")
    return rules
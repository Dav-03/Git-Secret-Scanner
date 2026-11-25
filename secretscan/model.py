from dataclasses import dataclass

STAGED = "STAGED"


@dataclass(frozen=True, slots=True)
class addedLine:
    commit: str
    path: str
    line_number: int
    text: str


@dataclass(frozen=True, slots=True)
class Found:
    rule_id: str
    commit: str
    path: str
    line_number: int
    secret: str
    entropy: float | None = None

    def redacted(self) -> str:
        s = self.secret
        if len(s) > 8:
            return s[:4] + "*" * max(len(s) - 4, 4)
        else:
            return "*" * len(s)

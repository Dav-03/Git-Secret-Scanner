import math
from collections import Counter

HEX_CHARS = frozenset("0123456789abcdefABCDEF")

MIN_LENGTH = 16
HEX_THRESHOLD = 3.0  # hex max is 4.0 bits/char
DEFAULT_THRESHOLD = 3.5  # alphanumeric max is ~5.95 bits/char


def shannon_entropy(s: str) -> float:
    """Bits per character: H = -sum(p(c) * log2(p(c)))."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def threshold_for(s: str) -> float:
    return HEX_THRESHOLD if set(s) <= HEX_CHARS else DEFAULT_THRESHOLD


def is_high_entropy(s: str) -> bool:
    if len(s) < MIN_LENGTH:
        return False
    return shannon_entropy(s) >= threshold_for(s)
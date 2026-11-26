import pytest

from secretscan.entropy import is_high_entropy, shannon_entropy
from tests.fakes import ALNUM, HEX, rand


@pytest.mark.parametrize(
    ("s", "expected"),
    [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("abcd", 2.0), ("aabb", 1.0)],
)
def test_entropy_exact_values(s, expected):
    assert shannon_entropy(s) == pytest.approx(expected)


def test_random_hex_is_high_entropy():
    assert is_high_entropy(rand(HEX, 32))


def test_random_alnum_is_high_entropy():
    assert is_high_entropy(rand(ALNUM, 32))


@pytest.mark.parametrize(
    "s",
    ["your_api_key_here", "aaaaaaaaaaaaaaaaaaaaaaaa", "1111222233334444"],
)
def test_low_entropy_strings_rejected(s):
    assert not is_high_entropy(s)


def test_short_strings_rejected():
    assert not is_high_entropy(rand(ALNUM, 15))
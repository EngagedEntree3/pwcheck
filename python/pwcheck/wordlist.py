"""Loader for the shared weak-token wordlist.

The canonical list lives in ``data/common_passwords.txt`` at the repository
root so that the Python and JavaScript implementations cannot drift apart.
A small embedded fallback keeps the module importable when the package is
vendored into a service without the data directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import FrozenSet

# Walk up from python/pwcheck/wordlist.py to the repository root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORDLIST_PATH = _REPO_ROOT / "data" / "common_passwords.txt"

# Minimal safety net: if the data file is missing we still reject the very
# worst passwords rather than silently reporting them as strong.
_FALLBACK: FrozenSet[str] = frozenset(
    {
        "password", "passwd", "letmein", "welcome", "admin", "root", "login",
        "qwerty", "abc123", "123456", "12345678", "123456789", "iloveyou",
        "monkey", "dragon", "shadow", "master", "sunshine", "princess",
        "football", "baseball", "trustno1", "changeme", "secret", "111111",
    }
)

# Shortest token we are willing to match. Below four characters the match rate
# against ordinary passwords is so high that the signal becomes noise.
MIN_TOKEN_LENGTH = 4


def _parse(text: str) -> FrozenSet[str]:
    """Parse the wordlist format: one lowercase token per line, ``#`` comments."""
    tokens = set()
    for raw_line in text.splitlines():
        line = raw_line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if len(line) >= MIN_TOKEN_LENGTH:
            tokens.add(line)
    return frozenset(tokens)


def load(path: Path | None = None) -> FrozenSet[str]:
    """Return the weak-token set, falling back to the embedded list on error."""
    target = path or _WORDLIST_PATH
    try:
        return _parse(target.read_text(encoding="utf-8")) or _FALLBACK
    except OSError:
        return _FALLBACK


#: Module-level cache. Loading is cheap and happens once per process.
COMMON_TOKENS: FrozenSet[str] = load()

#: Length of the longest token, used to bound substring scanning.
MAX_TOKEN_LENGTH: int = max((len(t) for t in COMMON_TOKENS), default=MIN_TOKEN_LENGTH)

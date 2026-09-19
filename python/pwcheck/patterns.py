"""Pattern detectors used to discount predictable regions of a password.

Security rationale
------------------
Naive strength meters multiply length by the size of the character set. That
badly overestimates passwords like ``Password123!``: a real attacker does not
brute-force it character by character, they run a dictionary with mangling
rules and find it in seconds.

Each detector below finds a region an attacker can guess *cheaply*. The core
scorer then replaces that region's brute-force entropy with the (much smaller)
cost of guessing it from the relevant pattern space. Detectors only report
locations and sizes here; the scoring model lives in ``core.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Sequence

# Minimum run lengths. Shorter runs occur so often in ordinary passwords that
# penalising them would punish good passwords for coincidences.
MIN_REPEAT_LENGTH = 3
MIN_SEQUENCE_LENGTH = 3
MIN_KEYBOARD_RUN = 3

# Single-pass leetspeak folding. We deliberately do not expand every possible
# substitution combination: one canonical form catches the overwhelming
# majority of real-world mangling at a fraction of the cost, and the cost
# matters because this runs on every keystroke in the browser.
LEET_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i",
    "|": "l", "+": "t", "(": "c", "<": "c",
}

# Some glyphs stand in for more than one letter: "1" is used for both "l"
# ("he11o") and "i" ("adm1n"), and "!" for both "i" and "l". One pass cannot
# resolve both readings, so we fold twice and match against each result.
LEET_ALT_OVERRIDES = {"1": "i", "!": "l"}
LEET_MAP_ALT = {**LEET_MAP, **LEET_ALT_OVERRIDES}

# Physical QWERTY rows, used to catch walks like "qwerty" or "1qaz" that are
# invisible to alphabetical-sequence detection.
_KEYBOARD_ROWS: Sequence[str] = (
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "~!@#$%^&*()_+",
    "QWERTYUIOP{}|",
    'ASDFGHJKL:"',
    "ZXCVBNM<>?",
)

_YEAR_RE = re.compile(r"(?:19|20)\d{2}")


@dataclass(frozen=True)
class Match:
    """A predictable region found inside a password.

    ``start``/``length`` index into the *original* password, so matches found
    in the leet-normalised form stay aligned (normalisation is 1:1).
    """

    kind: str       # "dictionary" | "repeat" | "sequence" | "keyboard" | "date"
    token: str      # the matched text (normalised form for dictionary hits)
    start: int
    length: int

    @property
    def end(self) -> int:
        """Exclusive end index."""
        return self.start + self.length


def normalize_leet(password: str, *, alternate: bool = False) -> str:
    """Fold common character substitutions so ``P4$$w0rd`` matches ``password``.

    Length is preserved 1:1 so match offsets remain valid against the original.

    Args:
        alternate: Use the second reading of ambiguous glyphs - ``1`` as "i"
            and ``!`` as "l" - which catches ``adm1n`` where the primary
            reading catches ``he11o``.
    """
    table = LEET_MAP_ALT if alternate else LEET_MAP
    return "".join(table.get(ch, ch) for ch in password.lower())


def leet_variants(password: str) -> List[str]:
    """The forms to match against, in a deterministic, duplicate-free order.

    Order matters: a ``set`` here would make the reported token depend on hash
    randomisation, so identical input could produce different wording between
    runs.
    """
    forms = [
        password.lower(),
        normalize_leet(password),
        normalize_leet(password, alternate=True),
    ]
    unique: List[str] = []
    for form in forms:
        if form not in unique:
            unique.append(form)
    return unique


def find_repeats(password: str) -> List[Match]:
    """Find runs of one repeated character, e.g. ``aaaa`` or ``!!!``."""
    matches: List[Match] = []
    start = 0
    for index in range(1, len(password) + 1):
        if index == len(password) or password[index] != password[start]:
            length = index - start
            if length >= MIN_REPEAT_LENGTH:
                matches.append(
                    Match("repeat", password[start:index], start, length)
                )
            start = index
    return matches


def find_sequences(password: str) -> List[Match]:
    """Find ascending or descending character runs, e.g. ``12345`` or ``dcba``.

    Works on code points, so it covers digits and letters with one rule. Runs
    must stay within a single character class to avoid nonsense matches across
    the ASCII boundary between digits and letters.
    """
    lowered = password.lower()
    matches: List[Match] = []
    start = 0
    direction = 0

    def same_class(a: str, b: str) -> bool:
        return (a.isdigit() and b.isdigit()) or (a.isalpha() and b.isalpha())

    for index in range(1, len(lowered) + 1):
        step = 0
        if index < len(lowered) and same_class(lowered[index - 1], lowered[index]):
            delta = ord(lowered[index]) - ord(lowered[index - 1])
            step = delta if delta in (1, -1) else 0

        if step == 0 or (direction != 0 and step != direction):
            length = index - start
            if length >= MIN_SEQUENCE_LENGTH and direction != 0:
                matches.append(
                    Match("sequence", password[start:index], start, length)
                )
            # A broken run restarts at the character that broke it, which may
            # itself begin the next run (e.g. "abcXcba").
            start = index - 1 if step != 0 else index
            direction = step
        else:
            direction = step

    return matches


def find_keyboard_walks(password: str) -> List[Match]:
    """Find runs that trace adjacent keys on a QWERTY layout, e.g. ``asdfgh``."""
    matches: List[Match] = []
    index = 0
    while index < len(password):
        best = 0
        for row in _KEYBOARD_ROWS:
            reverse_row = row[::-1]
            length = MIN_KEYBOARD_RUN
            while index + length <= len(password):
                chunk = password[index : index + length]
                if chunk in row or chunk in reverse_row:
                    best = max(best, length)
                    length += 1
                else:
                    break
        if best:
            matches.append(
                Match("keyboard", password[index : index + best], index, best)
            )
            index += best
        else:
            index += 1
    return matches


def find_dates(password: str) -> List[Match]:
    """Find four-digit years (1900-2099), the classic password suffix."""
    return [
        Match("date", m.group(0), m.start(), len(m.group(0)))
        for m in _YEAR_RE.finditer(password)
    ]


def find_dictionary_words(
    password: str,
    tokens: Iterable[str],
    min_length: int = 4,
    max_length: int | None = None,
) -> List[Match]:
    """Find weak-list tokens inside the password, case- and leet-insensitive.

    Scans the lowercased form and the leet-folded form. Bounded by
    ``max_length`` so the substring scan stays linear in practice.
    """
    token_set = tokens if isinstance(tokens, (set, frozenset)) else frozenset(tokens)
    if not token_set:
        return []

    limit = max_length or max(len(t) for t in token_set)
    variants = leet_variants(password)
    seen: set[tuple[int, int]] = set()
    matches: List[Match] = []

    for variant in variants:
        for start in range(len(variant)):
            # Longest match first: "password" should win over "pass".
            for length in range(min(limit, len(variant) - start), min_length - 1, -1):
                candidate = variant[start : start + length]
                if candidate in token_set:
                    if (start, length) not in seen:
                        seen.add((start, length))
                        matches.append(Match("dictionary", candidate, start, length))
                    break
    return matches


def is_single_repeated_block(password: str) -> bool:
    """True for passwords that are one short block repeated, e.g. ``abcabcabc``."""
    length = len(password)
    if length < 4:
        return False
    for block in range(1, length // 2 + 1):
        if length % block == 0 and password[:block] * (length // block) == password:
            return True
    return False


def find_all(password: str, tokens: Iterable[str]) -> List[Match]:
    """Run every detector and return the union of their matches (may overlap)."""
    return [
        *find_dictionary_words(password, tokens),
        *find_keyboard_walks(password),
        *find_sequences(password),
        *find_repeats(password),
        *find_dates(password),
    ]


def select_non_overlapping(matches: Sequence[Match]) -> List[Match]:
    """Reduce overlapping matches to one explanation per character.

    ``1234`` is both a sequence and a keyboard walk; charging for both would
    double-count. Longest match wins, ties broken by detector precedence so the
    most informative explanation survives.
    """
    precedence = {"dictionary": 0, "keyboard": 1, "sequence": 2, "repeat": 3, "date": 4}
    ordered = sorted(
        matches, key=lambda m: (-m.length, precedence.get(m.kind, 99), m.start)
    )
    claimed: set[int] = set()
    chosen: List[Match] = []
    for match in ordered:
        span = set(range(match.start, match.end))
        if span & claimed:
            continue
        claimed |= span
        chosen.append(match)
    return sorted(chosen, key=lambda m: m.start)

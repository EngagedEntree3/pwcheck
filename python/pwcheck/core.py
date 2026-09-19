"""Password strength scoring model.

The model has three stages:

1. **Raw entropy** - ``length * log2(pool_size)``, the cost of a pure
   brute-force search over the character classes actually used.
2. **Pattern discounting** - every predictable region found by
   :mod:`pwcheck.patterns` has its brute-force cost replaced by the far
   cheaper cost of guessing it from its own pattern space. This is what stops
   ``Password123!`` from scoring as a 78-bit password when an attacker cracks
   it in under a second.
3. **Policy caps** - hard limits that no amount of entropy can buy past, such
   as the 8-character minimum.

The result is an *estimate*. It is a defensive heuristic for guiding users, not
a guarantee; see the README for what it deliberately does not do.
"""

from __future__ import annotations

import math
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

from . import patterns
from .wordlist import COMMON_TOKENS

# --- policy -----------------------------------------------------------------

MIN_LENGTH = 8           # below this the password is rejected outright
IDEAL_LENGTH = 12        # target length for a "strong" verdict
MAX_ANALYSIS_LENGTH = 256  # bound the work an untrusted caller can trigger

SCORE_LABELS = ("Very weak", "Weak", "Fair", "Strong", "Excellent")

# Effective-entropy thresholds (bits) for each score band.
SCORE_THRESHOLDS = (28, 36, 60, 80)

# --- attacker model ---------------------------------------------------------

# Offline attack against a fast, unsalted hash on commodity GPUs. Pessimistic
# on purpose: we would rather understate a password's life expectancy.
OFFLINE_GUESSES_PER_SECOND = 1e10
# Online attack against a login endpoint with basic rate limiting.
ONLINE_GUESSES_PER_SECOND = 100.0

# --- character pools --------------------------------------------------------

POOL_LOWERCASE = 26
POOL_UPPERCASE = 26
POOL_DIGITS = 10
POOL_SYMBOLS = 33   # printable ASCII punctuation
POOL_SPACE = 1
POOL_OTHER = 100    # conservative stand-in for non-ASCII code points


@dataclass(frozen=True)
class Requirement:
    """One line of the user-facing checklist."""

    id: str
    label: str
    met: bool


@dataclass(frozen=True)
class Penalty:
    """Entropy removed because a region of the password is predictable."""

    id: str
    label: str
    bits: float


@dataclass(frozen=True)
class Result:
    """Full evaluation of a single password."""

    length: int
    score: int
    label: str
    entropy_bits: float
    raw_entropy_bits: float
    pool_size: int
    requirements: List[Requirement]
    penalties: List[Penalty]
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    crack_time_offline_seconds: float = 0.0
    crack_time_online_seconds: float = 0.0
    crack_time_display: str = ""

    @property
    def is_acceptable(self) -> bool:
        """True when the password clears the minimum policy bar (score >= 2)."""
        return self.score >= 2

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable form, suitable for an API response.

        Infinite crack times become ``None``: ``Infinity`` is not valid JSON
        and would break strict parsers on the receiving end.
        """
        data = asdict(self)
        data["is_acceptable"] = self.is_acceptable
        for key in ("crack_time_offline_seconds", "crack_time_online_seconds"):
            if math.isinf(data[key]):
                data[key] = None
        return data


def _character_pool(password: str) -> tuple[int, Dict[str, bool]]:
    """Return the search-space size and which character classes are present."""
    classes = {
        "lowercase": False,
        "uppercase": False,
        "digit": False,
        "symbol": False,
        "space": False,
        "other": False,
    }
    for ch in password:
        if ch.islower():
            classes["lowercase"] = True
        elif ch.isupper():
            classes["uppercase"] = True
        elif ch.isdigit():
            classes["digit"] = True
        elif ch == " ":
            classes["space"] = True
        elif 33 <= ord(ch) <= 126:
            classes["symbol"] = True
        else:
            classes["other"] = True

    pool = (
        POOL_LOWERCASE * classes["lowercase"]
        + POOL_UPPERCASE * classes["uppercase"]
        + POOL_DIGITS * classes["digit"]
        + POOL_SYMBOLS * classes["symbol"]
        + POOL_SPACE * classes["space"]
        + POOL_OTHER * classes["other"]
    )
    return max(pool, 1), classes


def _replacement_bits(match: patterns.Match, pool_size: int, token_count: int) -> float:
    """Cost of guessing a matched region *from its own pattern space*.

    Far cheaper than brute force, which is exactly the point: this is the
    number an attacker actually pays.
    """
    length_bits = math.log2(max(match.length, 1))
    if match.kind == "dictionary":
        # Index into the weak list, plus ~4 bits for case and leet mangling.
        return math.log2(max(token_count, 2)) + 4.0
    if match.kind == "keyboard":
        # Starting key (~47) x direction (2), times the run length.
        return math.log2(94) + length_bits
    if match.kind == "sequence":
        # Starting character (~36) x direction (2), times the run length.
        return math.log2(72) + length_bits
    if match.kind == "repeat":
        # One character chosen from the pool, plus the run length.
        return math.log2(pool_size) + length_bits
    if match.kind == "date":
        return math.log2(200)  # years 1900-2099
    return length_bits


_MATCH_LABELS = {
    "dictionary": "Contains the common word or password “{token}”",
    "keyboard": "Contains the keyboard pattern “{token}”",
    "sequence": "Contains the sequence “{token}”",
    "repeat": "Repeats the character “{char}” {length} times in a row",
    "date": "Contains what looks like a year ({token})",
}


def _describe(match: patterns.Match) -> str:
    template = _MATCH_LABELS.get(match.kind, "Contains a predictable pattern")
    return template.format(
        token=match.token, char=match.token[:1], length=match.length
    )


#: (singular, plural, seconds) ordered from largest unit to smallest.
_DURATION_UNITS = (
    ("century", "centuries", 60 * 60 * 24 * 365.25 * 100),
    ("year", "years", 60 * 60 * 24 * 365.25),
    ("month", "months", 60 * 60 * 24 * 30.44),
    ("day", "days", 60 * 60 * 24),
    ("hour", "hours", 60 * 60),
    ("minute", "minutes", 60),
    ("second", "seconds", 1),
)


def _format_duration(seconds: float) -> str:
    """Human-readable duration, tuned for the enormous range involved."""
    if seconds == math.inf:
        return "effectively forever"
    if seconds < 1:
        return "less than a second"
    for singular, plural, size in _DURATION_UNITS:
        if seconds >= size:
            value = seconds / size
            if value >= 1e6:
                return f"{value:.3g} {plural}"
            rounded = int(round(value))
            return f"{rounded} {singular if rounded == 1 else plural}"
    return "less than a second"


def _build_requirements(
    length: int, classes: Dict[str, bool], has_patterns: bool
) -> List[Requirement]:
    """The live checklist shown in the UI and returned by the API."""
    return [
        Requirement("min_length", f"At least {MIN_LENGTH} characters", length >= MIN_LENGTH),
        Requirement("ideal_length", f"{IDEAL_LENGTH} or more characters", length >= IDEAL_LENGTH),
        Requirement("lowercase", "Contains a lowercase letter", classes["lowercase"]),
        Requirement("uppercase", "Contains an uppercase letter", classes["uppercase"]),
        Requirement("digit", "Contains a number", classes["digit"]),
        Requirement("symbol", "Contains a special character", classes["symbol"] or classes["space"]),
        Requirement("no_patterns", "No common words or predictable patterns", not has_patterns),
    ]


def _build_suggestions(requirements: List[Requirement], score: int) -> List[str]:
    """Actionable advice, ordered by how much it would improve the score."""
    unmet = {r.id for r in requirements if not r.met}
    suggestions: List[str] = []
    if "min_length" in unmet:
        suggestions.append(f"Use at least {MIN_LENGTH} characters.")
    elif "ideal_length" in unmet:
        suggestions.append(f"Length helps more than anything else - aim for {IDEAL_LENGTH}+ characters.")
    if "no_patterns" in unmet:
        suggestions.append("Avoid dictionary words, names, years and keyboard runs.")
    missing_classes = [
        label
        for key, label in (
            ("uppercase", "uppercase letters"),
            ("lowercase", "lowercase letters"),
            ("digit", "numbers"),
            ("symbol", "special characters"),
        )
        if key in unmet
    ]
    if missing_classes:
        suggestions.append("Mix in " + ", ".join(missing_classes) + ".")
    if score < 2:
        suggestions.append(
            "A passphrase of four or more unrelated words is both stronger and easier to remember."
        )
    return suggestions


def evaluate(
    password: str,
    *,
    tokens: Optional[FrozenSet[str]] = None,
    user_inputs: Optional[List[str]] = None,
) -> Result:
    """Evaluate ``password`` and return a :class:`Result`.

    Args:
        password: The candidate password. Must be a ``str``.
        tokens: Override the weak-token list (useful for tests).
        user_inputs: Extra context-specific weak tokens - a username, email
            local part, company or product name. Attackers try these first, so
            callers should always pass whatever they know about the account.

    Raises:
        TypeError: If ``password`` is not a string.
    """
    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password).__name__}")

    # Normalise so that visually identical strings score identically across
    # platforms, and so code-point counts match the JavaScript implementation.
    normalised = unicodedata.normalize("NFC", password)
    true_length = len(normalised)

    warnings: List[str] = []
    if true_length > MAX_ANALYSIS_LENGTH:
        # Bound the work: pattern scanning is superlinear, and anything this
        # long is already far beyond any attacker's reach.
        normalised = normalised[:MAX_ANALYSIS_LENGTH]
        warnings.append(
            f"Only the first {MAX_ANALYSIS_LENGTH} characters were analysed."
        )

    length = len(normalised)
    pool_size, classes = _character_pool(normalised)

    if length == 0:
        return Result(
            length=0,
            score=0,
            label=SCORE_LABELS[0],
            entropy_bits=0.0,
            raw_entropy_bits=0.0,
            pool_size=0,
            requirements=_build_requirements(0, classes, has_patterns=False),
            penalties=[],
            warnings=["No password entered."],
            suggestions=[f"Use at least {MIN_LENGTH} characters."],
            crack_time_display="instantly",
        )

    # Context tokens are matched exactly like weak-list entries.
    token_set = COMMON_TOKENS if tokens is None else frozenset(tokens)
    if user_inputs:
        extra = {t.strip().lower() for t in user_inputs if t and len(t.strip()) >= 4}
        token_set = token_set | extra

    raw_entropy = length * math.log2(pool_size)

    found = patterns.select_non_overlapping(patterns.find_all(normalised, token_set))
    penalties: List[Penalty] = []
    for match in found:
        brute_force_bits = match.length * math.log2(pool_size)
        replacement = _replacement_bits(match, pool_size, len(token_set))
        bits = max(0.0, brute_force_bits - replacement)
        if bits > 0.01:
            penalties.append(Penalty(match.kind, _describe(match), round(bits, 2)))

    if patterns.is_single_repeated_block(normalised):
        # "abcabcabc" - the whole password is one short block repeated.
        block_penalty = max(0.0, raw_entropy - sum(p.bits for p in penalties) - 12.0)
        if block_penalty > 0.01:
            penalties.append(
                Penalty("repeated_block", "The whole password is one short block repeated", round(block_penalty, 2))
            )

    entropy = max(0.0, raw_entropy - sum(p.bits for p in penalties))

    # Band the entropy, then apply policy caps that entropy cannot buy past.
    score = sum(1 for threshold in SCORE_THRESHOLDS if entropy >= threshold)

    if any(form in token_set for form in patterns.leet_variants(normalised)):
        score = 0
        warnings.insert(0, "This is a known weak password - it would be guessed immediately.")
    if length < MIN_LENGTH:
        score = min(score, 1)
    elif length < IDEAL_LENGTH:
        score = min(score, 3)

    warnings.extend(p.label for p in penalties)

    requirements = _build_requirements(length, classes, has_patterns=bool(found))
    offline_seconds = (2 ** entropy) / 2 / OFFLINE_GUESSES_PER_SECOND if entropy < 1024 else math.inf
    online_seconds = (2 ** entropy) / 2 / ONLINE_GUESSES_PER_SECOND if entropy < 1024 else math.inf

    return Result(
        length=true_length,
        score=score,
        label=SCORE_LABELS[score],
        entropy_bits=round(entropy, 2),
        raw_entropy_bits=round(raw_entropy, 2),
        pool_size=pool_size,
        requirements=requirements,
        penalties=penalties,
        warnings=warnings,
        suggestions=_build_suggestions(requirements, score),
        crack_time_offline_seconds=offline_seconds,
        crack_time_online_seconds=online_seconds,
        crack_time_display=_format_duration(offline_seconds),
    )

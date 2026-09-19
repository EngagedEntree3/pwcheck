#!/usr/bin/env python3
"""Regenerate tests/fixtures/cases.json from the Python implementation.

The fixture is the contract between the two implementations: both test suites
assert these exact values, so an unintended change in either one fails the
build. Run this only when a scoring change is *intended*, and review the diff -
a large unexplained swing is the signal this file exists to produce.

    python3 tools/gen_fixture.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from pwcheck import evaluate  # noqa: E402

OUTPUT = ROOT / "tests" / "fixtures" / "cases.json"

CASES = [
    ("", "empty input"),
    ("a", "single character"),
    ("aB3$xY9", "7 chars, all classes, but under the minimum length"),
    ("password", "the canonical weak password"),
    ("P@ssw0rd", "leetspeak does not save a dictionary word"),
    ("Password123!", "all four classes, still trivially guessable"),
    ("12345678", "pure ascending digit sequence"),
    ("qwerty", "keyboard walk"),
    ("qwertyuiop", "long keyboard walk"),
    ("aaaaaaaaaaaa", "single repeated character"),
    ("abcabcabcabc", "one short block repeated"),
    ("letmein!", "dictionary word with a symbol suffix"),
    ("Summer2024!", "seasonal word plus a year, a very common corporate shape"),
    ("hunter2", "short dictionary word plus a digit"),
    ("Tr0ub4dor&3", "the xkcd mangled word"),
    ("correct horse battery staple", "the xkcd passphrase"),
    ("xK9#mQ2!vL4$", "12 random characters, all classes"),
    ("J8#vR!q2Lm$Ze4Wn", "16 random characters, all classes"),
    ("  spaces  in here 42", "spaces count toward the pool"),
    ("passenger-lentil-dial", "hyphenated passphrase"),
    ("z" * 300, "over the analysis cap"),
]

HEADER = (
    "Shared parity fixture. Both python/tests/test_core.py and "
    "tests/js/test_strength.js assert these exact values, so the two "
    "implementations cannot drift apart. Regenerate with "
    "tools/gen_fixture.py after an intentional model change."
)


def main() -> int:
    cases = []
    for password, note in CASES:
        result = evaluate(password)
        cases.append(
            {
                "password": password,
                "note": note,
                "score": result.score,
                "label": result.label,
                "entropyBits": result.entropy_bits,
                "length": result.length,
                "crackTimeDisplay": result.crack_time_display,
                "requirementsMet": sum(1 for r in result.requirements if r.met),
            }
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps({"_comment": HEADER, "cases": cases}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(cases)} cases to {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

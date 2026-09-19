"""Tests for the Python password strength implementation.

Run from the repository root:

    python3 -m unittest discover -s python/tests -t python -v
"""

from __future__ import annotations

import json
import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from pwcheck import IDEAL_LENGTH, MIN_LENGTH, evaluate  # noqa: E402
from pwcheck import patterns  # noqa: E402
from pwcheck.core import _format_duration  # noqa: E402

FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "cases.json").read_text(encoding="utf-8"))


class TestInputValidation(unittest.TestCase):
    def test_rejects_non_string(self):
        for bad in (None, 12345, b"bytes", ["list"], {"a": 1}):
            with self.subTest(value=bad):
                with self.assertRaises(TypeError):
                    evaluate(bad)

    def test_empty_password_is_score_zero(self):
        result = evaluate("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.length, 0)
        self.assertEqual(result.entropy_bits, 0.0)
        self.assertFalse(result.is_acceptable)

    def test_whitespace_only_is_still_evaluated(self):
        # Spaces are legitimate password characters; they must not be stripped.
        result = evaluate("    ")
        self.assertEqual(result.length, 4)

    def test_very_long_password_is_capped_not_rejected(self):
        result = evaluate("q" * 5000)
        self.assertEqual(result.length, 5000)
        self.assertTrue(any("first 256" in w for w in result.warnings))

    def test_result_is_json_serialisable(self):
        # Infinite crack times must not leak into JSON as `Infinity`.
        payload = json.dumps(evaluate("C4t!nTh3H@t*Rides-Again").to_dict())
        self.assertNotIn("Infinity", payload)

    def test_unicode_is_counted_by_code_point(self):
        result = evaluate("pässwörd")  # 8 code points
        self.assertEqual(result.length, 8)


class TestPolicyCaps(unittest.TestCase):
    def test_below_minimum_length_cannot_score_above_weak(self):
        # All four character classes, high raw entropy, still too short.
        result = evaluate("aB3$xY9")
        self.assertLess(result.length, MIN_LENGTH)
        self.assertLessEqual(result.score, 1)

    def test_below_ideal_length_cannot_score_excellent(self):
        result = evaluate("aB3$xY9zQ2#")  # 11 characters, random
        self.assertLess(result.length, IDEAL_LENGTH)
        self.assertLessEqual(result.score, 3)

    def test_exact_common_password_scores_zero(self):
        for password in ("password", "PASSWORD", "Password", "P@ssw0rd"):
            with self.subTest(password=password):
                self.assertEqual(evaluate(password).score, 0)

    def test_long_random_password_scores_excellent(self):
        self.assertEqual(evaluate("J8#vR!q2Lm$Ze4Wn").score, 4)


class TestRequirements(unittest.TestCase):
    def _requirement(self, password, requirement_id):
        return next(r for r in evaluate(password).requirements if r.id == requirement_id)

    def test_character_classes_detected(self):
        self.assertTrue(self._requirement("aQ1!aQ1!", "lowercase").met)
        self.assertTrue(self._requirement("aQ1!aQ1!", "uppercase").met)
        self.assertTrue(self._requirement("aQ1!aQ1!", "digit").met)
        self.assertTrue(self._requirement("aQ1!aQ1!", "symbol").met)

    def test_missing_classes_reported(self):
        self.assertFalse(self._requirement("abcdefgh", "uppercase").met)
        self.assertFalse(self._requirement("abcdefgh", "digit").met)
        self.assertFalse(self._requirement("abcdefgh", "symbol").met)

    def test_space_counts_as_a_special_character(self):
        self.assertTrue(self._requirement("hello there world", "symbol").met)

    def test_pattern_requirement_fails_on_dictionary_word(self):
        self.assertFalse(self._requirement("MyPasswordIsGreat", "no_patterns").met)

    def test_every_requirement_has_an_id_and_label(self):
        for requirement in evaluate("anything").requirements:
            self.assertTrue(requirement.id)
            self.assertTrue(requirement.label)


class TestUserInputs(unittest.TestCase):
    def test_context_words_are_penalised(self):
        baseline = evaluate("Wolfram-Delta-9182")
        contextual = evaluate("Wolfram-Delta-9182", user_inputs=["wolfram"])
        self.assertLess(contextual.entropy_bits, baseline.entropy_bits)

    def test_short_context_words_are_ignored(self):
        # Two-letter context would match almost everything; it must be dropped.
        baseline = evaluate("Kx7#mQ2!vL4$")
        contextual = evaluate("Kx7#mQ2!vL4$", user_inputs=["kx"])
        self.assertEqual(contextual.entropy_bits, baseline.entropy_bits)

    def test_none_and_empty_context_are_safe(self):
        self.assertEqual(
            evaluate("Kx7#mQ2!vL4$", user_inputs=[]).score,
            evaluate("Kx7#mQ2!vL4$").score,
        )


class TestPatternDetectors(unittest.TestCase):
    def test_repeat_detection(self):
        matches = patterns.find_repeats("aaabcc")
        self.assertEqual([(m.start, m.length) for m in matches], [(0, 3)])

    def test_sequence_detection_ascending_and_descending(self):
        self.assertTrue(patterns.find_sequences("abcd"))
        self.assertTrue(patterns.find_sequences("4321"))

    def test_sequence_does_not_cross_character_classes(self):
        # "9:;" is consecutive in ASCII but is not a meaningful sequence.
        self.assertEqual(patterns.find_sequences("9:;"), [])

    def test_keyboard_walk_detection(self):
        self.assertTrue(patterns.find_keyboard_walks("qwerty"))
        self.assertTrue(patterns.find_keyboard_walks("asdfgh"))

    def test_leet_normalisation(self):
        self.assertEqual(patterns.normalize_leet("P@$$w0rd"), "password")

    def test_ambiguous_leet_glyphs_have_both_readings(self):
        # "1" is both "l" and "i"; one pass cannot resolve both, so the
        # alternate reading exists to catch the other half.
        self.assertEqual(patterns.normalize_leet("L3tM31n"), "letmeln")
        self.assertEqual(patterns.normalize_leet("L3tM31n", alternate=True), "letmein")
        self.assertIn("letmein", patterns.leet_variants("L3tM31n"))

    def test_leet_variants_are_deterministic_and_unique(self):
        variants = patterns.leet_variants("Adm1n")
        self.assertEqual(variants, ["adm1n", "admln", "admin"])
        self.assertEqual(len(variants), len(set(variants)))
        # A password with no leet characters folds to a single form.
        self.assertEqual(patterns.leet_variants("Wolfram"), ["wolfram"])

    def test_alternate_reading_catches_digit_for_i(self):
        self.assertEqual(evaluate("Adm1n1strator").score, 0)

    def test_leet_normalisation_preserves_length(self):
        for sample in ("P@$$w0rd", "1337", "N0rm4l!z3", "ünïcödé"):
            with self.subTest(sample=sample):
                self.assertEqual(len(patterns.normalize_leet(sample)), len(sample))

    def test_date_detection(self):
        self.assertTrue(patterns.find_dates("summer2024"))
        self.assertFalse(patterns.find_dates("summer2124"))

    def test_repeated_block_detection(self):
        self.assertTrue(patterns.is_single_repeated_block("abcabcabc"))
        self.assertFalse(patterns.is_single_repeated_block("abcabd"))

    def test_overlapping_matches_are_charged_once(self):
        # "1234" is both a digit sequence and a keyboard-row walk.
        found = patterns.find_all("1234", frozenset())
        self.assertGreater(len(found), 1, "expected both a sequence and a keyboard match")
        chosen = patterns.select_non_overlapping(found)
        self.assertEqual(len(chosen), 1)

    def test_dictionary_match_prefers_the_longest_token(self):
        matches = patterns.find_dictionary_words("password", frozenset({"pass", "password"}))
        self.assertEqual(matches[0].token, "password")


class TestFormatting(unittest.TestCase):
    def test_duration_boundaries(self):
        self.assertEqual(_format_duration(0.4), "less than a second")
        self.assertEqual(_format_duration(1), "1 second")
        self.assertEqual(_format_duration(90), "2 minutes")
        self.assertEqual(_format_duration(math.inf), "effectively forever")

    def test_duration_pluralisation(self):
        self.assertTrue(_format_duration(60 * 60 * 24 * 365.25 * 100).endswith("century"))
        self.assertTrue(_format_duration(60 * 60 * 24 * 365.25 * 500).endswith("centuries"))


class TestMonotonicity(unittest.TestCase):
    def test_adding_length_never_lowers_entropy_for_random_text(self):
        base = "Kq7#mZ2!vL"
        previous = 0.0
        for extra in ("", "x", "xW", "xW4", "xW4%"):
            entropy = evaluate(base + extra).entropy_bits
            self.assertGreaterEqual(entropy, previous)
            previous = entropy

    def test_stronger_passwords_score_at_least_as_high(self):
        ladder = ["a", "abcdefg", "abcdefgh1", "Abcdefgh1", "Kq7#mZ2!vL4$wR"]
        scores = [evaluate(p).score for p in ladder]
        self.assertEqual(scores, sorted(scores))


class TestSharedFixture(unittest.TestCase):
    """The contract with the JavaScript implementation."""

    def test_matches_fixture(self):
        for case in FIXTURE["cases"]:
            with self.subTest(note=case["note"]):
                result = evaluate(case["password"])
                self.assertEqual(result.score, case["score"])
                self.assertEqual(result.label, case["label"])
                self.assertEqual(result.length, case["length"])
                self.assertAlmostEqual(result.entropy_bits, case["entropyBits"], places=1)
                self.assertEqual(result.crack_time_display, case["crackTimeDisplay"])
                self.assertEqual(
                    sum(1 for r in result.requirements if r.met), case["requirementsMet"]
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)

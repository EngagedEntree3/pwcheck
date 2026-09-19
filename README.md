# Password Strength Checker

A password strength checker with two implementations that share one scoring
model: a browser UI for the person choosing a password, and a Python package
for the service that has to accept or reject it.

The two are kept in lockstep by a shared fixture — if the JavaScript and the
Python ever disagree about a password, the test suites fail.

```
$ python3 python/checker.py

  ████████████████████████  EXCELLENT

  Length           16
  Entropy          105.1 bits (raw 105.1, pool 95)
  Offline crack    6.97e+11 centuries
```

## Contents

| Path | What it is |
|---|---|
| `data/common_passwords.txt` | The canonical weak-token list. Single source of truth. |
| `python/pwcheck/` | The Python package: `core.py` (scoring), `patterns.py` (detectors), `wordlist.py` (loader). |
| `python/checker.py` | CLI entry point. |
| `python/tests/test_core.py` | Python test suite (36 tests). |
| `web/index.html` | The single-page UI. |
| `web/css/styles.css` | Styles. No build step, no webfonts, no external requests. |
| `web/js/strength.js` | The JavaScript port of the scoring model. No DOM access. |
| `web/js/app.js` | DOM wiring only. Contains no scoring logic. |
| `web/js/common-passwords.js` | Generated from `data/`. Do not edit by hand. |
| `tests/js/test_strength.js` | JavaScript test suite (45 tests). |
| `tests/fixtures/cases.json` | The cross-language contract. Both suites assert it. |
| `tools/` | Regenerate the JS wordlist and the fixture. |

## Quick start

### The web UI

Open `web/index.html` in a browser. There is no build step and no server
required — it runs from `file://`.

### The CLI

```bash
python3 python/checker.py                  # interactive, input hidden
echo -n 'hunter2' | python3 python/checker.py --stdin
python3 python/checker.py --stdin --json   # machine-readable
python3 python/checker.py --stdin --min-score 3 --quiet   # exit 0/1 for scripts
```

Passing a password as an argument works but is **not safe on a shared
machine** — `argv` is visible to other local processes and lands in your shell
history. The CLI warns you when you do it. Use the prompt or `--stdin`.

### As a module

```python
from pwcheck import evaluate

result = evaluate(password, user_inputs=[email, username, "acme-corp"])

if not result.is_acceptable:          # score >= 2
    return 400, {
        "errors": result.warnings,
        "hints": result.suggestions,
    }
```

Always pass `user_inputs`. Attackers try the account's own email, username and
the company name before anything else, and a password built from them scores
as though it were a dictionary word.

`result.to_dict()` gives a JSON-serialisable dict suitable for an API response.

## How the score works

Three stages, in order.

**1. Raw entropy.** `length × log2(pool)`, where the pool is the size of the
character classes actually used (26 lowercase + 26 uppercase + 10 digits + 33
symbols + space, or 100 for non-ASCII). This is the cost of a pure brute-force
search.

**2. Pattern discounting.** Raw entropy alone is badly misleading. `Password123!`
uses all four character classes and 12 characters — 78.8 raw bits — but an
attacker with a dictionary and standard mangling rules finds it in under a
second. So every predictable region gets its brute-force cost *replaced* by the
cost of guessing it from its own, much smaller, pattern space:

| Detector | Catches | Replacement cost |
|---|---|---|
| dictionary | `password`, `P@ssw0rd`, `Adm1n` (case- and leetspeak-folded) | `log2(list size) + 4` bits |
| keyboard | `qwerty`, `asdfgh`, `1qaz` | `log2(94) + log2(run)` |
| sequence | `12345`, `dcba` | `log2(72) + log2(run)` |
| repeat | `aaaa`, `!!!` | `log2(pool) + log2(run)` |
| date | `1987`, `2024` | `log2(200)` |

Overlapping matches are charged once — `1234` is both a sequence and a keyboard
walk, and double-charging it would be wrong. Longest match wins.

`Password123!` therefore ends at **26.1 bits**, not 78.8.

**3. Policy caps** that entropy cannot buy past: under 8 characters can never
score above *Weak*; under 12 can never reach *Excellent*; an exact match for a
known weak password is always 0.

The resulting bands, on effective entropy:

| Bits | Score | Label |
|---|---|---|
| < 28 | 0 | Very weak |
| < 36 | 1 | Weak |
| < 60 | 2 | Fair |
| < 80 | 3 | Strong |
| ≥ 80 | 4 | Excellent |

Crack times assume **10¹⁰ guesses/second** — an offline attack on a fast,
unsalted hash with commodity GPUs. That is deliberately pessimistic; if the
number looks bad, it should.

## What this does *not* do

Be clear about the limits before relying on it.

- **The browser check is not a security control.** It is a user-experience
  feature and is trivially bypassed. The same check must run server-side before
  a password is accepted. That is what the Python package is for.
- **The bundled wordlist is small** (164 tokens) and covers the most common
  leaked passwords and base words. It is *not* a breach corpus, so uncommon
  dictionary words and multi-word English passphrases score more generously
  than a tool with a large dictionary would. To use a real list:

  ```python
  from pathlib import Path
  from pwcheck import evaluate
  from pwcheck.wordlist import load

  tokens = load(Path("/path/to/rockyou-top-100k.txt"))   # one lowercase token per line
  result = evaluate(password, tokens=tokens)
  ```

  Scanning is bounded by the longest token, so a much larger list costs more
  memory but stays fast.
- **It does not check whether a password has been breached.** For anything
  real, also query a k-anonymity breach API (e.g. Have I Been Pwned's range
  endpoint) server-side.
- **It is not a substitute for the things that actually protect accounts**:
  a slow password hash (argon2id/scrypt/bcrypt), rate limiting, and MFA.
- The score is a heuristic estimate, not a guarantee.

## Keeping the two implementations honest

`tests/fixtures/cases.json` holds 21 passwords with their expected score,
label, entropy, length and crack-time string. Both suites assert it, so a
change to one implementation that is not mirrored in the other fails the build.

After an *intentional* model change, regenerate it and review the diff — a
large unexplained swing is exactly what that file exists to surface:

```bash
python3 tools/gen_fixture.py
```

After editing `data/common_passwords.txt`, regenerate the browser copy:

```bash
python3 tools/gen_js_wordlist.py
```

## Tests

```bash
./tools/run_tests.sh
```

or individually:

```bash
python3 -m unittest discover -s python/tests -t python -v
node tests/js/test_strength.js
```

## Accessibility and design notes

The UI was built to measured gates, not to eye. Verified in Chrome:

- **Contrast.** Body text 14.93:1 (dark) / 18.42:1 (light). Muted text 6.84:1 /
  5.13:1. Every strength-band colour is ≥ 4.89:1 against the card and ≥ 4.10:1
  against the meter track, so each one is legible as both the fill and the
  label.
- **Colour is never the only signal.** The band name, the checklist and the
  live region all state the verdict in words.
- **Focus.** All four focusable elements (skip link, input, toggle, details
  summary) show a 2px `:focus-visible` ring at 2–3px offset. The skip link is
  the first focusable element and settles at 16px from the top edge.
- **Breakpoints.** No horizontal scroll and the input visible on load at 390,
  768, 1024 and 1440px. The checklist is one column at 390 and two from 768.
- **Scripts blocked.** The page still renders (902 characters of content), the
  toggle is hidden rather than dead, and a static checklist is shown.
- **Motion.** A `prefers-reduced-motion: reduce` block disables all
  transitions.
- **Weight.** No images and no webfonts; the whole UI is three text files.

Light-mode ratios above were computed rather than rendered — the verification
browser session ran in dark mode.

## Privacy

Nothing is transmitted. The web page makes no network requests of any kind
(there is no `fetch` in the project), and the Python package never logs or
stores the password it is given.

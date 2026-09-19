#!/usr/bin/env python3
"""Generate web/js/common-passwords.js from data/common_passwords.txt.

The browser cannot read the shared text file directly (there is no fetch from
``file://``, and we do not want a build step or a network round-trip on page
load), so the canonical list is compiled into a small JavaScript module.

Run this after editing the wordlist:

    python3 tools/gen_js_wordlist.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from pwcheck.wordlist import load  # noqa: E402

OUTPUT = ROOT / "web" / "js" / "common-passwords.js"

TEMPLATE = """\
/**
 * Weak-token list - GENERATED FILE, DO NOT EDIT BY HAND.
 *
 * Source: data/common_passwords.txt
 * Regenerate with: python3 tools/gen_js_wordlist.py
 *
 * Compiled from the shared wordlist so the browser and the Python backend
 * agree on what counts as a weak token without a build step or a fetch.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PasswordStrengthWordlist = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  return %(tokens)s;
});
"""


def main() -> int:
    tokens = sorted(load())
    # Wrap at a readable width rather than emitting one enormous line.
    lines, current = [], "  ["
    for index, token in enumerate(tokens):
        piece = json.dumps(token) + ("," if index < len(tokens) - 1 else "")
        if len(current) + len(piece) + 1 > 78:
            lines.append(current)
            current = "   "
        current += (" " if current.strip() else "") + piece
    lines.append(current + "\n  ]")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(TEMPLATE % {"tokens": "\n".join(lines).lstrip()}, encoding="utf-8")
    print(f"wrote {len(tokens)} tokens to {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

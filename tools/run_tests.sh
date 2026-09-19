#!/usr/bin/env bash
# Run both test suites. Fails if either does.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== Python =="
python3 -m unittest discover -s python/tests -t python

echo
echo "== JavaScript =="
node tests/js/test_strength.js

echo
echo "== Generated files are up to date =="
# The browser wordlist and the shared fixture are generated. If regenerating
# changes them, someone edited a source file without regenerating.
before_wordlist=$(shasum web/js/common-passwords.js | cut -d' ' -f1)
before_fixture=$(shasum tests/fixtures/cases.json | cut -d' ' -f1)
python3 tools/gen_js_wordlist.py > /dev/null
python3 tools/gen_fixture.py > /dev/null
after_wordlist=$(shasum web/js/common-passwords.js | cut -d' ' -f1)
after_fixture=$(shasum tests/fixtures/cases.json | cut -d' ' -f1)

status=0
if [ "$before_wordlist" != "$after_wordlist" ]; then
  echo "STALE: web/js/common-passwords.js — run tools/gen_js_wordlist.py and commit"
  status=1
fi
if [ "$before_fixture" != "$after_fixture" ]; then
  echo "STALE: tests/fixtures/cases.json — run tools/gen_fixture.py and review the diff"
  status=1
fi
[ "$status" -eq 0 ] && echo "ok"
exit "$status"

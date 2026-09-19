/**
 * Tests for the JavaScript password strength implementation.
 *
 * Dependency-free so it runs anywhere Node does:
 *
 *     node tests/js/test_strength.js
 *
 * The TestSharedFixture block asserts the same tests/fixtures/cases.json that
 * python/tests/test_core.py asserts. If the two implementations ever disagree,
 * one of the two suites fails.
 */
'use strict';

var assert = require('assert');
var path = require('path');
var fs = require('fs');

var ROOT = path.resolve(__dirname, '..', '..');
var strength = require(path.join(ROOT, 'web', 'js', 'strength.js'));
var fixture = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', 'cases.json'), 'utf8')
);

var passed = 0;
var failures = [];

function test(name, fn) {
  try {
    fn();
    passed += 1;
  } catch (error) {
    failures.push({ name: name, error: error });
  }
}

function requirement(password, id) {
  return strength.evaluate(password).requirements.filter(function (r) {
    return r.id === id;
  })[0];
}

// --- input validation -------------------------------------------------------

test('rejects non-string input', function () {
  [null, undefined, 12345, ['list'], { a: 1 }, true].forEach(function (bad) {
    assert.throws(function () { strength.evaluate(bad); }, TypeError,
      'expected TypeError for ' + JSON.stringify(bad));
  });
});

test('empty password scores zero', function () {
  var result = strength.evaluate('');
  assert.strictEqual(result.score, 0);
  assert.strictEqual(result.length, 0);
  assert.strictEqual(result.entropyBits, 0);
  assert.strictEqual(result.isAcceptable, false);
});

test('whitespace-only input is evaluated, not stripped', function () {
  assert.strictEqual(strength.evaluate('    ').length, 4);
});

test('very long password is capped, not rejected', function () {
  var result = strength.evaluate(new Array(5001).join('q'));
  assert.strictEqual(result.length, 5000);
  assert.ok(result.warnings.some(function (w) { return w.indexOf('first 256') !== -1; }));
});

test('unicode is counted by code point', function () {
  assert.strictEqual(strength.evaluate('pässwörd').length, 8);
});

test('astral characters count as one character', function () {
  // Two emoji are two code points, not four UTF-16 units.
  assert.strictEqual(strength.evaluate('😀😀').length, 2);
});

// --- policy caps ------------------------------------------------------------

test('below minimum length cannot score above weak', function () {
  var result = strength.evaluate('aB3$xY9');
  assert.ok(result.length < strength.MIN_LENGTH);
  assert.ok(result.score <= 1, 'score was ' + result.score);
});

test('below ideal length cannot score excellent', function () {
  var result = strength.evaluate('aB3$xY9zQ2#');
  assert.ok(result.length < strength.IDEAL_LENGTH);
  assert.ok(result.score <= 3);
});

test('exact common password scores zero regardless of case or leet', function () {
  ['password', 'PASSWORD', 'Password', 'P@ssw0rd'].forEach(function (p) {
    assert.strictEqual(strength.evaluate(p).score, 0, p);
  });
});

test('long random password scores excellent', function () {
  assert.strictEqual(strength.evaluate('J8#vR!q2Lm$Ze4Wn').score, 4);
});

// --- requirements -----------------------------------------------------------

test('character classes are detected', function () {
  ['lowercase', 'uppercase', 'digit', 'symbol'].forEach(function (id) {
    assert.strictEqual(requirement('aQ1!aQ1!', id).met, true, id);
  });
});

test('missing character classes are reported', function () {
  assert.strictEqual(requirement('abcdefgh', 'uppercase').met, false);
  assert.strictEqual(requirement('abcdefgh', 'digit').met, false);
  assert.strictEqual(requirement('abcdefgh', 'symbol').met, false);
});

test('a space counts as a special character', function () {
  assert.strictEqual(requirement('hello there world', 'symbol').met, true);
});

test('dictionary word fails the pattern requirement', function () {
  assert.strictEqual(requirement('MyPasswordIsGreat', 'no_patterns').met, false);
});

test('every requirement carries an id and a label', function () {
  strength.evaluate('anything').requirements.forEach(function (r) {
    assert.ok(r.id, 'missing id');
    assert.ok(r.label, 'missing label');
    assert.strictEqual(typeof r.met, 'boolean');
  });
});

// --- context inputs ---------------------------------------------------------

test('context words lower the score', function () {
  var baseline = strength.evaluate('Wolfram-Delta-9182');
  var contextual = strength.evaluate('Wolfram-Delta-9182', { userInputs: ['wolfram'] });
  assert.ok(contextual.entropyBits < baseline.entropyBits,
    baseline.entropyBits + ' -> ' + contextual.entropyBits);
});

test('short context words are ignored', function () {
  var baseline = strength.evaluate('Kx7#mQ2!vL4$');
  var contextual = strength.evaluate('Kx7#mQ2!vL4$', { userInputs: ['kx'] });
  assert.strictEqual(contextual.entropyBits, baseline.entropyBits);
});

test('empty and non-string context are safe', function () {
  assert.strictEqual(
    strength.evaluate('Kx7#mQ2!vL4$', { userInputs: [] }).score,
    strength.evaluate('Kx7#mQ2!vL4$').score
  );
  assert.doesNotThrow(function () {
    strength.evaluate('Kx7#mQ2!vL4$', { userInputs: [null, 42, undefined] });
  });
});

// --- leet folding -----------------------------------------------------------

test('leet folding resolves both readings of ambiguous glyphs', function () {
  assert.strictEqual(strength.normalizeLeet('P@$$w0rd'), 'password');
  assert.strictEqual(strength.normalizeLeet('L3tM31n'), 'letmeln');
  assert.strictEqual(strength.normalizeLeet('L3tM31n', true), 'letmein');
});

test('alternate reading catches a digit standing in for i', function () {
  assert.strictEqual(strength.evaluate('Adm1n1strator').score, 0);
});

// --- formatting -------------------------------------------------------------

test('duration formatting covers the boundaries', function () {
  assert.strictEqual(strength.formatDuration(0.4), 'less than a second');
  assert.strictEqual(strength.formatDuration(1), '1 second');
  assert.strictEqual(strength.formatDuration(90), '2 minutes');
  assert.strictEqual(strength.formatDuration(Infinity), 'effectively forever');
});

test('duration formatting pluralises', function () {
  var century = 60 * 60 * 24 * 365.25 * 100;
  assert.ok(/century$/.test(strength.formatDuration(century)));
  assert.ok(/centuries$/.test(strength.formatDuration(century * 5)));
});

// --- monotonicity -----------------------------------------------------------

test('adding random characters never lowers entropy', function () {
  var base = 'Kq7#mZ2!vL';
  var previous = 0;
  ['', 'x', 'xW', 'xW4', 'xW4%'].forEach(function (extra) {
    var entropy = strength.evaluate(base + extra).entropyBits;
    assert.ok(entropy >= previous, base + extra + ': ' + entropy + ' < ' + previous);
    previous = entropy;
  });
});

test('stronger passwords score at least as high', function () {
  var ladder = ['a', 'abcdefg', 'abcdefgh1', 'Abcdefgh1', 'Kq7#mZ2!vL4$wR'];
  var scores = ladder.map(function (p) { return strength.evaluate(p).score; });
  assert.deepStrictEqual(scores, scores.slice().sort(function (a, b) { return a - b; }));
});

// --- the cross-language contract -------------------------------------------

fixture.cases.forEach(function (expected) {
  test('fixture parity: ' + expected.note, function () {
    var result = strength.evaluate(expected.password);
    assert.strictEqual(result.score, expected.score, 'score');
    assert.strictEqual(result.label, expected.label, 'label');
    assert.strictEqual(result.length, expected.length, 'length');
    assert.ok(Math.abs(result.entropyBits - expected.entropyBits) < 0.05,
      'entropy ' + result.entropyBits + ' != ' + expected.entropyBits);
    assert.strictEqual(result.crackTimeDisplay, expected.crackTimeDisplay, 'crack time');
    assert.strictEqual(
      result.requirements.filter(function (r) { return r.met; }).length,
      expected.requirementsMet,
      'requirements met'
    );
  });
});

// --- report -----------------------------------------------------------------

failures.forEach(function (failure) {
  console.error('FAIL  ' + failure.name);
  console.error('      ' + failure.error.message.split('\n').join('\n      '));
});
console.log('\n' + passed + ' passed, ' + failures.length + ' failed');
process.exit(failures.length ? 1 : 0);

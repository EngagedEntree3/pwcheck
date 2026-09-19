/**
 * Password strength scoring - pure logic, no DOM.
 *
 * This is a direct port of python/pwcheck/{patterns,core}.py. The two
 * implementations are kept deliberately parallel (same constants, same
 * detectors, same scoring model) so a password scored in the browser gets the
 * same verdict from the backend. tests/js/test_strength.js and
 * python/tests/test_core.py assert the shared cases.
 *
 * THE MODEL
 *   1. Raw entropy = length x log2(pool), the cost of pure brute force.
 *   2. Pattern discounting: every predictable region (dictionary word,
 *      keyboard walk, sequence, repeat, year) has its brute-force cost
 *      replaced by the much cheaper cost of guessing it from its own pattern
 *      space. This is why "Password123!" scores near zero despite using all
 *      four character classes.
 *   3. Policy caps that entropy cannot buy past, e.g. the 8-character minimum.
 *
 * IMPORTANT: client-side scoring is a user-experience feature only. It is
 * trivially bypassed, so the same check must run server-side before the
 * password is accepted. That is what the Python package is for.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(require('./common-passwords.js'));
  } else {
    root.PasswordStrength = factory(root.PasswordStrengthWordlist || []);
  }
})(typeof self !== 'undefined' ? self : this, function (WORDLIST) {
  'use strict';

  // --- policy ---------------------------------------------------------------

  var MIN_LENGTH = 8;            // below this the password is rejected outright
  var IDEAL_LENGTH = 12;         // target length for a "strong" verdict
  var MAX_ANALYSIS_LENGTH = 256; // bound the work a paste can trigger

  var SCORE_LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'];
  var SCORE_THRESHOLDS = [28, 36, 60, 80]; // effective-entropy bands, in bits

  // --- attacker model -------------------------------------------------------

  var OFFLINE_GUESSES_PER_SECOND = 1e10; // fast unsalted hash, commodity GPUs
  var ONLINE_GUESSES_PER_SECOND = 100;   // rate-limited login endpoint

  // --- character pools ------------------------------------------------------

  var POOL_LOWERCASE = 26;
  var POOL_UPPERCASE = 26;
  var POOL_DIGITS = 10;
  var POOL_SYMBOLS = 33;
  var POOL_SPACE = 1;
  var POOL_OTHER = 100;

  // --- detector thresholds --------------------------------------------------

  var MIN_REPEAT_LENGTH = 3;
  var MIN_SEQUENCE_LENGTH = 3;
  var MIN_KEYBOARD_RUN = 3;
  var MIN_TOKEN_LENGTH = 4;

  // Single-pass leetspeak folding. We do not expand every substitution
  // combination: one canonical form catches the overwhelming majority of
  // real-world mangling, and this runs on every keystroke.
  var LEET_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g',
    '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's', '!': 'i',
    '|': 'l', '+': 't', '(': 'c', '<': 'c'
  };

  // Some glyphs stand in for more than one letter: "1" is used for both "l"
  // ("he11o") and "i" ("adm1n"), and "!" for both "i" and "l". One pass cannot
  // resolve both readings, so we fold twice and match against each result.
  var LEET_MAP_ALT = Object.assign({}, LEET_MAP, { '1': 'i', '!': 'l' });

  // Physical QWERTY rows, to catch walks like "qwerty" or "1qaz" that
  // alphabetical-sequence detection cannot see.
  var KEYBOARD_ROWS = [
    '`1234567890-=',
    'qwertyuiop[]\\',
    "asdfghjkl;'",
    'zxcvbnm,./',
    '~!@#$%^&*()_+',
    'QWERTYUIOP{}|',
    'ASDFGHJKL:"',
    'ZXCVBNM<>?'
  ];

  var YEAR_RE = /(?:19|20)\d{2}/g;
  var RE_LOWER = /\p{Ll}/u;
  var RE_UPPER = /\p{Lu}/u;
  var RE_DIGIT = /\p{Nd}/u;
  var RE_LETTER = /\p{L}/u;

  var TOKENS = new Set(
    (WORDLIST || []).filter(function (t) { return t.length >= MIN_TOKEN_LENGTH; })
  );
  var MAX_TOKEN_LENGTH = 4;
  TOKENS.forEach(function (t) {
    if (t.length > MAX_TOKEN_LENGTH) { MAX_TOKEN_LENGTH = t.length; }
  });

  // --- helpers --------------------------------------------------------------

  function log2(value) { return Math.log(value) / Math.LN2; }

  /** Split into code points so astral characters count as one, matching Python. */
  function toChars(text) { return Array.from(text); }

  /**
   * Fold common character substitutions so "P4$$w0rd" matches "password".
   * Length is preserved 1:1 so match offsets stay valid against the original.
   */
  function normalizeLeet(chars, alternate) {
    var table = alternate ? LEET_MAP_ALT : LEET_MAP;
    return chars
      .map(function (ch) {
        var lower = ch.toLowerCase();
        return Object.prototype.hasOwnProperty.call(table, lower)
          ? table[lower]
          : lower;
      })
      .join('');
  }

  /** The forms to match against, in a deterministic, duplicate-free order. */
  function leetVariants(chars) {
    var forms = [
      chars.join('').toLowerCase(),
      normalizeLeet(chars, false),
      normalizeLeet(chars, true)
    ];
    return forms.filter(function (form, index) {
      return forms.indexOf(form) === index;
    });
  }

  function makeMatch(kind, token, start, length) {
    return { kind: kind, token: token, start: start, length: length, end: start + length };
  }

  // --- detectors ------------------------------------------------------------

  /** Runs of one repeated character, e.g. "aaaa" or "!!!". */
  function findRepeats(chars) {
    var matches = [];
    var start = 0;
    for (var i = 1; i <= chars.length; i += 1) {
      if (i === chars.length || chars[i] !== chars[start]) {
        var length = i - start;
        if (length >= MIN_REPEAT_LENGTH) {
          matches.push(makeMatch('repeat', chars.slice(start, i).join(''), start, length));
        }
        start = i;
      }
    }
    return matches;
  }

  /**
   * Ascending or descending runs, e.g. "12345" or "dcba". Runs must stay
   * within one character class so we do not match across the ASCII boundary
   * between digits and letters.
   */
  function findSequences(chars) {
    var lowered = chars.map(function (c) { return c.toLowerCase(); });
    var matches = [];
    var start = 0;
    var direction = 0;

    function sameClass(a, b) {
      return (RE_DIGIT.test(a) && RE_DIGIT.test(b)) || (RE_LETTER.test(a) && RE_LETTER.test(b));
    }

    for (var i = 1; i <= lowered.length; i += 1) {
      var step = 0;
      if (i < lowered.length && sameClass(lowered[i - 1], lowered[i])) {
        var delta = lowered[i].codePointAt(0) - lowered[i - 1].codePointAt(0);
        step = (delta === 1 || delta === -1) ? delta : 0;
      }

      if (step === 0 || (direction !== 0 && step !== direction)) {
        var length = i - start;
        if (length >= MIN_SEQUENCE_LENGTH && direction !== 0) {
          matches.push(makeMatch('sequence', chars.slice(start, i).join(''), start, length));
        }
        // A broken run restarts at the character that broke it, which may
        // itself begin the next run (e.g. "abcXcba").
        start = step !== 0 ? i - 1 : i;
        direction = step;
      } else {
        direction = step;
      }
    }
    return matches;
  }

  /** Runs tracing adjacent keys on a QWERTY layout, e.g. "asdfgh". */
  function findKeyboardWalks(chars) {
    var matches = [];
    var i = 0;
    while (i < chars.length) {
      var best = 0;
      for (var r = 0; r < KEYBOARD_ROWS.length; r += 1) {
        var row = KEYBOARD_ROWS[r];
        var reversed = row.split('').reverse().join('');
        var length = MIN_KEYBOARD_RUN;
        while (i + length <= chars.length) {
          var chunk = chars.slice(i, i + length).join('');
          if (row.indexOf(chunk) !== -1 || reversed.indexOf(chunk) !== -1) {
            if (length > best) { best = length; }
            length += 1;
          } else {
            break;
          }
        }
      }
      if (best) {
        matches.push(makeMatch('keyboard', chars.slice(i, i + best).join(''), i, best));
        i += best;
      } else {
        i += 1;
      }
    }
    return matches;
  }

  /** Four-digit years (1900-2099), the classic password suffix. */
  function findDates(chars) {
    var text = chars.join('');
    var matches = [];
    var match;
    YEAR_RE.lastIndex = 0;
    while ((match = YEAR_RE.exec(text)) !== null) {
      matches.push(makeMatch('date', match[0], match.index, match[0].length));
    }
    return matches;
  }

  /** Weak-list tokens inside the password, case- and leet-insensitive. */
  function findDictionaryWords(chars, tokens) {
    if (!tokens || tokens.size === 0) { return []; }
    var limit = MAX_TOKEN_LENGTH;
    var variants = leetVariants(chars);
    var seen = new Set();
    var matches = [];

    for (var v = 0; v < variants.length; v += 1) {
      var variant = variants[v];
      for (var start = 0; start < variant.length; start += 1) {
        var maxLength = Math.min(limit, variant.length - start);
        // Longest match first: "password" should win over "pass".
        for (var length = maxLength; length >= MIN_TOKEN_LENGTH; length -= 1) {
          var candidate = variant.substr(start, length);
          if (tokens.has(candidate)) {
            var key = start + ':' + length;
            if (!seen.has(key)) {
              seen.add(key);
              matches.push(makeMatch('dictionary', candidate, start, length));
            }
            break;
          }
        }
      }
    }
    return matches;
  }

  /** True for passwords that are one short block repeated, e.g. "abcabcabc". */
  function isSingleRepeatedBlock(chars) {
    var length = chars.length;
    if (length < 4) { return false; }
    var text = chars.join('');
    for (var block = 1; block <= Math.floor(length / 2); block += 1) {
      if (length % block !== 0) { continue; }
      if (chars.slice(0, block).join('').repeat(length / block) === text) { return true; }
    }
    return false;
  }

  function findAll(chars, tokens) {
    return []
      .concat(findDictionaryWords(chars, tokens))
      .concat(findKeyboardWalks(chars))
      .concat(findSequences(chars))
      .concat(findRepeats(chars))
      .concat(findDates(chars));
  }

  /**
   * Reduce overlapping matches to one explanation per character. "1234" is
   * both a sequence and a keyboard walk; charging for both would double-count.
   */
  function selectNonOverlapping(matches) {
    var precedence = { dictionary: 0, keyboard: 1, sequence: 2, repeat: 3, date: 4 };
    var ordered = matches.slice().sort(function (a, b) {
      if (b.length !== a.length) { return b.length - a.length; }
      var pa = precedence[a.kind] === undefined ? 99 : precedence[a.kind];
      var pb = precedence[b.kind] === undefined ? 99 : precedence[b.kind];
      if (pa !== pb) { return pa - pb; }
      return a.start - b.start;
    });

    var claimed = new Set();
    var chosen = [];
    for (var i = 0; i < ordered.length; i += 1) {
      var match = ordered[i];
      var overlaps = false;
      for (var p = match.start; p < match.end; p += 1) {
        if (claimed.has(p)) { overlaps = true; break; }
      }
      if (overlaps) { continue; }
      for (var q = match.start; q < match.end; q += 1) { claimed.add(q); }
      chosen.push(match);
    }
    return chosen.sort(function (a, b) { return a.start - b.start; });
  }

  // --- scoring --------------------------------------------------------------

  /** Search-space size plus which character classes are present. */
  function characterPool(chars) {
    var classes = {
      lowercase: false, uppercase: false, digit: false,
      symbol: false, space: false, other: false
    };

    for (var i = 0; i < chars.length; i += 1) {
      var ch = chars[i];
      var code = ch.codePointAt(0);
      if (RE_LOWER.test(ch)) { classes.lowercase = true; }
      else if (RE_UPPER.test(ch)) { classes.uppercase = true; }
      else if (RE_DIGIT.test(ch)) { classes.digit = true; }
      else if (ch === ' ') { classes.space = true; }
      else if (code >= 33 && code <= 126) { classes.symbol = true; }
      else { classes.other = true; }
    }

    var pool =
      (classes.lowercase ? POOL_LOWERCASE : 0) +
      (classes.uppercase ? POOL_UPPERCASE : 0) +
      (classes.digit ? POOL_DIGITS : 0) +
      (classes.symbol ? POOL_SYMBOLS : 0) +
      (classes.space ? POOL_SPACE : 0) +
      (classes.other ? POOL_OTHER : 0);

    return { pool: Math.max(pool, 1), classes: classes };
  }

  /**
   * Cost of guessing a matched region from its own pattern space - far cheaper
   * than brute force, which is exactly the number an attacker actually pays.
   */
  function replacementBits(match, poolSize, tokenCount) {
    var lengthBits = log2(Math.max(match.length, 1));
    switch (match.kind) {
      // Index into the weak list, plus ~4 bits for case and leet mangling.
      case 'dictionary': return log2(Math.max(tokenCount, 2)) + 4.0;
      // Starting key (~47) x direction (2), times the run length.
      case 'keyboard': return log2(94) + lengthBits;
      // Starting character (~36) x direction (2), times the run length.
      case 'sequence': return log2(72) + lengthBits;
      // One character chosen from the pool, plus the run length.
      case 'repeat': return log2(poolSize) + lengthBits;
      case 'date': return log2(200); // years 1900-2099
      default: return lengthBits;
    }
  }

  function describe(match) {
    switch (match.kind) {
      case 'dictionary': return 'Contains the common word or password “' + match.token + '”';
      case 'keyboard': return 'Contains the keyboard pattern “' + match.token + '”';
      case 'sequence': return 'Contains the sequence “' + match.token + '”';
      case 'repeat': return 'Repeats the character “' + match.token.charAt(0) + '” ' + match.length + ' times in a row';
      case 'date': return 'Contains what looks like a year (' + match.token + ')';
      default: return 'Contains a predictable pattern';
    }
  }

  var DURATION_UNITS = [
    ['century', 'centuries', 60 * 60 * 24 * 365.25 * 100],
    ['year', 'years', 60 * 60 * 24 * 365.25],
    ['month', 'months', 60 * 60 * 24 * 30.44],
    ['day', 'days', 60 * 60 * 24],
    ['hour', 'hours', 60 * 60],
    ['minute', 'minutes', 60],
    ['second', 'seconds', 1]
  ];

  /**
   * Format a large magnitude the way Python's "%.3g" does, so the JavaScript
   * and Python reports read identically: three significant digits, trailing
   * zeros trimmed, two-digit exponent.
   */
  function formatLargeValue(value) {
    var parts = value.toExponential(2).split('e+');
    var mantissa = String(Number(parts[0]));
    var exponent = parts[1].length < 2 ? '0' + parts[1] : parts[1];
    return mantissa + 'e+' + exponent;
  }

  function formatDuration(seconds) {
    if (!isFinite(seconds)) { return 'effectively forever'; }
    if (seconds < 1) { return 'less than a second'; }
    for (var i = 0; i < DURATION_UNITS.length; i += 1) {
      var singular = DURATION_UNITS[i][0];
      var plural = DURATION_UNITS[i][1];
      var size = DURATION_UNITS[i][2];
      if (seconds >= size) {
        var value = seconds / size;
        if (value >= 1e6) { return formatLargeValue(value) + ' ' + plural; }
        var rounded = Math.round(value);
        return rounded + ' ' + (rounded === 1 ? singular : plural);
      }
    }
    return 'less than a second';
  }

  /** The live checklist shown in the UI. */
  function buildRequirements(length, classes, hasPatterns) {
    return [
      { id: 'min_length', label: 'At least ' + MIN_LENGTH + ' characters', met: length >= MIN_LENGTH },
      { id: 'ideal_length', label: IDEAL_LENGTH + ' or more characters', met: length >= IDEAL_LENGTH },
      { id: 'lowercase', label: 'Contains a lowercase letter', met: classes.lowercase },
      { id: 'uppercase', label: 'Contains an uppercase letter', met: classes.uppercase },
      { id: 'digit', label: 'Contains a number', met: classes.digit },
      { id: 'symbol', label: 'Contains a special character', met: classes.symbol || classes.space },
      { id: 'no_patterns', label: 'No common words or predictable patterns', met: !hasPatterns }
    ];
  }

  /** Actionable advice, ordered by how much it would improve the score. */
  function buildSuggestions(requirements, score) {
    var unmet = {};
    requirements.forEach(function (r) { if (!r.met) { unmet[r.id] = true; } });

    var suggestions = [];
    if (unmet.min_length) {
      suggestions.push('Use at least ' + MIN_LENGTH + ' characters.');
    } else if (unmet.ideal_length) {
      suggestions.push('Length helps more than anything else - aim for ' + IDEAL_LENGTH + '+ characters.');
    }
    if (unmet.no_patterns) {
      suggestions.push('Avoid dictionary words, names, years and keyboard runs.');
    }
    var missing = [
      ['uppercase', 'uppercase letters'],
      ['lowercase', 'lowercase letters'],
      ['digit', 'numbers'],
      ['symbol', 'special characters']
    ].filter(function (pair) { return unmet[pair[0]]; })
      .map(function (pair) { return pair[1]; });
    if (missing.length) {
      suggestions.push('Mix in ' + missing.join(', ') + '.');
    }
    if (score < 2) {
      suggestions.push('A passphrase of four or more unrelated words is both stronger and easier to remember.');
    }
    return suggestions;
  }

  /**
   * Evaluate a password.
   *
   * @param {string} password       the candidate
   * @param {Object} [options]
   * @param {string[]} [options.userInputs] context an attacker would try first
   *        (username, email, company name) - always pass what you know
   * @param {Set<string>} [options.tokens] override the weak-token list
   * @returns {Object} score, label, entropy, requirements, warnings, suggestions
   * @throws {TypeError} if password is not a string
   */
  function evaluate(password, options) {
    if (typeof password !== 'string') {
      throw new TypeError('password must be a string, got ' + typeof password);
    }
    var opts = options || {};

    // Normalise so visually identical strings score identically across
    // platforms and match the Python implementation's code-point counts.
    var normalised = password.normalize ? password.normalize('NFC') : password;
    var chars = toChars(normalised);
    var trueLength = chars.length;
    var warnings = [];

    if (trueLength > MAX_ANALYSIS_LENGTH) {
      // Bound the work: pattern scanning is superlinear and anything this long
      // is already far beyond any attacker's reach.
      chars = chars.slice(0, MAX_ANALYSIS_LENGTH);
      warnings.push('Only the first ' + MAX_ANALYSIS_LENGTH + ' characters were analysed.');
    }

    var length = chars.length;
    var poolInfo = characterPool(chars);
    var poolSize = poolInfo.pool;
    var classes = poolInfo.classes;

    if (length === 0) {
      return {
        length: 0,
        score: 0,
        label: SCORE_LABELS[0],
        entropyBits: 0,
        rawEntropyBits: 0,
        poolSize: 0,
        requirements: buildRequirements(0, classes, false),
        penalties: [],
        warnings: [],
        suggestions: [],
        isAcceptable: false,
        crackTimeOfflineSeconds: 0,
        crackTimeOnlineSeconds: 0,
        crackTimeDisplay: 'instantly'
      };
    }

    // Context tokens are matched exactly like weak-list entries.
    var tokens = opts.tokens || TOKENS;
    if (opts.userInputs && opts.userInputs.length) {
      tokens = new Set(tokens);
      opts.userInputs.forEach(function (input) {
        if (typeof input === 'string') {
          var trimmed = input.trim().toLowerCase();
          if (trimmed.length >= MIN_TOKEN_LENGTH) {
            tokens.add(trimmed);
            if (trimmed.length > MAX_TOKEN_LENGTH) { MAX_TOKEN_LENGTH = trimmed.length; }
          }
        }
      });
    }

    var rawEntropy = length * log2(poolSize);
    var found = selectNonOverlapping(findAll(chars, tokens));

    var penalties = [];
    var deducted = 0;
    found.forEach(function (match) {
      var bruteForceBits = match.length * log2(poolSize);
      var bits = Math.max(0, bruteForceBits - replacementBits(match, poolSize, tokens.size));
      if (bits > 0.01) {
        bits = Math.round(bits * 100) / 100;
        penalties.push({ id: match.kind, label: describe(match), bits: bits });
        deducted += bits;
      }
    });

    if (isSingleRepeatedBlock(chars)) {
      // "abcabcabc" - the whole password is one short block repeated.
      var blockPenalty = Math.max(0, rawEntropy - deducted - 12);
      if (blockPenalty > 0.01) {
        blockPenalty = Math.round(blockPenalty * 100) / 100;
        penalties.push({
          id: 'repeated_block',
          label: 'The whole password is one short block repeated',
          bits: blockPenalty
        });
        deducted += blockPenalty;
      }
    }

    var entropy = Math.max(0, rawEntropy - deducted);

    // Band the entropy, then apply policy caps entropy cannot buy past.
    var score = 0;
    for (var i = 0; i < SCORE_THRESHOLDS.length; i += 1) {
      if (entropy >= SCORE_THRESHOLDS[i]) { score += 1; }
    }

    var isKnownWeak = leetVariants(chars).some(function (form) {
      return tokens.has(form);
    });
    if (isKnownWeak) {
      score = 0;
      warnings.unshift('This is a known weak password - it would be guessed immediately.');
    }
    if (length < MIN_LENGTH) {
      score = Math.min(score, 1);
    } else if (length < IDEAL_LENGTH) {
      score = Math.min(score, 3);
    }

    penalties.forEach(function (p) { warnings.push(p.label); });

    var requirements = buildRequirements(length, classes, found.length > 0);
    var guesses = entropy < 1024 ? Math.pow(2, entropy) / 2 : Infinity;

    return {
      length: trueLength,
      score: score,
      label: SCORE_LABELS[score],
      entropyBits: Math.round(entropy * 100) / 100,
      rawEntropyBits: Math.round(rawEntropy * 100) / 100,
      poolSize: poolSize,
      requirements: requirements,
      penalties: penalties,
      warnings: warnings,
      suggestions: buildSuggestions(requirements, score),
      isAcceptable: score >= 2,
      crackTimeOfflineSeconds: guesses / OFFLINE_GUESSES_PER_SECOND,
      crackTimeOnlineSeconds: guesses / ONLINE_GUESSES_PER_SECOND,
      crackTimeDisplay: formatDuration(guesses / OFFLINE_GUESSES_PER_SECOND)
    };
  }

  return {
    evaluate: evaluate,
    formatDuration: formatDuration,
    normalizeLeet: function (text, alternate) {
      return normalizeLeet(toChars(text), alternate);
    },
    MIN_LENGTH: MIN_LENGTH,
    IDEAL_LENGTH: IDEAL_LENGTH,
    SCORE_LABELS: SCORE_LABELS,
    MAX_ANALYSIS_LENGTH: MAX_ANALYSIS_LENGTH
  };
});

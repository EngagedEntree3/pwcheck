/**
 * Password strength checker — UI wiring.
 *
 * This file only moves data between the DOM and PasswordStrength.evaluate().
 * All scoring lives in js/strength.js so the exact same model can be shared
 * with the Python backend; nothing here decides how strong a password is.
 *
 * Privacy: the value is read from the input, scored in memory, and never
 * stored, logged, or sent anywhere. There is no fetch() in this project.
 */
(function () {
  'use strict';

  var LIVE_REGION_DELAY = 700; // ms of quiet before announcing to a screen reader

  var el = {
    input: document.getElementById('password'),
    toggle: document.getElementById('toggle'),
    toggleText: document.querySelector('#toggle .toggle-text'),
    block: document.getElementById('meter-block'),
    meter: document.getElementById('meter'),
    fill: document.getElementById('meter-fill'),
    label: document.getElementById('strength-label'),
    time: document.getElementById('crack-time'),
    summary: document.getElementById('strength-summary'),
    checklist: document.getElementById('checklist'),
    advice: document.getElementById('advice'),
    adviceList: document.getElementById('advice-list'),
    details: document.getElementById('details'),
    stats: document.getElementById('stats'),
    penaltyIntro: document.getElementById('penalty-intro'),
    penaltyList: document.getElementById('penalty-list')
  };

  // If the scoring script failed to load, leave the static markup in place
  // rather than wiring up a control that would silently do nothing.
  if (!window.PasswordStrength || !el.input) {
    return;
  }

  var strength = window.PasswordStrength;
  var announceTimer = null;

  /** Build one checklist row. Screen readers get the state in words, not colour. */
  function renderCheck(requirement) {
    var item = document.createElement('li');
    item.className = 'check ' + (requirement.met ? 'is-met' : 'is-unmet');

    var mark = document.createElement('span');
    mark.className = 'check-mark';
    mark.setAttribute('aria-hidden', 'true');
    mark.textContent = requirement.met ? '✓' : '○';

    var text = document.createElement('span');
    text.textContent = requirement.label;

    // Colour and glyph are reinforced by text, so the state survives both
    // colour blindness and a screen reader.
    var state = document.createElement('span');
    state.className = 'visually-hidden';
    state.textContent = requirement.met ? ' — met' : ' — not met';

    text.appendChild(state);
    item.appendChild(mark);
    item.appendChild(text);
    return item;
  }

  function renderChecklist(requirements) {
    var fragment = document.createDocumentFragment();
    requirements.forEach(function (requirement) {
      fragment.appendChild(renderCheck(requirement));
    });
    el.checklist.replaceChildren(fragment);
  }

  function renderList(target, items) {
    var fragment = document.createDocumentFragment();
    items.forEach(function (text) {
      var item = document.createElement('li');
      // textContent, never innerHTML: the password and anything derived from
      // it must never be parsed as markup.
      item.appendChild(document.createTextNode(text));
      fragment.appendChild(item);
    });
    target.replaceChildren(fragment);
  }

  function renderStats(result) {
    var rows = [
      ['Length', String(result.length)],
      ['Entropy', result.entropyBits.toFixed(1) + ' bits'],
      ['Character pool', String(result.poolSize)],
      ['Offline attack', result.crackTimeDisplay]
    ];
    var fragment = document.createDocumentFragment();
    rows.forEach(function (row) {
      var group = document.createElement('div');
      var term = document.createElement('dt');
      term.textContent = row[0];
      var value = document.createElement('dd');
      value.textContent = row[1];
      group.appendChild(term);
      group.appendChild(value);
      fragment.appendChild(group);
    });
    el.stats.replaceChildren(fragment);
  }

  /**
   * Announce the verdict politely, but only once the user stops typing.
   * Updating a live region on every keystroke makes a screen reader
   * unusable, so the visuals update instantly and speech lags behind.
   */
  function announce(message) {
    window.clearTimeout(announceTimer);
    announceTimer = window.setTimeout(function () {
      el.summary.textContent = message;
    }, LIVE_REGION_DELAY);
  }

  function renderEmpty() {
    el.block.setAttribute('data-score', 'empty');
    el.fill.style.width = '0%';
    el.label.textContent = 'No password yet';
    el.time.textContent = '';
    el.meter.setAttribute('aria-valuenow', '0');
    el.meter.setAttribute('aria-valuetext', 'No password entered');
    renderChecklist(strength.evaluate('').requirements);
    el.advice.hidden = true;
    el.details.hidden = true;
    announce('Enter a password to see how strong it is.');
  }

  function render(result) {
    var met = result.requirements.filter(function (r) { return r.met; }).length;

    el.block.setAttribute('data-score', String(result.score));
    // Five bands over a 0-100% track: the weakest band still shows a sliver,
    // so the meter never reads as "nothing entered" when something was.
    el.fill.style.width = ((result.score + 1) / 5) * 100 + '%';
    el.label.textContent = result.label;
    el.time.textContent = 'Offline attack: ' + result.crackTimeDisplay;

    el.meter.setAttribute('aria-valuenow', String(result.score));
    el.meter.setAttribute('aria-valuetext', result.label);

    renderChecklist(result.requirements);

    var advice = result.suggestions.concat(
      result.warnings.filter(function (w) {
        return result.suggestions.indexOf(w) === -1;
      })
    );
    if (advice.length) {
      renderList(el.adviceList, advice);
      el.advice.hidden = false;
    } else {
      el.advice.hidden = true;
    }

    renderStats(result);
    if (result.penalties.length) {
      renderList(
        el.penaltyList,
        result.penalties.map(function (p) {
          return p.bits.toFixed(1) + ' bits — ' + p.label;
        })
      );
      el.penaltyIntro.hidden = false;
    } else {
      el.penaltyList.replaceChildren();
      el.penaltyIntro.hidden = true;
    }
    el.details.hidden = false;

    announce(
      result.label + '. ' + met + ' of ' + result.requirements.length +
      ' requirements met. Offline attack: ' + result.crackTimeDisplay + '.'
    );
  }

  function update() {
    var value = el.input.value;
    if (!value) {
      renderEmpty();
      return;
    }
    try {
      render(strength.evaluate(value));
    } catch (error) {
      // Never leave the meter showing a stale verdict for a new password.
      renderEmpty();
      el.summary.textContent = 'Could not score this password.';
      if (window.console) { window.console.error(error); }
    }
  }

  el.toggle.addEventListener('click', function () {
    var revealed = el.input.type === 'text';
    var start = el.input.selectionStart;
    var end = el.input.selectionEnd;

    el.input.type = revealed ? 'password' : 'text';
    el.toggle.setAttribute('aria-pressed', String(!revealed));
    el.toggleText.textContent = revealed ? 'Show' : 'Hide';

    // Changing `type` drops the caret to the end in most browsers; put the
    // user back where they were so the toggle never costs them their place.
    el.input.focus();
    if (start !== null && typeof el.input.setSelectionRange === 'function') {
      try { el.input.setSelectionRange(start, end); } catch (ignored) { /* unsupported type */ }
    }
  });

  el.input.addEventListener('input', update);

  // Re-hide the password when the field loses focus: a revealed password left
  // on screen is the main risk this control introduces.
  el.input.addEventListener('blur', function (event) {
    if (event.relatedTarget === el.toggle) { return; }
    if (el.input.type === 'text') {
      el.input.type = 'password';
      el.toggle.setAttribute('aria-pressed', 'false');
      el.toggleText.textContent = 'Show';
    }
  });

  // Browsers restore field values on back/forward navigation and on reload.
  update();
})();

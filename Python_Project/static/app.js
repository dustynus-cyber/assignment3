/* Link Check — page logic.
 *
 * Two detection layers are shown to the user:
 *   1. The trained structural model, served by the Flask backend (/api/check).
 *   2. The impersonation layer (defense.js), run here in the browser.
 * The displayed verdict combines them (model OR impersonation), the same rule
 * measured in security/evaluate.py.
 *
 * Safety: pasted URLs are only ever written with textContent, never as HTML
 * and never as clickable links. innerHTML is used for fixed icon SVGs only. */

const $ = (id) => document.getElementById(id);
const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const supportsViewTransitions = typeof document.startViewTransition === 'function';
const RING = 2 * Math.PI * 34;            // circumference of the trust ring (r = 34)

// ---- state ----
let historyItems = [];
let currentResult = null;
let filter = 'all';
let visibleRows = 9;
let requestNumber = 0;
let controller = null;
let focusInputNext = false;   // "Check another link" lands the cursor in the input

const labels = { high: 'High risk', caution: 'Be careful', low: 'Low risk' };
const titles = {
  high: 'We’d avoid this one',
  caution: 'Be careful with this link',
  low: 'Looks low risk — still check',
};

// ---- fixed inline icons ----
const iconPaths = {
  search: 'M21 21l-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
  check: 'M12 2 4 5v6c0 5 4 9 8 10 4-1 8-5 8-10V5ZM9 12l2 2 4-4',
  alert: 'M10.3 4.3 2.6 18a1.9 1.9 0 0 0 1.7 2.9h15.4a1.9 1.9 0 0 0 1.7-2.9L13.7 4.3a1.9 1.9 0 0 0-3.4 0ZM12 9v4M12 17h.01',
};
function icon(name) {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${iconPaths[name]}"/></svg>`;
}

// ---- helpers ----
function element(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
function checkedTime(item) {
  return new Date(item.checked_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
}

/* Attach the impersonation layer to a result and derive the combined verdict.
   A strong impersonation signal raises the shown risk to "high". */
function decorate(item) {
  const signals = window.PhishDefense ? PhishDefense.impersonationSignals(item.url) : [];
  item.impersonation = signals;
  item.strongImpersonation = signals.some((s) => s.strength === 'strong');
  item.displayRisk = item.strongImpersonation ? 'high' : item.risk;
  return item;
}

/* Risk mark: a coloured dot and a word. No pill, no chip. */
function riskMark(risk, text) {
  const el = element('span', undefined, `risk risk-${risk}`);
  const dot = element('i');
  dot.setAttribute('aria-hidden', 'true');
  el.append(dot, document.createTextNode(text || labels[risk]));
  return el;
}

/* ---- URL anatomy ----
   Browsers highlight the registered domain because that is who owns the
   site. We do the same: everything else is dimmed, and text before an "@"
   is struck through because the browser ignores it for the destination. */
function splitUrl(url) {
  const text = String(url).trim();
  let parsed;
  try {
    parsed = new URL(text.includes('://') ? text : 'http://' + text);
  } catch {
    return null;
  }
  const host = parsed.hostname;
  if (!host) return null;
  const isIp = /^[\d.]+$/.test(host) || host.startsWith('[');
  const domain = isIp ? host : PhishDefense.registrableDomain(host.replace(/^www\./, ''));
  // URL() always reports a "/" path; only show it if the user actually typed one.
  const afterScheme = text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[?#]/)[0];
  const showPath = parsed.pathname !== '/' || afterScheme.includes('/');
  return {
    scheme: text.includes('://') ? parsed.protocol + '//' : '',
    creds: parsed.username ? parsed.username + (parsed.password ? ':•••' : '') + '@' : '',
    sub: host.slice(0, host.length - domain.length),
    domain,
    rest: (parsed.port ? ':' + parsed.port : '') + (showPath ? parsed.pathname : '') + parsed.search + parsed.hash,
  };
}

function renderAnatomy(target, url, risk) {
  target.replaceChildren();
  target.dataset.risk = risk || '';
  const parts = splitUrl(url);
  if (!parts) { target.textContent = url; return; }
  const add = (text, className, title) => {
    if (!text) return;
    const span = element('span', text, className);
    if (title) span.title = title;
    target.append(span);
  };
  add(parts.scheme, 'dim');
  add(parts.creds, 'creds', 'Ignored by the browser: the real destination is after the @.');
  add(parts.sub, 'dim');
  add(parts.domain, 'domain', 'The registered domain: who actually owns this site.');
  add(parts.rest, 'dim');
}

/* ---- sliding underline (nav + filters) ----
   One indicator moves with transform only. The first placement and resizes
   jump without animating, so it never slides in from the left edge. */
function placeIndicator(container, indicator, active, animate = true) {
  if (!active) { indicator.style.opacity = '0'; return; }
  const box = container.getBoundingClientRect();
  const rect = active.getBoundingClientRect();
  const jump = !animate || indicator.style.opacity !== '1';
  if (jump) indicator.style.transition = 'none';
  indicator.style.transform = `translateX(${rect.left - box.left}px) scaleX(${rect.width / 100})`;
  indicator.style.opacity = '1';
  if (jump) {
    indicator.getBoundingClientRect();     // commit the jump before re-enabling transitions
    indicator.style.transition = '';
  }
}

function syncNav(name, animate = true) {
  const target = name === 'history' ? '#history' : location.hash === '#how' ? '#how' : '#home';
  let active = null;
  document.querySelectorAll('#nav a').forEach((a) => {
    if (a.hash === target) { a.setAttribute('aria-current', 'page'); active = a; }
    else a.removeAttribute('aria-current');
  });
  placeIndicator($('nav'), $('nav-indicator'), active, animate);
}

function syncFilters(animate = true) {
  placeIndicator($('filters'), $('filter-indicator'), $('filters').querySelector('[aria-pressed="true"]'), animate);
}

// ---- routing + page transitions ----
function showPage(name) {
  const view = $(name);
  const alreadyVisible = !view.hidden;
  syncNav(name);
  if (alreadyVisible) return Promise.resolve();

  const swap = () => {
    document.querySelectorAll('.view').forEach((el) => (el.hidden = el.id !== name));
    window.scrollTo(0, 0);
  };
  const done = supportsViewTransitions && !reduceMotion.matches
    ? document.startViewTransition(swap).updateCallbackDone
    : Promise.resolve(swap());
  return done.then(() => {
    if (name === 'home' && focusInputNext) {
      focusInputNext = false;
      $('url-input').focus({ preventScroll: true });
      return;
    }
    const heading = view.querySelector('h1') || view;
    heading.setAttribute('tabindex', '-1');
    heading.focus({ preventScroll: true });   // announce the new page to screen readers
  });
}

function route() {
  const hash = location.hash.slice(1) || 'home';
  if (hash === 'history') {
    renderHistory();
    showPage('history').then(() => syncFilters(false));
  } else if (hash === 'result' && currentResult) {
    showPage('result').then(() => animateScore(currentResult));
  } else {
    showPage('home').then(() => {
      if (hash === 'how') $('how').scrollIntoView({ behavior: reduceMotion.matches ? 'auto' : 'smooth' });
    });
  }
}
function go(name) {
  if (location.hash === '#' + name) route();
  else location.hash = name;
}
window.addEventListener('hashchange', route);

// ---- trust ring ----
/* Same critically damped spring as --spring in the CSS: no overshoot. */
function spring(t) { return t >= 1 ? 1 : 1 - (1 + 7 * t) * Math.exp(-7 * t); }
let scoreFrame = 0;
function animateScore(item) {
  cancelAnimationFrame(scoreFrame);
  const ring = $('ring-value');
  const label = $('score');
  const target = Math.max(0, Math.min(100, item.trust_score));
  const end = RING * (1 - target / 100);
  if (reduceMotion.matches) {
    ring.style.strokeDashoffset = end;
    label.textContent = String(target);
    return;
  }
  const start = performance.now();
  const duration = 1100;
  const tick = (now) => {
    const t = Math.min(1, (now - start) / duration);
    const p = spring(t);
    ring.style.strokeDashoffset = RING - (RING - end) * p;
    label.textContent = t < 1 ? String(Math.round(target * p)) : String(target);
    if (t < 1) scoreFrame = requestAnimationFrame(tick);
  };
  ring.style.strokeDashoffset = RING;
  scoreFrame = requestAnimationFrame(tick);
}

// ---- result view ----
function obsRow(iconName, title, text, className, index) {
  const row = element('div', undefined, `obs-row ${className || ''}`);
  row.style.setProperty('--i', index);
  row.insertAdjacentHTML('afterbegin', icon(iconName));
  const body = element('div');
  body.append(element('h3', title), element('p', text));
  row.append(body);
  return row;
}

function openResult(item) {
  currentResult = item;
  const risk = item.displayRisk;
  const decided = item.strongImpersonation && item.risk !== 'high';

  $('result-card').dataset.risk = risk;
  $('verdict-word').replaceChildren(riskMark(risk));
  $('result-title').textContent = titles[risk];
  $('result-subtitle').textContent = decided
    ? 'The impersonation layer caught what the model let through.'
    : `Trust score ${item.trust_score}/100, read from the URL alone.`;
  $('score').textContent = '0';
  $('ring-value').style.strokeDashoffset = RING;

  renderAnatomy($('result-anatomy'), item.url, item.strongImpersonation ? 'high' : '');
  $('result-url').textContent = item.url;

  // Layer 1 — structural model (from the backend).
  $('model-verdict').replaceChildren(riskMark(item.risk),
    document.createTextNode(`trust ${item.trust_score}/100 · phishing score ${(item.phishing_probability * 100).toFixed(1)}%`));
  $('model-explanation').textContent = `The trained model classified this URL as ${item.prediction}, `
    + 'using only its structure: length, dots, hyphens, digits and TLD.';
  const obs = $('observations');
  obs.replaceChildren();
  if (!item.observations.length) {
    obs.append(obsRow('check', 'No structural warning signs', 'Our simple checks found nothing unusual. The model can still make mistakes.', 'clear', 0));
  }
  item.observations.forEach((note, i) => obs.append(obsRow('search', note.title, note.text, '', i)));

  const dl = $('feature-list');
  dl.replaceChildren();
  Object.entries(item.features).forEach(([name, value]) => {
    dl.append(element('dt', name.replaceAll('_', ' ')),
      element('dd', Number.isInteger(value) ? value : Number(value).toFixed(3)));
  });

  // Layer 2 — impersonation defence (in the browser).
  const layer = $('layer-imp');
  layer.classList.toggle('decided', decided);
  const verdict = item.strongImpersonation ? riskMark('high', 'Brand look-alike found')
    : item.impersonation.length ? riskMark('caution', 'Weak signals only')
    : riskMark('low', 'No look-alike found');
  $('imp-verdict').replaceChildren(verdict);
  if (decided) $('imp-verdict').append(element('span', 'Decided the verdict', 'decided-note'));
  $('imp-explanation').textContent = decided
    ? `The model alone rated this ${item.trust_score}/100 (${labels[item.risk].toLowerCase()}), but this layer found a brand look-alike, so the combined verdict is high risk.`
    : item.strongImpersonation
      ? 'This layer independently confirms the model’s verdict.'
      : 'Looks for punycode, typosquats and brand names outside their real domain.';
  const list = $('impersonation-list');
  list.replaceChildren();
  item.impersonation.forEach((sig, i) =>
    list.append(obsRow(sig.strength === 'strong' ? 'alert' : 'search', sig.title, sig.text, sig.strength, i)));

  // Advice.
  const advice = risk === 'low'
    ? ['Check the highlighted domain before opening the link.',
       'Use an official app or a known bookmark for sensitive accounts.',
       'Do not rely on this score alone.']
    : ['Avoid opening the link until you confirm who sent it.',
       'Do not enter passwords or personal information.',
       'Use the organisation’s official app or a known bookmark instead.'];
  $('advice').replaceChildren(...advice.map((text) => element('li', text)));

  $('report').disabled = item.reported;
  $('report').textContent = item.reported ? 'Saved for review' : 'Report this result';
  $('action-message').textContent = '';
  go('result');
}

// ---- lists ----
function renderRecent() {
  const container = $('recent-list');
  container.replaceChildren();
  if (!historyItems.length) {
    container.append(element('p', 'No links checked yet. Paste one above to get started.', 'empty'));
    return;
  }
  historyItems.slice(0, 3).forEach((item) => {
    const row = element('button', undefined, 'row');
    row.type = 'button';
    const chev = element('span', '›', 'row-chev');
    chev.setAttribute('aria-hidden', 'true');
    row.append(element('span', item.url, 'row-url'), element('span', checkedTime(item), 'row-time'),
      riskMark(item.displayRisk), chev);
    row.addEventListener('click', () => openResult(item));
    container.append(row);
  });
}

function renderHistory() {
  const counts = $('history-counts');
  counts.replaceChildren();
  const count = (risk) => historyItems.filter((i) => i.displayRisk === risk).length;
  [['links checked', historyItems.length, ''], ['high risk', count('high'), 'high'],
   ['be careful', count('caution'), 'caution'], ['low risk', count('low'), 'low']]
    .forEach(([label, value, tone]) => {
      const stat = element('div', undefined, `stat ${tone}`);
      stat.append(element('strong', String(value)), element('span', label));
      counts.append(stat);
    });

  const search = $('search').value.toLowerCase();
  const items = historyItems.filter((i) =>
    (filter === 'all' || i.displayRisk === filter) &&
    (i.url.toLowerCase().includes(search) || labels[i.displayRisk].toLowerCase().includes(search)));

  const rows = $('history-rows');
  rows.replaceChildren();
  items.slice(0, visibleRows).forEach((item) => {
    const row = element('tr');
    const url = element('td', item.url);
    url.title = item.url;
    const verdict = element('td');
    verdict.append(riskMark(item.displayRisk));
    const open = element('button', 'Open ›', 'open-btn');
    open.type = 'button';
    open.setAttribute('aria-label', `Open result for ${item.url}`);
    open.addEventListener('click', () => openResult(item));
    const action = element('td');
    action.append(open);
    row.append(url, verdict, element('td', `${item.trust_score}/100`, 'num'),
      element('td', checkedTime(item), 'row-time'), action);
    rows.append(row);
  });

  $('history-empty').hidden = items.length > 0;
  $('history-empty').textContent = historyItems.length
    ? 'No links match this filter.'
    : 'No links checked yet. Paste one on the Check a link page.';
  $('load-more').hidden = items.length <= visibleRows;
}

async function loadHistory() {
  const response = await fetch('/api/history');
  if (!response.ok) throw new Error('History could not be loaded. Refresh to try again.');
  historyItems = (await response.json()).map(decorate);
  renderRecent();
  renderHistory();
}

// ---- live preview while typing (instant: no debounce, no network) ----
function updateLive() {
  const value = $('url-input').value.trim();
  const host = value && window.PhishDefense ? PhishDefense.host(value) : '';
  const live = $('live');
  const field = $('field');
  if (!host || !host.includes('.')) {
    live.dataset.open = 'false';
    field.dataset.risk = '';
    return;
  }
  const signals = PhishDefense.impersonationSignals(value);
  const strong = signals.find((s) => s.strength === 'strong');
  const shown = strong || signals[0];
  renderAnatomy($('live-anatomy'), value, strong ? 'high' : '');
  field.dataset.risk = strong ? 'high' : '';

  const box = $('live-signal');
  if (shown) {
    box.className = strong ? 'signal' : 'signal weak';
    box.replaceChildren();
    box.insertAdjacentHTML('afterbegin', icon('alert'));
    const text = element('span');
    text.append(element('strong', shown.title + '. '), document.createTextNode(shown.text));
    box.append(text);
    box.hidden = false;
  } else {
    box.hidden = true;
  }
  live.dataset.open = 'true';
}
$('url-input').addEventListener('input', updateLive);

document.querySelectorAll('[data-example]').forEach((button) => {
  button.addEventListener('click', () => {
    $('url-input').value = button.dataset.example;
    updateLive();
    $('url-input').focus();
  });
});

// ---- actions ----
$('search').addEventListener('input', () => { visibleRows = 9; renderHistory(); });
$('filters').addEventListener('click', (event) => {
  const button = event.target.closest('[data-filter]');
  if (!button) return;
  filter = button.dataset.filter;
  visibleRows = 9;
  document.querySelectorAll('[data-filter]').forEach((b) => b.setAttribute('aria-pressed', String(b === button)));
  syncFilters();
  renderHistory();
});
$('load-more').addEventListener('click', () => { visibleRows += 9; renderHistory(); });

$('check-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('form-error').textContent = '';
  const url = $('url-input').value.trim();
  if (!url) { $('form-error').textContent = 'Please paste a website address.'; return; }

  const number = ++requestNumber;
  controller = new AbortController();
  $('loading-url').textContent = url;
  // Only show the loading page if the answer is slow; a fast answer skips it,
  // so there is no flash and no artificial wait.
  const loadingTimer = setTimeout(() => { if (number === requestNumber) showPage('loading'); }, 180);
  try {
    const response = await fetch('/api/check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }), signal: controller.signal,
    });
    const result = await response.json();
    clearTimeout(loadingTimer);
    if (number !== requestNumber) return;
    if (!response.ok) throw new Error(result.error || 'The check failed. Please try again.');
    decorate(result);
    historyItems.unshift(result);
    renderRecent();
    renderHistory();
    openResult(result);
  } catch (error) {
    clearTimeout(loadingTimer);
    if (number !== requestNumber || error.name === 'AbortError') return;
    showPage('home');
    $('form-error').textContent = error.message;
    $('url-input').focus();
  }
});

$('cancel').addEventListener('click', () => {
  ++requestNumber;
  controller?.abort();
  showPage('home');
  $('url-input').focus();
  loadHistory().catch(() => {});
});
$('another').addEventListener('click', () => {
  $('url-input').value = '';
  updateLive();
  focusInputNext = true;
  go('home');
});
$('recheck').addEventListener('click', () => {
  if (!currentResult) return;
  $('url-input').value = currentResult.url;
  updateLive();
  $('check-form').requestSubmit();
});
$('report').addEventListener('click', async () => {
  if (!currentResult) return;
  $('report').disabled = true;
  try {
    const response = await fetch(`/api/report/${currentResult.id}`, { method: 'POST' });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not save this report.');
    currentResult.reported = true;
    $('report').textContent = 'Saved for review';
    $('action-message').textContent = data.message;
  } catch (error) {
    $('report').disabled = false;
    $('action-message').textContent = error.message;
  }
});
$('copy').addEventListener('click', async () => {
  if (!currentResult) return;
  const summary = `Link Check: ${labels[currentResult.displayRisk]}\n${currentResult.url}\n`
    + `Trust score: ${currentResult.trust_score}/100`
    + (currentResult.strongImpersonation ? '\nImpersonation layer: flagged a brand look-alike' : '')
    + '\nModel estimate only; the website was not visited.';
  try {
    await navigator.clipboard.writeText(summary);
    $('action-message').textContent = 'Summary copied.';
  } catch {
    $('action-message').textContent = 'Copy is unavailable in this browser. Select the result text to copy it.';
  }
});
$('privacy').addEventListener('click', () => {
  $('notice').textContent = 'This local app stores the pasted URL, its features, and the result in SQLite for history. '
    + 'The impersonation check runs in your browser and sends nothing. Avoid pasting links with private tokens. '
    + 'History is separated by browser cookie.';
  $('notice').hidden = !$('notice').hidden;
});

// ---- chrome: scroll edge + resize ----
window.addEventListener('scroll', () => {
  $('topbar').classList.toggle('scrolled', window.scrollY > 4);
}, { passive: true });
window.addEventListener('resize', () => {
  syncNav(document.querySelector('.view:not([hidden])').id, false);
  if (!$('history').hidden) syncFilters(false);
});

// ---- init ----
if (supportsViewTransitions && !reduceMotion.matches) document.documentElement.classList.add('vt');
setTimeout(() => document.documentElement.classList.add('booted'), 1200);
route();
loadHistory().catch((error) => { $('form-error').textContent = error.message; });

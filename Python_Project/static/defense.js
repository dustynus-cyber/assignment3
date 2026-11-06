/* Client-side impersonation defence.
 *
 * This is a faithful mirror of security/defense.py. It runs in the browser so
 * the user gets an INSTANT impersonation warning as they type -- before the
 * request to the structural model even returns. The Python copy is the one we
 * measure (see security/evaluate.py); production would fold the same check into
 * the backend verdict (model OR impersonation). Keeping the two in step is the
 * point, so the rules below are line-for-line the same as the Python ones.
 *
 * It reads only the URL string. It never opens the site. Pure, no network. */
(function (global) {
  'use strict';

  // Most-impersonated brands (APWG/PhishTank) -> their real registrable domain.
  const BRANDS = {
    paypal: 'paypal.com', apple: 'apple.com', microsoft: 'microsoft.com',
    amazon: 'amazon.com', google: 'google.com', netflix: 'netflix.com',
    facebook: 'facebook.com', instagram: 'instagram.com', whatsapp: 'whatsapp.com',
    linkedin: 'linkedin.com', chase: 'chase.com', wellsfargo: 'wellsfargo.com',
    bankofamerica: 'bankofamerica.com', coinbase: 'coinbase.com', binance: 'binance.com',
    dhl: 'dhl.com', fedex: 'fedex.com', ups: 'ups.com', usps: 'usps.com',
    dropbox: 'dropbox.com', adobe: 'adobe.com', ebay: 'ebay.com',
    steam: 'steampowered.com', roblox: 'roblox.com'
  };
  const ABUSED_TLDS = new Set(['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'zip',
    'mov', 'country', 'kim', 'work', 'click', 'link', 'rest']);
  const MULTI_LABEL_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk',
    'co.jp', 'com.au', 'co.nz', 'com.br', 'co.za', 'com.sg', 'com.my']);
  const CONFUSABLES = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '9': 'g', '$': 's', '@': 'a', '|': 'l' };

  function host(url) {
    const text = String(url).trim();
    try {
      const parsed = new URL(text.includes('://') ? text : 'http://' + text);
      return parsed.hostname.toLowerCase().replace(/^www\./, '');
    } catch (e) {
      return '';
    }
  }

  function registrableDomain(h) {
    const labels = h.split('.');
    if (labels.length < 2) return h;
    const lastTwo = labels.slice(-2).join('.');
    if (MULTI_LABEL_SUFFIXES.has(lastTwo) && labels.length >= 3) {
      return labels.slice(-3).join('.');
    }
    return lastTwo;
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1,
          prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  function deconfuse(text) {
    return text.split('').map((c) => CONFUSABLES[c] || c).join('');
  }

  function impersonationSignals(url) {
    const h = host(url);
    if (!h) return [];
    const registrable = registrableDomain(h);
    const regLabel = registrable.split('.')[0];
    const tld = h.split('.').pop();
    const signals = [];

    const tokens = new Set();
    for (const label of h.split('.')) {
      for (const token of label.split('-')) {
        tokens.add(token);
        tokens.add(deconfuse(token));
      }
    }

    if (h.includes('xn--')) {
      signals.push({ code: 'punycode', strength: 'strong', title: 'Punycode hostname',
        text: 'The host uses xn-- encoding, a common way to disguise look-alike letters.' });
    } else if ([...h].some((c) => c.charCodeAt(0) > 127)) {
      signals.push({ code: 'non_ascii_host', strength: 'strong', title: 'Non-standard characters in host',
        text: 'The host mixes in non-English letters that can imitate a trusted name.' });
    }

    for (const brand in BRANDS) {
      const legit = BRANDS[brand];
      if (registrable === legit) continue;         // genuinely this brand's domain

      const foldedLabel = deconfuse(regLabel);
      if (brand.length >= 5 && regLabel !== brand
          && levenshtein(foldedLabel, brand) <= 1
          && Math.abs(foldedLabel.length - brand.length) <= 1) {
        signals.push({ code: 'typosquat', strength: 'strong', title: `Look-alike of "${brand}"`,
          text: `The domain "${regLabel}" is within one character of ${legit}.` });
        break;
      }
      if (tokens.has(brand)) {
        signals.push({ code: 'brand_misplaced', strength: 'strong', title: `"${brand}" outside its real domain`,
          text: `The name "${brand}" appears, but the registered domain is "${registrable}", not ${legit}.` });
        break;
      }
    }

    if (ABUSED_TLDS.has(tld)) {
      signals.push({ code: 'abused_tld', strength: 'weak', title: `.${tld} domain`,
        text: `The .${tld} suffix is cheap and heavily abused, but also used legitimately.` });
    }
    if ((h.match(/\./g) || []).length >= 4) {
      signals.push({ code: 'deep_subdomains', strength: 'weak', title: 'Many subdomains',
        text: 'Several subdomains push the real domain out of easy view.' });
    }
    return signals;
  }

  function flagsAsPhishing(url) {
    return impersonationSignals(url).some((s) => s.strength === 'strong');
  }

  global.PhishDefense = { impersonationSignals, flagsAsPhishing, host, registrableDomain };
})(window);

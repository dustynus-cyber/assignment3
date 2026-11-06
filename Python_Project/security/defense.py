"""Impersonation-signal layer: a defence that reads the parts of a URL an
attacker cannot drop without also failing to impersonate a brand.

Why this layer exists
---------------------
The trained model in ``../models/classifier.joblib`` only reads *structural*
features (length, dot count, hyphens, digit ratio, common TLD, ...). Those are
cheap for an attacker to reshape: a phishing URL can be shortened, moved to a
``.com`` and stripped of hyphens until it looks structurally ordinary. See
``attack.py``.

But a phishing URL still has a job to do: convince a human it belongs to a real
brand. To do that it must *look like* the brand somewhere in the hostname. That
requirement leaves fingerprints that survive structural flattening:

  * Punycode / IDN homographs        (``xn--pypal-4ve.com``)
  * Non-ASCII look-alike characters  (Cyrillic "а" inside ``pаypal.com``)
  * A brand name placed outside the registrable domain
                                     (``paypal.secure-login.com``)
  * Typosquats of a brand domain     (``paypa1.com``, ``micros0ft.com``)

These are the attacker's dilemma: evade the structural model (look generic) OR
impersonate the brand (look like it) -- they struggle to do both at once.

This module reads ONLY the URL string. It never visits the site. It is a pure
function so the exact same rules can be mirrored in the browser (static/app.js)
and measured here.
"""
from urllib.parse import urlsplit

# --- Reference data -------------------------------------------------------
# The brands most often impersonated in real phishing (APWG / PhishTank top
# targets). The value is the brand's legitimate registrable domain, so we can
# tell "this really is PayPal" apart from "this only mentions PayPal".
BRANDS = {
    'paypal': 'paypal.com', 'apple': 'apple.com', 'microsoft': 'microsoft.com',
    'amazon': 'amazon.com', 'google': 'google.com', 'netflix': 'netflix.com',
    'facebook': 'facebook.com', 'instagram': 'instagram.com', 'whatsapp': 'whatsapp.com',
    'linkedin': 'linkedin.com', 'chase': 'chase.com', 'wellsfargo': 'wellsfargo.com',
    'bankofamerica': 'bankofamerica.com', 'coinbase': 'coinbase.com', 'binance': 'binance.com',
    'dhl': 'dhl.com', 'fedex': 'fedex.com', 'ups': 'ups.com', 'usps': 'usps.com',
    'dropbox': 'dropbox.com', 'adobe': 'adobe.com', 'ebay': 'ebay.com',
    'steam': 'steampowered.com', 'roblox': 'roblox.com',
}

# TLDs that are cheap or free and are abused far above their market share
# (Spamhaus / Interisle "most abused TLDs" reports). A weak signal on its own.
ABUSED_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'zip', 'mov',
               'country', 'kim', 'work', 'click', 'link', 'rest'}

# Second-level public suffixes we handle so the registrable domain of
# ``bbc.co.uk`` is ``bbc.co.uk`` and not ``co.uk``. Small on purpose: a full
# Public Suffix List is a backend concern, this is a deliberate approximation.
MULTI_LABEL_SUFFIXES = {'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'com.au',
                        'co.nz', 'com.br', 'co.za', 'com.sg', 'com.my'}

# Characters attackers swap in to look like letters ("leet"/visual spoofing).
CONFUSABLES = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',
               '9': 'g', '$': 's', '@': 'a', '|': 'l'}


def _host(url):
    text = str(url).strip()
    parsed = urlsplit(text if '://' in text else '//' + text)
    return (parsed.hostname or '').lower().removeprefix('www.')


def registrable_domain(host):
    """The part a user actually controls, e.g. ``login.paypal.com`` -> ``paypal.com``.

    Approximation using a short suffix list; good enough to separate the
    registrable label from everything an attacker can freely prepend.
    """
    labels = host.split('.')
    if len(labels) < 2:
        return host
    last_two = '.'.join(labels[-2:])
    if last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return '.'.join(labels[-3:])
    return last_two


def _levenshtein(a, b):
    """Edit distance. Used to catch typosquats one keystroke from a brand."""
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _deconfuse(text):
    """Fold look-alike characters so ``paypa1`` and ``paypal`` compare equal."""
    return ''.join(CONFUSABLES.get(c, c) for c in text)


def impersonation_signals(url):
    """Return the list of impersonation signals found in ``url`` (may be empty).

    Each signal is a dict with a ``strength``:
      * ``strong`` -- high precision; enough on its own to flag the URL.
      * ``weak``   -- suspicious but common in benign URLs too; reported only.
    """
    host = _host(url)
    if not host:
        return []
    registrable = registrable_domain(host)
    reg_label = registrable.split('.')[0]          # "paypal" of "paypal.com"
    tld = host.rsplit('.', 1)[-1]
    signals = []

    # Break the host into word tokens (labels split on '-') and add a
    # look-alike-folded copy of each, so "secure-paypa1" yields {secure,
    # paypa1, paypal}. Token matching avoids substrings like "ups" inside
    # "groups" triggering a false brand hit.
    tokens = set()
    for label in host.split('.'):
        for token in label.split('-'):
            tokens.add(token)
            tokens.add(_deconfuse(token))

    # 1. Punycode / IDN: the single clearest homograph marker.
    if 'xn--' in host:
        signals.append({'code': 'punycode', 'strength': 'strong',
                        'title': 'Punycode hostname',
                        'text': 'The host uses xn-- encoding, a common way to disguise look-alike letters.'})

    # 2. Raw non-ASCII letters in the host (Cyrillic/Greek look-alikes).
    elif any(ord(c) > 127 for c in host):
        signals.append({'code': 'non_ascii_host', 'strength': 'strong',
                        'title': 'Non-standard characters in host',
                        'text': 'The host mixes in non-English letters that can imitate a trusted name.'})

    for brand, legit_domain in BRANDS.items():
        if registrable == legit_domain:
            continue  # Genuinely this brand's own domain -> never flag it.

        # 3. Typosquat: the registrable label is zero or one edit away from the
        #    brand after folding look-alikes, but is not the brand itself.
        #    paypa1.com, micros0ft.com, amaz0n.co.uk. Length >= 5 only, so
        #    short brands (ups, dhl) do not match random labels by distance.
        folded_label = _deconfuse(reg_label)
        if (len(brand) >= 5 and reg_label != brand
                and _levenshtein(folded_label, brand) <= 1
                and abs(len(folded_label) - len(brand)) <= 1):
            signals.append({'code': 'typosquat', 'strength': 'strong',
                            'title': f'Look-alike of "{brand}"',
                            'text': f'The domain "{reg_label}" is within one character of {legit_domain}.'})
            break

        # 4. Brand name present as a token, but NOT as the registrable domain.
        #    The real owner is someone else: paypal.secure-login.com,
        #    secure-paypal.net, micros0ft-support.xyz.
        if brand in tokens:
            signals.append({'code': 'brand_misplaced', 'strength': 'strong',
                            'title': f'"{brand}" outside its real domain',
                            'text': f'The name "{brand}" appears, but the registered domain is "{registrable}", not {legit_domain}.'})
            break

    # 5. Abused TLD -- weak: plenty of honest sites use .xyz, so report only.
    if tld in ABUSED_TLDS:
        signals.append({'code': 'abused_tld', 'strength': 'weak',
                        'title': f'.{tld} domain',
                        'text': f'The .{tld} suffix is cheap and heavily abused, but also used legitimately.'})

    # 6. Deep subdomain nesting -- weak: hides the real domain far to the right.
    if host.count('.') >= 4:
        signals.append({'code': 'deep_subdomains', 'strength': 'weak',
                        'title': 'Many subdomains',
                        'text': 'Several subdomains push the real domain out of easy view.'})

    return signals


def flags_as_phishing(url):
    """The defence's verdict: does any STRONG impersonation signal fire?

    Deliberately strict (strong signals only) so the layer keeps a low
    false-positive rate on benign URLs -- that cost is measured in evaluate.py.
    """
    return any(s['strength'] == 'strong' for s in impersonation_signals(url))


def brand_visible(url):
    """Victim's-eye view: can a person still read a brand in the host?

    This is intentionally looser than ``flags_as_phishing`` -- it catches the
    brand even when it is glued into one label (``paypallogin.com``). It is NOT
    the shipped defence; evaluate.py uses it two ways:
      * as the attacker's constraint (an impersonation campaign must keep the
        brand visible, so evasions that keep this true are the realistic ones),
      * as a stricter "flag any visible brand" defence whose extra false-positive
        cost we measure to justify shipping the token-based version instead.
    """
    host = _host(url)
    if not host:
        return False
    if 'xn--' in host or any(ord(c) > 127 for c in host):
        return True
    folded = _deconfuse(host)
    reg = registrable_domain(host)
    return any(brand in folded for brand, legit in BRANDS.items() if reg != legit)


if __name__ == '__main__':
    import sys
    for arg in sys.argv[1:]:
        verdict = 'FLAGGED' if flags_as_phishing(arg) else 'clean'
        print(f'{verdict:8} {arg}')
        for signal in impersonation_signals(arg):
            print(f'         - [{signal["strength"]}] {signal["title"]}')

"""A controlled test set of brand-impersonation URLs and matched benign URLs.

Why generate these
------------------
The real dataset is dominated by *generic* phishing (compromised hosts, random
domains). It contains very few clean brand-impersonation URLs, so it cannot show
how a detector copes with the techniques that matter most for credential theft:
homographs, typosquats and brand-bearing domains. Evaluating a detector against
purpose-built inputs is standard in adversarial ML. These are URL *strings*
only -- nothing is hosted and no site is contacted.

Shaping the inputs to the model's blind spot
--------------------------------------------
We probed the trained model (see the report): it treats a *bare registrable
domain on a common TLD* as benign, but flags almost anything with an extra
subdomain or a path -- even legitimate ones like ``login.paypal.com`` or
``google.com/search``. So the realistic, evasive impersonation is a **bare
.com domain**. Every URL below is therefore a bare domain: that is exactly the
shape that slips past the structural model, which is what makes the defence's
job meaningful.

Each URL carries the pattern that produced it, so the evaluation can report, per
technique, what the defence catches and what it misses.
"""
from defense import BRANDS

# Confusable letter swaps used to build typosquats (leet / visual look-alikes).
_SWAP = {'a': '4', 'e': '3', 'o': '0', 'i': '1', 'l': '1', 's': '5'}
# Cyrillic look-alikes for homograph (punycode) hosts.
_CYRILLIC = {'a': 'а', 'e': 'е', 'o': 'о', 'c': 'с', 'p': 'р'}


def _typosquat(brand):
    for i, ch in enumerate(brand):
        if ch in _SWAP:
            return brand[:i] + _SWAP[ch] + brand[i + 1:]
    return brand + brand[-1]          # fallback: double the last letter


def _punycode(brand):
    swapped = ''.join(_CYRILLIC.get(c, c) for c in brand)
    if swapped == brand:
        return None
    try:
        return (swapped + '.com').encode('idna').decode('ascii')
    except (UnicodeError, ValueError):
        return None


def impersonation_urls():
    """Return [(url, brand, pattern), ...] -- all bare .com (or punycode) hosts.

    Patterns, each a real-world registration style:
      * hyphen        brand-account.com     (brand as a separate token)
      * concatenation brandlogin.com        (brand glued into one label)
      * typosquat     p4ypal.com            (one confusable character)
      * punycode      xn--...com            (IDN homograph)

    We deliberately omit subdomain/path styles: the structural model already
    over-flags those (it flags login.paypal.com too), so they would not test the
    defence. The report states this.
    """
    rows = []
    for brand in BRANDS:
        rows.append((f'https://{brand}-account.com', brand, 'hyphen'))
        rows.append((f'https://{brand}login.com', brand, 'concatenation'))
        rows.append((f'https://{_typosquat(brand)}.com', brand, 'typosquat'))
        puny = _punycode(brand)
        if puny:
            rows.append((f'https://{puny}', brand, 'punycode'))
    return rows


def benign_urls():
    """Bare legit domains, including hard ones that merely CONTAIN a brand
    substring. A good defence must leave all of these alone."""
    rows = [f'https://{domain}' for domain in BRANDS.values()]      # the real domains
    rows += [
        'https://pineapple.com',          # contains "apple"
        'https://snapple.com',            # contains "apple"
        'https://grapple-robotics.com',   # contains "apple"
        'https://applied-materials.com',  # starts "appl..."
        'https://amazonaws.com',          # real AWS
        'https://microsoftonline.com',    # real Microsoft domain
        'https://googleblog.com',         # contains "google"
        'https://github.com',
        'https://wikipedia.org',
        'https://nytimes.com',
        'https://ycombinator.com',
        'https://cloudflare.com',
    ]
    return rows


if __name__ == '__main__':
    for url, brand, pattern in impersonation_urls()[:16]:
        print(f'{pattern:14} {url}')

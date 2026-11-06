"""Evasion attack: reshape a phishing URL so the structural model stops
recognising it, without changing what the URL *is*.

Threat model
------------
The attacker knows (or guesses) that the detector reads only cheap structural
features -- length, dot count, hyphens, digit ratio, common TLD, path depth,
raw-IP host. That is a realistic assumption: these are the features in
``../features.py`` and they are the standard lexical features in published
URL-phishing classifiers, so an attacker does not need to see our exact model.

Each transformation below is a *real move an attacker can make* while still
running the same phishing campaign:

  * register the look-alike on a plain ``.com`` instead of a flagged TLD,
  * register a no-hyphen variant of the name,
  * drop the ``user@host`` credential trick,
  * use a short landing path behind a redirect instead of a long one,
  * strip digits from the path,
  * put the real domain up front instead of raw IP or deep subdomains.

None of these change the destination's purpose; they only make the *string*
look ordinary. That is why the attack is "label preserving": a phishing URL
stays a phishing URL. We then recompute features and ask the model again.
"""
import ipaddress
import random
from urllib.parse import urlsplit, urlunsplit


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _rebuild(parsed, netloc=None, path=None, query=None):
    return urlunsplit((parsed.scheme or 'http',
                       netloc if netloc is not None else parsed.netloc,
                       path if path is not None else parsed.path,
                       query if query is not None else parsed.query, ''))


def _split(url):
    text = str(url).strip()
    return urlsplit(text if '://' in text else '//' + text)


def drop_query(url):
    """Remove the query string (query_length -> 0, url_length down)."""
    return _rebuild(_split(url), query='')


def shorten_path(url):
    """Keep only the first path segment (path_depth and url_length down)."""
    parsed = _split(url)
    first = next((part for part in parsed.path.split('/') if part), '')
    return _rebuild(parsed, path=('/' + first) if first else '')


def remove_at(url):
    """Drop a user@host credential prefix (at_count -> 0)."""
    parsed = _split(url)
    netloc = parsed.netloc.rsplit('@', 1)[-1]
    return _rebuild(parsed, netloc=netloc)


def remove_hyphens(url):
    """Register a no-hyphen variant of the host (hyphen/host_hyphen down)."""
    parsed = _split(url)
    host = (parsed.hostname or '').replace('-', '')
    port = f':{parsed.port}' if parsed.port else ''
    return _rebuild(parsed, netloc=host + port)


def reduce_digits(url):
    """Strip digits from the path (digit_ratio down)."""
    parsed = _split(url)
    path = ''.join(c for c in parsed.path if not c.isdigit())
    return _rebuild(parsed, path=path)


def use_common_tld(url):
    """Move the name onto a .com, the most trusted TLD (common_tld -> 1)."""
    parsed = _split(url)
    host = parsed.hostname or ''
    if _is_ip(host):                       # Leave raw-IP hosts to ip_to_domain.
        return url
    if '.' in host:
        host = host.rsplit('.', 1)[0] + '.com'
    port = f':{parsed.port}' if parsed.port else ''
    return _rebuild(parsed, netloc=host + port)


def collapse_subdomains(url):
    """Keep only the last two host labels (dot_count down).

    Note: this also removes a brand placed in a subdomain, which is exactly the
    attacker's trade-off -- hiding from the model can also drop the human bait.
    """
    parsed = _split(url)
    host = parsed.hostname or ''
    if _is_ip(host):                       # Never chop an IP address into pieces.
        return url
    labels = host.split('.')
    if len(labels) > 2:
        host = '.'.join(labels[-2:])
    port = f':{parsed.port}' if parsed.port else ''
    return _rebuild(parsed, netloc=host + port)


def ip_to_domain(url):
    """Replace a raw-IP host with a short domain (has_ip -> 0)."""
    parsed = _split(url)
    host = parsed.hostname or ''
    if not _is_ip(host):
        return url
    port = f':{parsed.port}' if parsed.port else ''
    return _rebuild(parsed, netloc='secure-portal.com' + port)


# All moves, cheapest first. The attacker picks a subset (their "effort budget").
TRANSFORMS = [remove_at, drop_query, use_common_tld, remove_hyphens,
              reduce_digits, shorten_path, collapse_subdomains, ip_to_domain]


def evade(url, transforms=None):
    """Apply a sequence of transformations in order and return the new URL."""
    result = url
    for transform in (transforms if transforms is not None else TRANSFORMS):
        result = transform(result)
    return result


def random_attack(url, rng, budget):
    """Apply ``budget`` randomly chosen transformations (the attacker's effort).

    Using a budget lets us measure evasion as a *distribution*: a weak attacker
    changes one thing, a determined one changes many.
    """
    chosen = rng.sample(TRANSFORMS, min(budget, len(TRANSFORMS)))
    # Apply in the canonical order so results do not depend on draw order.
    ordered = [t for t in TRANSFORMS if t in chosen]
    return evade(url, ordered)


if __name__ == '__main__':
    rng = random.Random(0)
    samples = ['http://secure-paypal.com.account-verify.tk/login/confirm?id=8891',
               'http://192.168.10.24/wp/paypal/signin.php?session=1920',
               'http://free-netflix-gift-2024.xyz/claim/now/verify']
    for url in samples:
        print('original :', url)
        print('full evade:', evade(url))
        print()

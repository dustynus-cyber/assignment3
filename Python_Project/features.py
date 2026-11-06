"""Turn a URL into simple numbers. We do not open the website."""
import ipaddress
from urllib.parse import urlsplit
import pandas as pd


def get_host(url):
    # Some dataset URLs do not include http or https.
    text = str(url).strip()
    parsed = urlsplit(text if '://' in text else '//' + text)
    return parsed.hostname or ''


def normalize_url(url):
    text = str(url).strip()
    parsed = urlsplit(text if '://' in text else '//' + text)
    host = (parsed.hostname or '').removeprefix('www.')
    # Keep credentials and ports so different destinations are not merged.
    credentials = parsed.netloc.rsplit('@', 1)[0] + '@' if '@' in parsed.netloc else ''
    port = ':' + str(parsed.port) if parsed.port else ''
    key = credentials + host + port + parsed.path.rstrip('/')
    if parsed.query:
        key += '?' + parsed.query
    if parsed.fragment:
        key += '#' + parsed.fragment
    return key


def get_features(url):
    text = str(url).strip()
    parsed = urlsplit(text if '://' in text else '//' + text)
    host = parsed.hostname or ''
    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0
    # Ignore scheme and a leading www so pasted formats have the same features.
    host = host.removeprefix('www.')
    text = normalize_url(url)
    if parsed.query:
        text += '?' + parsed.query
    if parsed.fragment:
        text += '#' + parsed.fragment
    digits = sum(c.isdigit() for c in text)
    return {
        'url_length': len(text),
        'host_length': len(host),
        'dot_count': host.count('.'),
        'hyphen_count': text.count('-'),
        'at_count': str(url).count('@'),
        'digit_ratio': digits / max(len(text), 1),
        'path_depth': len([part for part in parsed.path.split('/') if part]),
        'query_length': len(parsed.query),
        'has_ip': has_ip,
        'common_tld': int(host.rsplit('.', 1)[-1] in {'com', 'org', 'net', 'edu', 'gov'}),
        'host_hyphens': host.count('-'),
    }


def make_features(urls):
    return pd.DataFrame([get_features(url) for url in urls])

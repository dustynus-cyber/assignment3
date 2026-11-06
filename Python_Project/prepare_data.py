"""Combine two real URL sources in the same simple format."""
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile
import hashlib
import json
import requests
import pandas as pd
from features import get_host, make_features, normalize_url

ROOT = Path(__file__).resolve().parent
SOURCES = {
    'kaggle': 'https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset',
    'uci': 'https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip',
}


def read_archive(source, archive=None):
    if archive:
        content = Path(archive).read_bytes()
    else:
        response = requests.get(SOURCES[source], timeout=120)
        response.raise_for_status()
        content = response.content
    filename = 'malicious_phish.csv' if source == 'kaggle' else 'PhiUSIIL_Phishing_URL_Dataset.csv'
    columns = ['url', 'type'] if source == 'kaggle' else ['URL', 'label']
    with ZipFile(BytesIO(content)) as zipped:
        data = pd.read_csv(zipped.open(filename), usecols=columns)
    original_rows = len(data)
    if source == 'kaggle':
        data = data[data['type'].isin(['benign', 'phishing'])].copy()
        data['label'] = data['type'].map({'benign': 0, 'phishing': 1})
        data = data[['url', 'label']]
    else:
        data = data.rename(columns={'URL': 'url'})
        # UCI uses 1 for legitimate. Our project uses 1 for phishing.
        data['label'] = 1 - data['label']
    data['source'] = source
    return data, {'url': SOURCES[source], 'original_rows': original_rows,
                  'archive_sha256': hashlib.sha256(content).hexdigest()}


def valid_url(url):
    try:
        return bool(get_host(url)) and not any(c.isspace() for c in url)
    except ValueError:
        return False


def prepare_data(archive=None, uci_archive=None):
    base, base_info = read_archive('kaggle', archive)
    extra, extra_info = read_archive('uci', uci_archive)
    data = pd.concat([base, extra], ignore_index=True).dropna()
    data['url'] = data['url'].str.strip()
    data = data[data['url'].map(valid_url)].copy()
    # Equivalent formats must not appear on both sides of the split.
    data['url_key'] = data['url'].map(normalize_url)
    conflicts = data.groupby('url_key')['label'].nunique()
    bad_keys = conflicts[conflicts > 1].index
    data = data[~data['url_key'].isin(bad_keys)].drop_duplicates('url_key')
    available = data.groupby(['source', 'label']).size().to_dict()
    samples = []
    for (source, label), group in data.groupby(['source', 'label']):
        count = 10000 if source == 'kaggle' else 5000
        samples.append(group.sample(n=min(count, len(group)), random_state=42))
    selected = pd.concat(samples).sample(frac=1, random_state=42).reset_index(drop=True)
    (ROOT / 'data').mkdir(exist_ok=True)
    selected[['url', 'label']].to_csv(ROOT / 'data/urls.csv', index=False)
    selected[['url', 'label', 'source']].to_csv(ROOT / 'data/provenance.csv', index=False)
    features = make_features(selected['url'])
    features['label'] = selected['label']
    features.to_csv(ROOT / 'data/features.csv', index=False)
    info = {'sources': {'kaggle': base_info, 'uci': extra_info},
            'prepared_date': '2026-10-10', 'conflicting_normalized_urls_removed': len(bad_keys),
            'clean_counts_before_sampling': {f'{s}_{l}': int(v) for (s,l),v in available.items()},
            'selected_counts': {f'{s}_{l}': int(v) for (s,l),v in selected.groupby(['source','label']).size().items()},
            'seed': 42, 'label_mapping': {'benign': 0, 'phishing': 1},
            'normalization': 'Ignore http/https, leading www and trailing path slashes. Preserve path case and query.'}
    (ROOT / 'data/source.json').write_text(json.dumps(info, indent=2))
    print('Saved', len(selected), 'real URLs from two sources.')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', help='Optional local Kaggle zip file')
    parser.add_argument('--uci-archive', help='Optional local UCI zip file')
    args = parser.parse_args()
    prepare_data(args.archive, args.uci_archive)

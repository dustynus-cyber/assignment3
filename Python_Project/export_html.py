"""Update the trained tree inside the standalone HTML demo."""
from pathlib import Path
import json
import re
import argparse
import joblib

ROOT = Path(__file__).resolve().parent
SUPPORTED_FEATURES = ['url_length', 'host_length', 'dot_count', 'hyphen_count', 'at_count',
                      'digit_ratio', 'path_depth', 'query_length', 'has_ip', 'common_tld', 'host_hyphens']


def export_html(path):
    saved = joblib.load(ROOT / 'models/classifier.joblib')
    if saved['features'] != SUPPORTED_FEATURES:
        raise ValueError('The features changed. Update the browser feature function first.')
    tree = saved['model'].tree_
    model = {'features': saved['features'], 'left': tree.children_left.tolist(),
             'right': tree.children_right.tolist(), 'feature': tree.feature.tolist(),
             'threshold': tree.threshold.tolist(),
             'phishing': (tree.value[:, 0, 1] / tree.value[:, 0, :].sum(axis=1)).tolist()}
    html = path.read_text()
    replacement = 'const TREE=' + json.dumps(model, separators=(',', ':')) + ';'
    html, count = re.subn(r'const TREE=\{[^\n]+\};', lambda match: replacement, html, count=1)
    if count != 1:
        raise ValueError('The HTML model block was not found.')
    path.write_text(html)
    print('Updated the model in', path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--html', type=Path, default=ROOT.parent / 'Link_Check.html')
    args = parser.parse_args()
    export_html(args.html)

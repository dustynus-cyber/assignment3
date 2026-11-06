"""Use the saved classifier with one URL."""
from pathlib import Path
import argparse
import json
import joblib
from features import make_features, get_host

ROOT = Path(__file__).resolve().parent


def predict_url(url):
    if not url.strip() or any(c.isspace() for c in url) or not get_host(url):
        raise ValueError('Please enter a URL with a hostname and no spaces.')
    saved = joblib.load(ROOT / 'models/classifier.joblib')
    features = make_features([url])[saved['features']]
    model = saved['model']
    prediction = int(model.predict(features)[0])
    probability = float(model.predict_proba(features)[0, list(model.classes_).index(1)])
    # This score is a model estimate, not proof that a website is safe.
    return {'model_version': 'url-tree-v2',
            'prediction': 'phishing' if prediction else 'benign',
            'phishing_probability': round(probability, 4),
            'trust_score': round(100 * (1 - probability), 1),
            'note': 'This is an uncalibrated model score. The website was not visited.',
            'features': features.iloc[0].to_dict()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url')
    args = parser.parse_args()
    try:
        print(json.dumps(predict_url(args.url), indent=2))
    except ValueError as error:
        parser.error(str(error))

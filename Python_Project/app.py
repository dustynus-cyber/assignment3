"""A small Flask website for our trained URL model."""
from pathlib import Path
from urllib.parse import urlsplit
from datetime import datetime, timezone
import json
import sqlite3
import uuid
from flask import Flask, jsonify, request, render_template, session, Response
from predict import predict_url

ROOT = Path(__file__).resolve().parent
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16384
# Keep the browser ID stable after restarting the local app.
secret_file = ROOT / '.session_secret'
if not secret_file.exists():
    secret_file.write_text(uuid.uuid4().hex + uuid.uuid4().hex)
app.secret_key = secret_file.read_text()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
DATABASE = ROOT / 'history.sqlite'
with sqlite3.connect(DATABASE) as db:
    db.execute('CREATE TABLE IF NOT EXISTS checks (id TEXT PRIMARY KEY, browser TEXT, result TEXT)')


def browser_id():
    if 'browser_id' not in session:
        session['browser_id'] = uuid.uuid4().hex
    return session['browser_id']


def validate_url(value):
    if not isinstance(value, str):
        raise ValueError('Please paste a website address.')
    url = value.strip()
    if not url or len(url) > 4096 or any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError('Use a URL under 4,096 characters, with no spaces.')
    parsed = urlsplit(url if '://' in url else '//' + url)
    host = parsed.hostname
    if parsed.scheme and parsed.scheme.lower() not in ('http', 'https'):
        raise ValueError('Use an http or https website address.')
    if not host or ('.' not in host and ':' not in host):
        raise ValueError('Include a hostname, for example example.com.')
    # Accessing port also catches invalid port values.
    parsed.port
    return url


def explain(features):
    # These observations explain the URL, not the cause of the prediction.
    notes = []
    if features['has_ip']:
        notes.append({'title': 'An IP address is used', 'text': 'This address uses a number-based host instead of a domain name.'})
    if features['at_count']:
        notes.append({'title': 'An at sign is present', 'text': 'An @ sign can make the real destination harder to read.'})
    if features['url_length'] > 75:
        notes.append({'title': 'A long URL', 'text': 'This address has more than 75 characters. Check the hostname carefully.'})
    if features['hyphen_count'] > 2:
        notes.append({'title': 'Several hyphens', 'text': 'This URL contains more than two hyphens. This alone does not mean phishing.'})
    if features['digit_ratio'] > 0.2:
        notes.append({'title': 'Many digits', 'text': 'More than 20% of the characters are digits. Some normal links also use many digits.'})
    return notes


@app.get('/')
def index():
    browser_id()
    return render_template('index.html')


@app.post('/api/check')
def check():
    payload = request.get_json(silent=True)
    try:
        url = validate_url(payload.get('url') if isinstance(payload, dict) else None)
        result = predict_url(url)
    except ValueError as error:
        return jsonify({'error': str(error)}), 400
    score = result['trust_score']
    result.update({'id': uuid.uuid4().hex, 'url': url,
                   'checked_at': datetime.now(timezone.utc).isoformat(),
                   'risk': 'high' if score < 40 else 'caution' if score < 70 else 'low',
                   'observations': explain(result['features']), 'reported': False})
    with sqlite3.connect(DATABASE) as db:
        db.execute('INSERT INTO checks VALUES (?, ?, ?)', (result['id'], browser_id(), json.dumps(result)))
    return jsonify(result)


@app.get('/api/history')
def history():
    with sqlite3.connect(DATABASE) as db:
        rows = db.execute('SELECT result FROM checks WHERE browser = ? ORDER BY rowid DESC', (browser_id(),)).fetchall()
    return jsonify([json.loads(row[0]) for row in rows])


@app.post('/api/report/<check_id>')
def report(check_id):
    with sqlite3.connect(DATABASE) as db:
        row = db.execute('SELECT result FROM checks WHERE id = ? AND browser = ?', (check_id, browser_id())).fetchone()
        if not row:
            return jsonify({'error': 'This result was not found.'}), 404
        result = json.loads(row[0])
        result['reported'] = True
        db.execute('UPDATE checks SET result = ? WHERE id = ?', (json.dumps(result), check_id))
    return jsonify({'message': 'Saved for local review. No report was sent to another organisation.'})


@app.get('/api/export')
def export():
    # JSON preserves all features and the model output without spreadsheet formulas.
    response = history()
    return Response(response.get_data(), mimetype='application/json', headers={'Content-Disposition': 'attachment; filename="link-check-history.json"'})


@app.errorhandler(413)
def too_large(error):
    return jsonify({'error': 'This request is too large. Use a shorter URL.'}), 413


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5050, debug=False)

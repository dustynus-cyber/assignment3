import { useState } from 'react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts'
import './App.css'

function App() {
  const [url, setUrl] = useState('')
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')

  async function handleSubmit(event) {
    event.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)

    const submittedUrl = url.trim()

    try {
      let parsed

      try {
        parsed = new URL(submittedUrl)
      } catch {
        throw new Error(
          'Enter a valid URL beginning with https:// or http://.'
        )
      }

      if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Use an http:// or https:// address.')
      }

      if (/\s/.test(submittedUrl)) {
        throw new Error('The URL must not contain spaces.')
      }

      const response = await fetch('http://127.0.0.1:8000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: submittedUrl }),
        signal: AbortSignal.timeout(15000),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(
          data.error?.message || 'Unable to check this URL.'
        )
      }

      const entry = {
        ...data,
        id: crypto.randomUUID(),
        url: submittedUrl,
        checkedAt: new Date().toLocaleString(),
      }

      setResult(entry)
      setHistory((previous) => [entry, ...previous])
    } catch (err) {
      if (err.name === 'TimeoutError') {
        setError('The check took too long. Please try again.')
      } else if (err instanceof TypeError) {
        setError(
          'Cannot connect to the backend. Check that it is running.'
        )
      } else {
        setError(err.message || 'Unable to complete the check.')
      }
    } finally {
      setLoading(false)
    }
  }

  const modelScore = result
    ? (
        (result.prediction === 'phishing'
          ? result.phishing_probability
          : 1 - result.phishing_probability) * 100
      ).toFixed(1)
    : null

  const currentScores = result
    ? [
        {
          name: 'Current URL',
          Phishing: Number(
            (result.phishing_probability * 100).toFixed(1)
          ),
          Legitimate: Number(
            ((1 - result.phishing_probability) * 100).toFixed(1)
          ),
        },
      ]
    : []

  const phishingCount = history.filter(
    (entry) => entry.combined_prediction === 'phishing'
  ).length

  const sessionCounts = [
    {
      name: 'This session',
      'Flagged phishing': phishingCount,
      'No phishing flag': history.length - phishingCount,
    },
  ]

  const visibleHistory = history.filter(
    (entry) =>
      filter === 'all' || entry.combined_prediction === filter
  )

  function showHistoryResult(entry) {
    setResult(entry)
    setUrl(entry.url)
    setError('')
  }

  return (
    <>
      <header className="topbar">
        <a className="brand" href="#home">
          <span className="brand-mark" aria-hidden="true"></span>
          Link Check
        </a>

        <nav aria-label="Main navigation">
          <a href="#home">Check a link</a>
          <a href="#history">History</a>
          <a href="#how">How it works</a>
        </nav>
      </header>

      <main>
        <section id="home" className="view">
          <div className="hero">
            <h1>
              Not sure about a link?
              <span>Check it before you click.</span>
            </h1>
            <p className="lede">
              Paste it below. We read the address only—we never open
              the site.
            </p>
          </div>

          <form className="checker" onSubmit={handleSubmit}>
            <label htmlFor="url-input">Website address</label>

            <div className="field">
              <input
                id="url-input"
                type="url"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com/login"
                maxLength={4096}
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                aria-describedby="url-help form-error"
                disabled={loading}
                required
              />

              <button
                type="submit"
                className="btn-primary"
                disabled={loading}
              >
                {loading ? 'Checking…' : 'Check link'}
              </button>
            </div>

            <p id="url-help" className="helper">
              Include https:// or http:// at the beginning.
            </p>
            <p id="form-error" className="error" role="alert">
              {error}
            </p>
          </form>

          <div aria-live="polite" aria-atomic="true">
            {loading && <p role="status">Analysing the URL…</p>}

            {result && (
              <section className="block">
                <h2>
                  {result.combined_prediction === 'phishing'
                    ? 'Flagged as possible phishing'
                    : 'No phishing flag detected'}
                </h2>

                <p className="checked-url">{result.url}</p>

                <p>
                  The combined decision flags a URL when the model
                  predicts phishing or a strong impersonation rule
                  matches.
                </p>

                <p>
                  <strong>
                    Model prediction:{' '}
                    {result.prediction === 'phishing'
                      ? 'Phishing'
                      : 'Legitimate'}
                  </strong>
                </p>

                <p>
                  Model score for that prediction: {modelScore}%
                </p>

                <p>{result.note}</p>

                <h3>Security warnings</h3>

                {result.security.signals.length > 0 ? (
                  <ul>
                    {result.security.signals.map((signal) => (
                      <li key={signal.code}>
                        <strong>{signal.title}</strong>
                        {' — '}
                        {signal.strength === 'strong'
                          ? 'Strong rule match'
                          : 'Weak rule match'}
                        <p>{signal.text}</p>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>No impersonation rules matched this address.</p>
                )}

                <p>
                  Strong rule matches affect the combined decision.
                  Weak matches are reported for information only.
                </p>

                <p className="helper">{result.security.note}</p>
              </section>
            )}
          </div>

          {result && (
            <section className="block">
              <h2>Current URL: model scores</h2>
              <p>
                Compare the model’s two class scores. These are
                uncalibrated estimates, not verified safety ratings.
                The security rules do not change these scores.
              </p>

              <div style={{ width: '100%', height: 280 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={currentScores} accessibilityLayer>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis
                      domain={[0, 100]}
                      unit="%"
                      width={55}
                    />
                    <Tooltip formatter={(value) => `${value}%`} />
                    <Legend />
                    <Bar dataKey="Phishing" fill="#b42318" />
                    <Bar dataKey="Legitimate" fill="#196b45" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <p className="helper">
                Phishing: {currentScores[0].Phishing}% · Legitimate:{' '}
                {currentScores[0].Legitimate}%
              </p>

              <details>
                <summary>View extracted URL features</summary>
                <dl>
                  {Object.entries(result.features).map(
                    ([name, value]) => (
                      <div key={name}>
                        <dt>{name.replaceAll('_', ' ')}</dt>
                        <dd>{Number(value.toFixed(4))}</dd>
                      </div>
                    )
                  )}
                </dl>
              </details>
            </section>
          )}

          <section id="history" className="block">
            <h2>Session summary: combined decisions</h2>
            <p>
              Counts from the model and security rules combined.
              Repeated checks count separately. No phishing flag
              does not mean a website is safe.
            </p>

            {history.length === 0 ? (
              <p>Check a URL to start your session history.</p>
            ) : (
              <>
                <div style={{ width: '100%', height: 280 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={sessionCounts} accessibilityLayer>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" />
                      <YAxis
                        allowDecimals={false}
                        width={45}
                        label={{
                          value: 'URL checks',
                          angle: -90,
                          position: 'insideLeft',
                        }}
                      />
                      <Tooltip />
                      <Legend />
                      <Bar
                        dataKey="Flagged phishing"
                        fill="#b42318"
                      />
                      <Bar
                        dataKey="No phishing flag"
                        fill="#196b45"
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <p>
                  Total: {history.length} · Flagged phishing:{' '}
                  {phishingCount} · No phishing flag:{' '}
                  {history.length - phishingCount}
                </p>

                <label htmlFor="history-filter">
                  Filter combined decisions
                </label>
                <select
                  id="history-filter"
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                >
                  <option value="all">All decisions</option>
                  <option value="phishing">Flagged phishing</option>
                  <option value="benign">No phishing flag</option>
                </select>

                {visibleHistory.length === 0 && (
                  <p>No decisions match this filter.</p>
                )}

                <ul className="history-list">
                  {visibleHistory.map((entry) => (
                    <li key={entry.id}>
                      <button
                        type="button"
                        onClick={() => showHistoryResult(entry)}
                        disabled={loading}
                      >
                        <span>{entry.url}</span>
                        <small>
                          {entry.combined_prediction === 'phishing'
                            ? 'Flagged phishing'
                            : 'No phishing flag'}
                          {' · '}
                          {entry.checkedAt}
                        </small>
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            )}

            <p className="helper">
              History stays in this page’s memory and clears when
              you refresh or close it.
            </p>
          </section>

          <section id="how" className="block">
            <h2>How it works</h2>
            <p>
              Enter a URL. FastAPI checks the input, extracts its
              features, and passes them to our trained model.
              Separate rules check for warning signs such as
              look-alike brand names.
            </p>
            <p>
              The combined decision flags phishing when either
              the model predicts phishing or a strong rule matches.
              The charts show model scores and session decisions.
            </p>
            <p>
              We analyse URL text without visiting the website.
              Both the model and rules can make mistakes.
              No result guarantees safety.
            </p>
          </section>
        </section>
      </main>

      <footer>
        <span>COS30049 · Link Check</span>
        <a href="#how">Help</a>
      </footer>
    </>
  )
}

export default App
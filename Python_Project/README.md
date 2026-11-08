# Link Check — COS30049 Assignment 3

## Overview

Link Check analyses website addresses using our Assignment 2 model
and separate brand-impersonation rules. It reads URL text only and
does not open the submitted website.

The application uses a React frontend and a FastAPI backend.
Predictions and scores can be wrong and do not guarantee safety.

## Requirements

- Python 3.12
- Node.js and npm
- Python packages listed in Python_Project/requirements.txt
- Frontend packages recorded in frontend/package-lock.json

Development was tested using Python 3.12.15, Node.js 26.13.0
and npm 11.20.0.

## Start the backend

Open a terminal in the main project folder:

```bash
cd Python_Project
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Backend: http://127.0.0.1:8000

API documentation: http://127.0.0.1:8000/docs

The supplied model must remain at:

```text
Python_Project/models/classifier.joblib
```

Only load model files from a trusted source. Joblib model files
can execute code when loaded.

## Start the frontend

Open another terminal in the main project folder:

```bash
cd frontend
npm ci
npm run dev
```

Open http://localhost:5173 and leave both terminals running.

The frontend calls http://127.0.0.1:8000/predict.
CORS allows the frontend origin http://localhost:5173.

## Build the frontend

Inside frontend:

```bash
npm run build
```

The build produces the dist folder. The observed bundle-size
warning does not prevent the build from completing.

## Application workflow

1. The user enters an HTTP or HTTPS URL.
2. React sends a JSON POST request to /predict.
3. FastAPI validates the input.
4. The model analyses extracted URL features.
5. Separate rules check for impersonation signals.
6. FastAPI returns the model result, warnings and combined decision.

The model is loaded when the prediction module is imported,
rather than for every request.

The combined decision flags phishing if the model predicts
phishing or any strong security rule matches. Weak rule matches
are displayed for information only.

Model scores remain separate from the combined decision.
They are uncalibrated estimates.

## API

- GET /health: returns the API availability status.
- POST /predict: analyses a JSON body such as
  {"url": "https://example.com"}.

Successful predictions return HTTP 200.
Invalid input returns HTTP 422.
Bodies exceeding 32 KB return HTTP 413.
Processing failures return HTTP 500 with a generic message.

Errors use this structure:

```json
{
  "error": {
    "code": "invalid_input",
    "message": "Description of the problem."
  }
}
```

## Visualisations

The current-URL chart compares the model's phishing and legitimate
scores.

The session chart counts combined decisions across successful
checks. Users can filter history and reopen a previous result.
Repeated checks count separately. History clears on refresh.

## Threat model and limitations

Submitted URLs are untrusted input. The application limits URL
length to 4096 characters, validates input on the backend, and
limits request bodies to 32 KB. These controls reduce the impact
of malformed and oversized requests.

React displays submitted addresses as text rather than inserting
user-supplied HTML. API errors avoid returning stack traces.
CORS restricts browser access to the configured frontend origin;
it is not authentication and does not block direct API clients.

The application does not fetch submitted websites, so submitted
URLs cannot directly make it contact internal network services.
There is no database or file-upload endpoint in the React/FastAPI
workflow.

The body-size limit does not provide complete denial-of-service
protection. Rate limiting, authentication and a production hosting
configuration have not been implemented.

Impersonation rules can produce false alarms and miss threats.
They use a limited brand list and an approximate domain-suffix
list. Internationalised domains can be legitimate.

## Attack and defence evaluation

From Python_Project:

```bash
python security/evaluate.py
```

Results and figures are written to security/results.

The real-data test used 3000 phishing and 3000 benign URLs.
Model phishing recall decreased from 73.03% to 53.83% after all
simulated URL transformations. The combined defence also achieved
53.83% recall after those transformations.

On the real benign examples, the false-positive rate increased
from 32.03% to 32.57% with the defence.

On the controlled suite of 95 impersonation examples, recall
increased from 26.32% to 74.74%. The token defence flagged none
of the 36 controlled benign examples, but missed all 24
concatenated-brand examples.

Measured defence runtime was approximately 0.156 milliseconds
per URL on the test machine.

These are results for the supplied tests, not guarantees of
performance on other data. URL transformations are offline
simulations; changing a domain or path does not demonstrate that
the modified URL still hosts the original phishing content.

## Checks completed

- Frontend production build completed.
- Python dependency compatibility check passed.
- Oversized request returned HTTP 413.
- The API returned an impersonation warning for paypa1.com.
- Security evaluation completed and generated result files.

### Remaining ZAP findings

The updated documentation scan reported four alert types:

- Missing Content Security Policy on /docs: unresolved.
- Missing integrity attributes on external Swagger UI resources:
  unresolved; these resources introduce a supply-chain risk.
- External JavaScript inclusion: /docs loads Swagger UI from a CDN.
  This dependency remains a risk.
- Modern Web Application: informational.

The missing anti-clickjacking and content-type headers were fixed
and were absent from the new scan.

Remaining risks are accepted for this local demonstration.
Before public deployment, documentation resources should be
hardened or the documentation routes disabled.

The /predict active scan sent 309 requests and reported no new
active-scan alerts. This does not prove the application is secure.
## Selected security defences

1. Misconfiguration and vulnerable dependencies:
   dependency audits, security headers, generic error messages,
   and ZAP scans. Remaining findings are documented above.

2. Brand-impersonation detection (proposed custom innovation):
   backend rules supplement the model by checking for strong
   impersonation signals. The evaluation records detection,
   false positives, runtime and known bypasses.
   The innovation level is subject to tutor assessment.
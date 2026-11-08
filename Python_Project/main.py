from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from predict import predict_url
from security.defense import impersonation_signals


def error_response(status, code, message, headers=None):
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
            }
        },
        headers=headers,
    )


class RequestSizeLimit:
    """Limit actual body bytes, even without Content-Length."""

    def __init__(self, app, max_bytes=32768):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        chunks = []
        total = 0

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            chunk = message.get("body", b"")
            total += len(chunk)

            if total > self.max_bytes:
                response = error_response(
                    413,
                    "request_too_large",
                    "Request body must not exceed 32 KB.",
                )
                await response(scope, receive, send)
                return

            chunks.append(chunk)

            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        delivered = False

        async def limited_receive():
            nonlocal delivered

            if not delivered:
                delivered = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }

            return await receive()

        await self.app(scope, limited_receive, send)


app = FastAPI(
    title="Link Check API",
    description=(
        "Analyses URL text using a trained model and separate "
        "impersonation rules. It does not visit websites. "
        "Model scores are uncalibrated and cannot guarantee safety."
    ),
    version="1.1.0",
    debug=False,
)

app.add_middleware(RequestSizeLimit, max_bytes=32768)

# CORS also applies to responses from the request-size limit.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request,
    exc: RequestValidationError,
):
    return error_response(
        422,
        "invalid_input",
        "Provide a URL as text, between 1 and 4096 characters.",
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(
    request: Request,
    exc: StarletteHTTPException,
):
    return error_response(
        exc.status_code,
        f"http_{exc.status_code}",
        str(exc.detail),
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    return error_response(
        500,
        "internal_error",
        "Unable to process the request. Please try again.",
    )


class URLRequest(BaseModel):
    url: str = Field(
        min_length=1,
        max_length=4096,
        description="The website address to analyse.",
        examples=["https://example.com"],
    )


class SecuritySignal(BaseModel):
    code: str
    strength: Literal["strong", "weak"]
    title: str
    text: str


class SecurityResult(BaseModel):
    flagged: bool = Field(
        description="Whether any strong impersonation rule matched."
    )
    signals: list[SecuritySignal]
    note: str


class PredictionResponse(BaseModel):
    model_version: str
    prediction: Literal["phishing", "benign"]

    phishing_probability: float = Field(
        ge=0,
        le=1,
        description="Uncalibrated model estimate for the phishing class.",
    )

    trust_score: float = Field(
        ge=0,
        le=100,
        description="100 multiplied by one minus the phishing score.",
    )

    note: str
    features: dict[str, float]
    security: SecurityResult

    combined_prediction: Literal["phishing", "benign"] = Field(
        description=(
            "Phishing if the model predicts phishing or a strong "
            "impersonation rule matches. Otherwise benign. "
            "No probability is assigned to this combined decision."
        )
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "model_version": "url-tree-v2",
                    "prediction": "benign",
                    "phishing_probability": 0.2969,
                    "trust_score": 70.3,
                    "note": (
                        "This is an uncalibrated model score. "
                        "The website was not visited."
                    ),
                    "features": {
                        "url_length": 11,
                        "host_length": 11,
                        "dot_count": 1,
                        "hyphen_count": 0,
                        "at_count": 0,
                        "digit_ratio": 0,
                        "path_depth": 0,
                        "query_length": 0,
                        "has_ip": 0,
                        "common_tld": 1,
                        "host_hyphens": 0,
                    },
                    "security": {
                        "flagged": False,
                        "signals": [],
                        "note": (
                            "Rule-based warnings can produce false alarms "
                            "or miss threats. No warning does not mean safe. "
                            "Internationalised domains can be legitimate."
                        ),
                    },
                    "combined_prediction": "benign",
                }
            ]
        }
    }


class HealthResponse(BaseModel):
    status: str = Field(examples=["ok"])


class ErrorDetails(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetails


def validate_url(value):
    url = value.strip()

    if not url or len(url) > 4096:
        raise ValueError("Invalid URL length.")

    if any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError("Spaces and control characters are not allowed.")

    parsed = urlsplit(url if "://" in url else "//" + url)
    host = parsed.hostname

    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Unsupported scheme.")

    if not host or ("." not in host and ":" not in host):
        raise ValueError("A hostname is required.")

    # Accessing this property rejects invalid port values.
    parsed.port

    return url


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Check API availability",
    description=(
        "Returns the API status. This does not run a prediction "
        "or contact a destination website."
    ),
)
def health():
    return {"status": "ok"}


@app.post(
    "/predict",
    response_model=PredictionResponse,
    summary="Analyse one URL",
    description=(
        "Validates a URL and returns the original model prediction "
        "and scores, separate impersonation warnings, and a combined "
        "decision. The combined decision flags phishing when either "
        "the model predicts phishing or a strong rule matches. "
        "Model scores describe only the model prediction. "
        "The destination website is never visited."
    ),
    responses={
        413: {
            "model": ErrorResponse,
            "description": "Request body exceeds 32 KB.",
        },
        422: {
            "model": ErrorResponse,
            "description": "Invalid URL or request data.",
        },
        500: {
            "model": ErrorResponse,
            "description": "Prediction could not be completed.",
        },
    },
)
def predict(request: URLRequest):
    try:
        url = validate_url(request.url)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=(
                "Enter a valid http or https URL, such as "
                "https://example.com, with no spaces and "
                "at most 4096 characters."
            ),
        )

    try:
        result = dict(predict_url(url))
        signals = impersonation_signals(url)

        flagged = any(
            signal["strength"] == "strong"
            for signal in signals
        )

        result["security"] = {
            "flagged": flagged,
            "signals": signals,
            "note": (
                "Rule-based warnings can produce false alarms "
                "or miss threats. No warning does not mean safe. "
                "Internationalised domains can be legitimate."
            ),
        }

        result["combined_prediction"] = (
            "phishing"
            if result["prediction"] == "phishing" or flagged
            else "benign"
        )

        return result

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to process the prediction. Please try again.",
        )
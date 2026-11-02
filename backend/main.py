"""CyberShield API - FastAPI Backend for cyber threat detection."""

from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberShield API",
    description="API for detecting phishing URLs, scam SMS, malicious APKs, QR codes, and screenshots.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str


class URLScanRequest(BaseModel):
    url: str


class SMSScanRequest(BaseModel):
    message: str


class StubResponse(BaseModel):
    status: str = "not_implemented"
    message: str
    scan_type: str
    received_input: Optional[str] = None


class HistoryResponse(BaseModel):
    scans: list = []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="CyberShield API",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/api/v1/scan/url", response_model=StubResponse)
async def scan_url(request: URLScanRequest):
    """Scan a URL for phishing/malicious content (stub)."""
    return StubResponse(
        status="not_implemented",
        message="URL scanning is not yet implemented. Detection logic will be added here.",
        scan_type="url",
        received_input=request.url,
    )


@app.post("/api/v1/scan/sms", response_model=StubResponse)
async def scan_sms(request: SMSScanRequest):
    """Scan an SMS message for scam indicators (stub)."""
    return StubResponse(
        status="not_implemented",
        message="SMS scanning is not yet implemented. Detection logic will be added here.",
        scan_type="sms",
        received_input=request.message,
    )


@app.post("/api/v1/scan/apk", response_model=StubResponse)
async def scan_apk(file: UploadFile = File(...)):
    """Scan an APK file for malicious content (stub)."""
    return StubResponse(
        status="not_implemented",
        message="APK scanning is not yet implemented. Detection logic will be added here.",
        scan_type="apk",
        received_input=file.filename,
    )


@app.post("/api/v1/scan/qr", response_model=StubResponse)
async def scan_qr(file: UploadFile = File(...)):
    """Scan a QR code image for malicious links (stub)."""
    return StubResponse(
        status="not_implemented",
        message="QR code scanning is not yet implemented. Detection logic will be added here.",
        scan_type="qr",
        received_input=file.filename,
    )


@app.post("/api/v1/scan/screenshot", response_model=StubResponse)
async def scan_screenshot(file: UploadFile = File(...)):
    """Scan a screenshot for phishing/scam indicators (stub)."""
    return StubResponse(
        status="not_implemented",
        message="Screenshot scanning is not yet implemented. Detection logic will be added here.",
        scan_type="screenshot",
        received_input=file.filename,
    )


@app.get("/api/v1/history", response_model=HistoryResponse)
async def get_history():
    """Retrieve scan history (stub)."""
    return HistoryResponse(scans=[])

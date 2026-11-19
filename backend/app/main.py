"""CyberShield API - FastAPI Backend for cyber threat detection."""

import asyncio
from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Request, UploadFile, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from app.auth import get_current_user, get_current_user_optional, AuthenticatedUser, initialize_firebase_admin
from app.services.url_detector import URLThreatDetector, URLAnalysisResult
from app.services.sms_detector import SMSThreatDetector, SMSAnalysisResult
from app.services.qr_detector import QRThreatDetector, QRAnalysisResult
from app.services.screenshot_detector import ScreenshotThreatDetector, ScreenshotAnalysisResult
from app.services.apk_detector import APKSecurityAnalyzer, APKAnalysisResult
from app.services.permission_detector import PermissionAnalyzer, PermissionAnalysisResult
from app.services.email_detector import EmailThreatDetector, EmailAnalysisResult
from app.services.file_detector import FileThreatDetector, FileAnalysisResult
from app.services.history_service import HistoryRepository
from app.services.community_service import CommunityRepository, normalize_target, SUPPORTED_CATEGORIES
from app.services.assistant_service import SecurityAssistantService
from app.services.analytics_service import AnalyticsService
from app.services.alert_service import AlertRepository
from app.services.communication_service import (
    CommunicationRepository,
    classify_communication_risk,
    is_threat_flagged,
    redact_sensitive_communication,
)
from app.services.smart_event_engine import ALL_18_MODULES, SmartSecurityEventEngine
from app.services.openrouter_service import get_openrouter_service

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Initialize Firebase Admin SDK on module load
initialize_firebase_admin()

# ---------------------------------------------------------------------------
# App Initialization & Middleware
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberShield API",
    description="CyberShield Security Suite Backend - Real-time analysis for URLs, SMS, QR, screenshots, and APKs.",
    version="1.0.0",
)

_raw_allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").strip()
_allowed_origins = (
    ["*"]
    if not _raw_allowed_origins or _raw_allowed_origins == "*"
    else [o.strip() for o in _raw_allowed_origins.split(",") if o.strip()]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=_allowed_origins != ["*"],
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With"],
)

# Sliding-window API rate limiter (protects public cloud deployment from abuse)
_RATE_LIMIT_MAX_REQUESTS = int(os.getenv("API_RATE_LIMIT_PER_MINUTE", "120"))
_RATE_LIMIT_WINDOW_SECONDS = 60.0
_rate_limit_buckets: Dict[str, List[float]] = {}
_rate_limit_lock = __import__("threading").Lock()


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    """Attach defensive HTTP security headers and enforce per-client rate limits in production."""
    path = request.url.path
    if (
        _RATE_LIMIT_MAX_REQUESTS > 0
        and not os.getenv("PYTEST_CURRENT_TEST")
        and path not in ("/", "/health", "/api/v1/health", "/docs", "/openapi.json")
    ):
        forwarded_for = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        client_key = forwarded_for or (request.client.host if request.client else "unknown")
        now = __import__("time").monotonic()
        cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
        with _rate_limit_lock:
            hits = [t for t in _rate_limit_buckets.get(client_key, []) if t > cutoff]
            if len(hits) >= _RATE_LIMIT_MAX_REQUESTS:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Too many requests. Please slow down and try again shortly."},
                    headers={"Retry-After": "60"},
                )
            hits.append(now)
            _rate_limit_buckets[client_key] = hits

    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


url_detector = URLThreatDetector()
sms_detector = SMSThreatDetector()
qr_detector = QRThreatDetector()
screenshot_detector = ScreenshotThreatDetector(url_detector=url_detector, sms_detector=sms_detector)
apk_analyzer = APKSecurityAnalyzer()
permission_analyzer = PermissionAnalyzer()
email_detector = EmailThreatDetector(url_detector=url_detector)
file_detector = FileThreatDetector()
history_repo = HistoryRepository()
community_repo = CommunityRepository(db_path=history_repo.db_path)
assistant_service = SecurityAssistantService(db_path=history_repo.db_path)
analytics_service = AnalyticsService(history_repo=history_repo, community_repo=community_repo)
alert_repo = AlertRepository(db_path=history_repo.db_path)
communication_repo = CommunicationRepository(db_path=history_repo.db_path)
smart_event_engine = SmartSecurityEventEngine(
    db_path=history_repo.db_path,
    alert_repo=alert_repo,
)
ai_service = get_openrouter_service()


def _start_lan_discovery_beacon(http_port: int = 8000, udp_port: int = 8001) -> None:
    """Start a lightweight UDP broadcast responder on local dev networks (auto-disabled in cloud)."""
    if (
        os.getenv("PYTEST_CURRENT_TEST")
        or os.getenv("DISABLE_LAN_BEACON") == "1"
        or os.getenv("RAILWAY_ENVIRONMENT")
        or os.getenv("RENDER")
        or os.getenv("K_SERVICE")
        or os.getenv("FLY_APP_NAME")
    ):
        return

    import json as _json
    import socket as _socket
    import threading as _threading

    def _serve() -> None:
        sock = None
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", udp_port))
            reply = _json.dumps({"service": "CyberShield API", "port": http_port}).encode("utf-8")
            while True:
                try:
                    data, addr = sock.recvfrom(256)
                    if data and b"CYBERSHIELD_DISCOVER" in data:
                        sock.sendto(reply, addr)
                except OSError:
                    break
                except Exception:
                    continue
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    t = _threading.Thread(target=_serve, name="cybershield-lan-beacon", daemon=True)
    t.start()


_start_lan_discovery_beacon()


async def _read_upload_bounded(
    upload: UploadFile,
    max_bytes: int,
    label: str = "file",
    chunk_size: int = 256 * 1024,
) -> bytes:
    """Stream multipart upload in bounded 256 KB chunks, rejecting oversized payloads early."""
    buf = bytearray()
    total = 0
    while True:
        chunk = await upload.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{label} size exceeds maximum limit of {max_bytes // (1024 * 1024)}MB.",
            )
        buf.extend(chunk)
    return bytes(buf)


def _apply_ai_enrichment(
    *,
    module_name: str,
    target: str,
    risk_score: int,
    classification: str,
    findings: List[str],
    explanation: str,
    metadata: Dict[str, Any],
) -> str:
    """Enrich deterministic scanner explanation with centralized OpenRouter AI without altering risk score."""
    ai_res = ai_service.generate_structured_security_analysis_sync(
        module_name=module_name,
        target=target,
        risk_score=risk_score,
        classification=classification,
        findings=findings,
        base_explanation=explanation,
    )
    metadata["ai_enrichment"] = ai_res.to_dict()
    if ai_res.success and ai_res.explanation and ai_res.explanation.strip() != explanation.strip():
        return f"{explanation}\n\nAI Insight ({ai_res.model}): {ai_res.explanation.strip()}"
    return explanation

# ---------------------------------------------------------------------------
# Scan History Store (SQLite persistent repository + in-memory cache)
# ---------------------------------------------------------------------------

SCAN_HISTORY: List[Dict[str, Any]] = list(history_repo.get_all(limit=1000))

_SCAN_TYPE_TO_MODULE = {
    "URL": "url_scanner",
    "SMS": "sms_scanner",
    "QR": "qr_scanner",
    "SCREENSHOT": "screenshot_analyzer",
    "APK": "apk_analyzer",
    "FILE": "file_scanner",
    "PERMISSIONS": "permission_analyzer",
    "EMAIL": "email_scanner",
    "GMAIL": "gmail_integration",
    "INSTALLED_APPS": "installed_app_audit",
}

def record_scan_event(
    scan_type: str,
    target: str,
    summary: str,
    status_badge: str,
    risk_score: int = 0,
    classification: str = "Safe",
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Record an audit trail item in SQLite database, in-memory cache, and Smart Event Engine."""
    scan_id = f"scan-{len(SCAN_HISTORY) + 1:04d}"
    timestamp = datetime.now(timezone.utc).isoformat()

    merged_details = dict(details) if details else {}
    if user_id:
        merged_details["user_id"] = user_id

    event = history_repo.record_scan(
        scan_id=scan_id,
        scan_type=scan_type,
        target=target,
        risk_score=risk_score,
        classification=classification,
        summary=summary,
        status_badge=status_badge,
        timestamp=timestamp,
        details=merged_details,
    )
    SCAN_HISTORY.insert(0, event)  # Most recent first

    # Automatically generate security alert for critical, high-risk, or suspicious findings
    try:
        alert_repo.evaluate_and_create_scan_alert(event, user_id=user_id)
    except Exception:
        pass

    # Submit standardized event into Centralized Smart Security Event Engine (fault-isolated)
    if user_id:
        mod_override = merged_details.get("module_override")
        mod_name = str(mod_override) if mod_override else _SCAN_TYPE_TO_MODULE.get(
            (scan_type or "").upper(), "audit_history"
        )
        src_override = merged_details.get("source_override")
        raw_findings = merged_details.get("findings") or merged_details.get("threat_categories") or []
        findings_list = [str(x) for x in raw_findings] if isinstance(raw_findings, list) else []
        rec = merged_details.get("recommendation")
        rec_list = [str(rec)] if rec else []
        smart_event_engine.safe_record(
            user_id=user_id,
            module_name=mod_name,
            source=str(src_override) if src_override else None,
            target_identifier=target or "N/A",
            risk_score=risk_score,
            classification=classification,
            findings=findings_list,
            explanation=summary,
            recommended_actions=rec_list,
            analysis_status="analyzed",
            detection_timestamp=timestamp,
            idempotency_key=f"scan:{scan_id}:{timestamp}",
            create_alert=False,  # alert_repo.evaluate_and_create_scan_alert already ran above
            metadata={"audit_scan_id": scan_id, "scan_type": scan_type, "status_badge": status_badge},
        )

    return event

# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "healthy"
    service: str = "CyberShield API"
    version: str = "1.0.0"
    timestamp: str
    active_modules: List[str] = [
        "url_threat_detector",
        "url_scanner",
        "sms_threat_detector",
        "sms_scanner",
        "qr_scanner",
        "qr_threat_detector",
        "screenshot_analysis",
        "screenshot_threat_detector",
        "apk_analysis",
        "apk_security_inspector",
        "permission_analyzer",
        "email_threat_detector",
        "email_scanner",
        "file_threat_detector",
        "file_scanner",
        "audit_history",
        "community_reporting",
        "community_threat_intelligence",
        "ai_security_assistant",
        "security_dashboard_analytics",
        "security_alerts",
        "realtime_protection",
        "notification_monitor",
        "call_screening",
    ]


class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL to inspect")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("URL cannot be empty or contain only whitespace.")
        lower = trimmed.lower()
        if lower.startswith(("javascript:", "data:", "file:", "vbscript:")):
            raise ValueError("Unsupported or dangerous URL scheme detected.")
        return trimmed


class URLThreatScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The URL string to inspect for cyber threats and phishing indicators.",
        examples=["https://secure-bank.example.com", "http://192.168.1.1/login", "https://secure-login-verify.example.com"],
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("URL cannot be empty or contain only whitespace.")
        lower = trimmed.lower()
        if lower.startswith(("javascript:", "data:", "file:", "vbscript:")):
            raise ValueError("Unsupported or dangerous URL scheme detected.")
        return trimmed


class URLScanResponse(BaseModel):
    status: str = Field("inspected", description="Status code of the inspection")
    scan_type: str = Field("url", description="Type of scan performed")
    target: str = Field(..., description="Target URL inspected")
    scanned_url: str = Field(..., description="Normalized URL inspected")
    timestamp: str = Field(..., description="ISO 8601 timestamp of inspection")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated threat risk score from 0 (Safe) to 100 (Malicious)")
    classification: str = Field(..., description="Threat classification: Safe, Suspicious, or Malicious")
    findings: List[str] = Field(default_factory=list, description="List of detected findings and structural checks")
    detected_indicators: List[str] = Field(default_factory=list, description="Alias for detected threat indicators")
    explanation: str = Field(..., description="Detailed explanation of findings and overall risk assessment")
    finding_explanations: List[Dict[str, str]] = Field(default_factory=list, description="Granular explanation for each detected finding")
    recommendation: str = Field(..., description="Actionable security recommendation for the user")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="URL protocol and structural metadata")
    engine_status: str = Field("heuristic_threat_inspector_active", description="Active security engine status")


# Backwards compatibility aliases
ScanResultResponse = URLScanResponse
URLThreatScanResponse = URLScanResponse


class QRScanRequest(BaseModel):
    payload: Optional[str] = Field(None, max_length=50000, description="Decoded QR code content")

    def get_clean_payload(self) -> str:
        if self.payload is None:
            raise ValueError("QR payload must be provided.")
        trimmed = self.payload.strip()
        if not trimmed:
            raise ValueError("QR payload cannot be empty or contain only whitespace.")
        return trimmed


class QRScanResponse(BaseModel):
    status: str
    scan_type: str = "qr"
    content_type: str
    decoded_payload: str
    timestamp: str
    risk_score: int
    classification: str
    findings: List[str]
    detected_indicators: List[str]
    explanation: str
    finding_explanations: List[Dict[str, str]]
    recommendation: str
    metadata: Dict[str, Any]
    engine_status: str = "qr_threat_inspector_active"


class ScreenshotAnalysisResponse(BaseModel):
    status: str = Field("inspected", description="Status code of the inspection")
    scan_type: str = Field("screenshot", description="Type of scan performed")
    filename: str = Field(..., description="Uploaded image filename")
    ocr_text: str = Field("", description="Raw textual content extracted via OCR")
    timestamp: str = Field(..., description="ISO 8601 timestamp of inspection")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated threat risk score (0-100)")
    classification: str = Field(..., description="Threat classification: Safe, Suspicious, or Malicious")
    findings: List[str] = Field(default_factory=list, description="Detected threat findings")
    detected_indicators: List[str] = Field(default_factory=list, description="Detected indicators")
    explanation: str = Field(..., description="Analysis explanation")
    finding_explanations: List[Dict[str, str]] = Field(default_factory=list, description="Granular finding details")
    recommendation: str = Field(..., description="Actionable recommendation")
    extracted_urls: List[str] = Field(default_factory=list, description="URLs extracted from screenshot")
    threat_categories: List[str] = Field(default_factory=list, description="Identified threat categories")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Image and extraction metadata")
    engine_status: str = Field("screenshot_threat_inspector_active", description="Engine status")


class APKAnalysisResponse(BaseModel):
    status: str = Field("inspected", description="Status code of the inspection")
    scan_type: str = Field("apk", description="Type of scan performed")
    filename: str = Field(..., description="Uploaded APK package filename")
    package_name: str = Field(..., description="Parsed Android package name (e.g. com.example.app)")
    app_name: str = Field(..., description="Application name or label")
    version_name: str = Field(..., description="Application version name")
    version_code: str = Field(..., description="Application version code")
    min_sdk: int = Field(0, description="Minimum Android SDK level required")
    target_sdk: int = Field(0, description="Target Android SDK level")
    permissions: List[str] = Field(default_factory=list, description="All permissions requested in AndroidManifest")
    dangerous_permissions: List[str] = Field(default_factory=list, description="Elevated-risk / dangerous permissions detected")
    combo_findings: List[str] = Field(default_factory=list, description="Dangerous permission combination findings")
    timestamp: str = Field(..., description="ISO 8601 timestamp of inspection")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated security risk score (0-100)")
    classification: str = Field(..., description="Security classification: Safe, Suspicious, or High Risk")
    findings: List[str] = Field(default_factory=list, description="Security findings and risk observations")
    detected_indicators: List[str] = Field(default_factory=list, description="Detected risk indicators")
    explanation: str = Field(..., description="Detailed security analysis explanation")
    finding_explanations: List[Dict[str, Any]] = Field(default_factory=list, description="Explanations for each dangerous permission or risk flag")
    recommendation: str = Field(..., description="Actionable security recommendation for the user")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="APK structural details (file count, dex count, native libs)")
    engine_status: str = Field("apk_security_inspector_active", description="Active analyzer engine status")


class PermissionListRequest(BaseModel):
    package_name: str = Field(default="custom.app.inspect", description="Android package name (e.g. com.example.app)")
    app_name: str = Field(default="Android Application", description="Application label")
    permissions: List[str] = Field(..., description="List of Android permission strings")
    min_sdk: Optional[int] = Field(default=0, description="Minimum SDK version")
    target_sdk: Optional[int] = Field(default=0, description="Target SDK version")
    version_name: Optional[str] = Field(default="1.0", description="App version name")


class PermissionAnalysisResponse(BaseModel):
    status: str = Field("analyzed", description="Status code of permission analysis")
    scan_type: str = Field("permissions", description="Type of scan performed")
    package_name: str = Field(..., description="Parsed Android package name")
    app_name: str = Field(..., description="Application name")
    version_name: str = Field("1.0", description="Version name")
    version_code: str = Field("1", description="Version code")
    min_sdk: int = Field(0, description="Minimum Android SDK")
    target_sdk: int = Field(0, description="Target Android SDK")
    total_permissions_count: int = Field(..., description="Total count of requested permissions")
    dangerous_permissions_count: int = Field(..., description="Count of dangerous permissions")
    permissions: List[str] = Field(default_factory=list, description="All requested permissions")
    dangerous_permissions: List[str] = Field(default_factory=list, description="Identified dangerous permissions")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0-100")
    classification: str = Field(..., description="Risk tier: Safe, Suspicious, High Risk, or Critical")
    findings: List[str] = Field(default_factory=list, description="Summary findings")
    detected_indicators: List[str] = Field(default_factory=list, description="List of suspicious indicator flags")
    combo_findings: List[str] = Field(default_factory=list, description="Detected high-risk combinations")
    finding_explanations: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed explanation per permission/combo")
    explanation: str = Field(..., description="Detailed context and rationale")
    recommendation: str = Field(..., description="Actionable recommendation")
    recommendations: List[str] = Field(default_factory=list, description="List of actionable security recommendations")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    engine_status: str = Field("permission_analyzer_active", description="Engine status")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InstalledAppItem(BaseModel):
    package_name: str = Field(..., min_length=1, max_length=200, description="Package name")
    app_name: str = Field(default="Android Application", max_length=200, description="App display name")
    permissions: List[str] = Field(default_factory=list, description="Declared permissions")
    version_name: Optional[str] = Field(default="1.0", max_length=50)
    version_code: Optional[str] = Field(default="1", max_length=50)
    min_sdk: Optional[int] = Field(default=0)
    target_sdk: Optional[int] = Field(default=0)
    is_system_app: Optional[bool] = Field(default=False)


class BatchPermissionAnalysisRequest(BaseModel):
    apps: List[InstalledAppItem] = Field(..., min_length=1, max_length=500, description="List of installed applications")


class InstalledAppAnalysisResult(BaseModel):
    package_name: str
    app_name: str
    version_name: str
    is_system_app: bool
    risk_score: int
    classification: str
    total_permissions_count: int
    dangerous_permissions_count: int
    dangerous_permissions: List[str]
    combo_findings: List[str]
    finding_explanations: List[Dict[str, Any]]
    explanation: str
    recommendations: List[str]


class BatchPermissionAnalysisResponse(BaseModel):
    status: str = Field("analyzed", description="Status of batch analysis")
    scan_type: str = Field("installed_applications_batch")
    total_apps_analyzed: int
    safe_count: int
    suspicious_count: int
    high_risk_count: int
    critical_count: int
    overall_device_risk_score: int
    overall_classification: str
    summary: str
    high_risk_apps: List[InstalledAppAnalysisResult]
    all_apps: List[InstalledAppAnalysisResult]
    recommendations: List[str]
    engine_status: str = Field("installed_apps_batch_analyzer_active")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CallScreenRequest(BaseModel):
    phone_number: str = Field(..., min_length=3, max_length=25, description="Incoming phone number")
    caller_name: Optional[str] = Field(default=None, max_length=100, description="Caller name or display text")


class CallScreenResponse(BaseModel):
    phone_number: str
    normalized_number: str
    caller_name: Optional[str] = None
    is_known_spam: bool
    spam_score: int
    classification: str
    confidence: str
    report_count: int
    evidence_tags: List[str]
    recommended_action: str
    explanation: str
    engine_status: str = Field("call_screening_active")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class NotificationAnalyzeRequest(BaseModel):
    package_name: str = Field(..., min_length=1, max_length=200, description="Source app package name")
    title: Optional[str] = Field(default="", max_length=500, description="Notification title")
    text: Optional[str] = Field(default="", max_length=4000, description="Notification body text")
    sub_text: Optional[str] = Field(default="", max_length=500, description="Notification subtext")
    posted_timestamp: Optional[str] = Field(default=None, description="ISO timestamp")


class NotificationAnalyzeResponse(BaseModel):
    status: str = Field("analyzed", description="Status of notification analysis")
    package_name: str
    sanitized_text: str
    detected_urls: List[str]
    url_analyses: List[Dict[str, Any]]
    sms_risk_score: int
    overall_risk_score: int
    classification: str
    threat_types: List[str]
    has_phishing_url: bool
    has_financial_urgency: bool
    has_impersonation: bool
    redacted_sensitive_data: bool
    explanation: str
    recommended_action: str
    engine_status: str = Field("notification_threat_detector_active")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EmailScanRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=100000, description="Email body content to inspect")
    sender: Optional[str] = Field(None, max_length=500, description="Email sender address and/or display name")
    subject: Optional[str] = Field(None, max_length=1000, description="Email subject line")
    reply_to: Optional[str] = Field(None, max_length=500, description="Optional Reply-To header")

    @field_validator("body")
    @classmethod
    def validate_body(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Email body cannot be empty or contain only whitespace.")
        return trimmed


class GmailMessageScanRequest(BaseModel):
    message_id: str = Field(..., max_length=128, description="Gmail unique message ID")
    sender: str = Field(..., max_length=500, description="Email sender header")
    subject: str = Field(..., max_length=1000, description="Email subject line")
    body: str = Field(..., min_length=1, max_length=100000, description="Decoded email body or snippet")
    date: Optional[str] = Field(None, max_length=128, description="Email date header")
    reply_to: Optional[str] = Field(None, max_length=500, description="Optional Reply-To header")

    @field_validator("body")
    @classmethod
    def validate_body(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Email body cannot be empty or contain only whitespace.")
        return trimmed


class EmailScanResponse(BaseModel):
    status: str = Field("inspected", description="Status code of the inspection")
    scan_type: str = Field("email", description="Type of scan performed")
    sender: str = Field("", description="Sender address evaluated")
    subject: str = Field("", description="Subject line evaluated")
    body: str = Field("", description="Scanned body excerpt")
    risk_score: int = Field(..., ge=0, le=100, description="Computed risk score from 0-100")
    classification: str = Field(..., description="Risk tier: Safe, Suspicious, High Risk, or Critical")
    threat_categories: List[str] = Field(default_factory=list, description="Identified threat categories")
    detected_indicators: List[str] = Field(default_factory=list, description="Detected indicator strings")
    findings: List[str] = Field(default_factory=list, description="Security findings summary")
    finding_explanations: List[Dict[str, str]] = Field(default_factory=list, description="Detailed explanation per indicator")
    explanation: str = Field(..., description="Overall context and assessment")
    recommendation: str = Field(..., description="Primary recommendation")
    recommendations: List[str] = Field(default_factory=list, description="List of actionable recommendations")
    embedded_urls: List[str] = Field(default_factory=list, description="URLs extracted from the email")
    url_scan_results: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed analysis per extracted URL")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata flags")
    engine_status: str = Field("email_threat_detector_active", description="Active analyzer engine status")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FileScanResponse(BaseModel):
    status: str = Field("inspected", description="Status code of the inspection")
    scan_type: str = Field("file", description="Type of scan performed")
    filename: str = Field(..., description="Name of the uploaded file")
    file_size_bytes: int = Field(..., description="File size in bytes")
    detected_mime: str = Field(..., description="Detected magic byte file signature")
    file_extension: str = Field(..., description="Reported file extension")
    is_archive: bool = Field(False, description="Whether the file is a compressed archive")
    risk_score: int = Field(..., ge=0, le=100, description="Computed risk score from 0-100")
    classification: str = Field(..., description="Risk tier: Safe, Suspicious, High Risk, or Critical")
    threat_categories: List[str] = Field(default_factory=list, description="Identified threat categories")
    detected_indicators: List[str] = Field(default_factory=list, description="Detected indicator strings")
    findings: List[str] = Field(default_factory=list, description="Security findings summary")
    finding_explanations: List[Dict[str, str]] = Field(default_factory=list, description="Detailed explanation per indicator")
    explanation: str = Field(..., description="Overall context and assessment")
    recommendation: str = Field(..., description="Primary recommendation")
    recommendations: List[str] = Field(default_factory=list, description="List of actionable recommendations")
    archive_contents: List[str] = Field(default_factory=list, description="Archive member paths if applicable")
    md5: Optional[str] = Field(None, description="MD5 cryptographic file hash")
    sha1: Optional[str] = Field(None, description="SHA-1 cryptographic file hash")
    sha256: Optional[str] = Field(None, description="SHA-256 cryptographic file hash")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata flags")
    engine_status: str = Field("file_threat_detector_active", description="Active analyzer engine status")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SMSScanRequest(BaseModel):
    message: Optional[str] = Field(None, max_length=10000, description="SMS message text to analyze")
    text: Optional[str] = Field(None, max_length=10000, description="Alternative field for message text")

    def get_clean_text(self) -> str:
        content = self.message if self.message is not None else self.text
        if content is None:
            raise ValueError("SMS content must be provided in 'message' or 'text' field.")
        trimmed = content.strip()
        if not trimmed:
            raise ValueError("SMS message cannot be empty or contain only whitespace.")
        return trimmed


class SMSScanResponse(BaseModel):
    status: str = Field("inspected", description="Status code of the inspection")
    scan_type: str = Field("sms", description="Type of scan performed")
    target: str = Field(..., description="Target SMS snippet")
    scanned_message: str = Field(..., description="Full message text analyzed")
    timestamp: str = Field(..., description="ISO 8601 timestamp of inspection")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated threat risk score from 0 (Safe) to 100 (Malicious)")
    classification: str = Field(..., description="Threat classification: Safe, Suspicious, or Malicious")
    threat_categories: List[str] = Field(default_factory=list, description="Threat categories detected")
    findings: List[str] = Field(default_factory=list, description="List of detected findings and structural checks")
    detected_indicators: List[str] = Field(default_factory=list, description="Alias for detected threat indicators")
    explanation: str = Field(..., description="Detailed explanation of findings and overall risk assessment")
    finding_explanations: List[Dict[str, str]] = Field(default_factory=list, description="Granular explanation for each detected finding")
    recommendation: str = Field(..., description="Actionable security recommendation for the user")
    embedded_urls: List[str] = Field(default_factory=list, description="URLs extracted and analyzed from the SMS")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="SMS structural and linguistic metadata")
    engine_status: str = Field("sms_threat_inspector_active", description="Active security engine status")


# Backwards compatibility alias
SMSScanResultResponse = SMSScanResponse


class HistoryResponse(BaseModel):
    total_count: int = Field(..., description="Total scan events recorded in history")
    filtered_count: Optional[int] = Field(None, description="Count of scans matching current filters")
    scans: List[Dict[str, Any]] = Field(default_factory=list, description="List of scan audit records")


class HistoryDetailResponse(BaseModel):
    id: str
    scan_id: str
    scan_type: str
    target: str
    risk_score: int
    classification: str
    summary: str
    status_badge: str
    timestamp: str
    details: Dict[str, Any] = Field(default_factory=dict)


class HistoryDeleteResponse(BaseModel):
    status: str = "deleted"
    scan_id: str
    message: str


class CommunityReportCreateRequest(BaseModel):
    category: str = Field(..., description="Report category: phone, sms, url, qr, email, app")
    target: str = Field(..., min_length=1, max_length=4000, description="Reported target content or identifier")
    title: str = Field(..., min_length=3, max_length=200, description="Brief summary of threat reason")
    description: Optional[str] = Field(default="", max_length=2000, description="Optional detailed observations")
    tags: List[str] = Field(default_factory=list, description="Tags describing the threat (e.g. phishing, impersonation)")

    @field_validator("category")
    @classmethod
    def validate_category(cls, v: str) -> str:
        trimmed = v.strip().lower()
        if trimmed not in SUPPORTED_CATEGORIES:
            raise ValueError(f"Category '{v}' is unsupported. Must be one of: {sorted(SUPPORTED_CATEGORIES)}")
        return trimmed

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Report target cannot be empty or whitespace.")
        return trimmed


class CommunityReputationResponse(BaseModel):
    category: str = Field(..., description="Target category")
    target: str = Field(..., description="Normalized target")
    total_reports: int = Field(0, description="Total reports received")
    distinct_reporters: int = Field(0, description="Number of distinct reporting users")
    suspicion_score: int = Field(0, ge=0, le=100, description="Community suspicion score (0-100, unverified capped at 75)")
    classification: str = Field(..., description="Reputation classification")
    confidence: str = Field(..., description="Confidence rating: None, Low, Moderate, High")
    threat_status: str = Field(..., description="Threat status flag: UNKNOWN, UNVERIFIED_COMMUNITY_FLAGGED, VERIFIED_THREAT")
    is_verified_threat: bool = Field(False, description="Whether threat has been verified by security intelligence")
    last_reported_at: Optional[str] = Field(None, description="ISO timestamp of most recent report")
    evidence_tags: List[Dict[str, Any]] = Field(default_factory=list, description="Common tags observed in reports")
    disclaimer: str = Field(..., description="Analytical disclaimer distinguishing reports from confirmed malware")


class CommunityReportResponse(BaseModel):
    id: str = Field(..., description="Unique report ID")
    category: str = Field(..., description="Category")
    target: str = Field(..., description="Normalized target")
    target_display: str = Field(..., description="Display target")
    title: str = Field(..., description="Report title")
    description: Optional[str] = Field("", description="Report description")
    tags: List[str] = Field(default_factory=list, description="Report tags")
    status: str = Field(..., description="Report status: PENDING, UNDER_REVIEW, VERIFIED_THREAT, REJECTED")
    is_verified: bool = Field(False, description="Whether verified threat")
    created_at: str = Field(..., description="Creation timestamp")
    reputation: Optional[CommunityReputationResponse] = Field(None, description="Associated target reputation")


class CommunityReportListResponse(BaseModel):
    total_count: int = Field(..., description="Total count of reports matching filters")
    reports: List[CommunityReportResponse] = Field(default_factory=list, description="List of community reports")


class CommunityStatsResponse(BaseModel):
    total_reports: int = Field(..., description="Total community reports recorded")
    distinct_targets: int = Field(..., description="Unique targets reported across all categories")
    active_reporters: int = Field(..., description="Unique active reporting users")
    verified_threats: int = Field(..., description="Number of confirmed threats")
    categories: Dict[str, int] = Field(default_factory=dict, description="Report count per category")
    timestamp: str = Field(..., description="Timestamp of metrics generation")


class ScanContextInput(BaseModel):
    scan_type: str = Field(..., description="Scan type: URL, SMS, QR, EMAIL, FILE, APK, PERMISSIONS, etc.")
    target: Optional[str] = Field(None, description="Scanned target string, URL, filename, or message")
    risk_score: Optional[int] = Field(0, ge=0, le=100, description="Risk score from detector")
    classification: Optional[str] = Field("Safe", description="Threat classification")
    findings: List[str] = Field(default_factory=list, description="Detector findings")
    threat_categories: List[str] = Field(default_factory=list, description="Threat categories")
    details: Dict[str, Any] = Field(default_factory=dict, description="Detailed scan metadata")


class AssistantChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000, description="User prompt or cybersecurity question")
    session_id: Optional[str] = Field(None, max_length=64, description="Chat session identifier")
    scan_context: Optional[ScanContextInput] = Field(None, description="Optional scan telemetry for explanation")
    language: Optional[str] = Field("en", max_length=10, description="Preferred response language")

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Message cannot be empty or contain only whitespace.")
        return trimmed


class AssistantChatResponse(BaseModel):
    id: str = Field(..., description="Unique assistant reply ID")
    session_id: str = Field(..., description="Session identifier")
    role: str = Field("assistant", description="Message role")
    content: str = Field(..., description="Assistant response text (markdown)")
    provider: str = Field(..., description="AI or heuristic engine provider used")
    is_ai_generated: bool = Field(True, description="Whether response was generated by AI/heuristic assistant")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Telemetry, disclaimer, and guard tags")


class AssistantHistoryResponse(BaseModel):
    user_id: str = Field(..., description="Firebase user UID")
    session_id: Optional[str] = Field(None, description="Session filter")
    total_messages: int = Field(..., description="Total messages in history")
    messages: List[Dict[str, Any]] = Field(default_factory=list, description="Ordered conversation history")


class AssistantClearHistoryResponse(BaseModel):
    status: str = Field("cleared", description="Operation status")
    deleted_count: int = Field(..., description="Number of deleted messages")
    message: str = Field(..., description="User-facing confirmation message")


class SecurityScoreData(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Calculated security posture score")
    status: str = Field(..., description="Defense rating label")
    tier: str = Field(..., description="Risk tier: Optimal, Guarded, Warning, Danger, Neutral")
    calculation_explanation: str = Field(..., description="Transparent mathematical breakdown of score")
    disclaimer: str = Field(..., description="Non-absolute protection disclaimer")


class ScannerStatsItem(BaseModel):
    total: int = Field(0, description="Total scans evaluated")
    safe: int = Field(0, description="Clean inspections")
    threats: int = Field(0, description="Threat encounters")


class ActivityTrendPoint(BaseModel):
    date: str = Field(..., description="Date key (YYYY-MM-DD)")
    total: int = Field(0, description="Total scans on date")
    safe: int = Field(0, description="Clean scans on date")
    threats: int = Field(0, description="Threat scans on date")


class CommunityOverviewStats(BaseModel):
    total_reports: int = Field(0, description="Total community threat reports")
    distinct_targets: int = Field(0, description="Unique targets reported")
    active_reporters: int = Field(0, description="Unique citizen contributors")
    verified_threats: int = Field(0, description="Verified threats count")


class RecentScanItem(BaseModel):
    id: str = Field(..., description="Scan identifier")
    scan_id: str = Field(..., description="Scan ID")
    scan_type: str = Field(..., description="Scanner module type")
    target: str = Field(..., description="Target string, URL, filename, or message")
    risk_score: int = Field(..., ge=0, le=100, description="Evaluated risk score")
    classification: str = Field(..., description="Threat classification")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")


class DashboardAnalyticsResponse(BaseModel):
    time_range_days: int = Field(..., description="Evaluation window in days (0 for all-time)")
    total_scans: int = Field(..., description="Total scans recorded")
    safe_scans: int = Field(..., description="Safe scans count")
    suspicious_scans: int = Field(..., description="Suspicious scans count")
    high_risk_scans: int = Field(..., description="High risk scans count")
    critical_scans: int = Field(..., description="Critical threats count")
    threat_detection_rate: float = Field(..., description="Percentage of scans with suspicious or malicious findings")
    security_score: SecurityScoreData = Field(..., description="Transparent security posture rating")
    scanner_breakdown: Dict[str, ScannerStatsItem] = Field(default_factory=dict, description="Scanner-wise statistics")
    risk_distribution: Dict[str, int] = Field(default_factory=dict, description="Safe vs Suspicious vs High Risk vs Critical")
    activity_trends: List[ActivityTrendPoint] = Field(default_factory=list, description="Chronological activity trend datapoints")
    community_stats: CommunityOverviewStats = Field(..., description="Crowd threat metrics")
    recent_scans: List[RecentScanItem] = Field(default_factory=list, description="Top recent scan records")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of analytics generation")


# ---------------------------------------------------------------------------
# Helper function for consistent URL threat response
# ---------------------------------------------------------------------------

def _build_url_scan_payload(raw_url: str, user_id: Optional[str] = None) -> URLScanResponse:
    """Run URLThreatDetector and compile backwards-compatible, structured response."""
    result: URLAnalysisResult = url_detector.analyze(raw_url)
    result.explanation = _apply_ai_enrichment(
        module_name="URL Threat Scanner",
        target=result.scanned_url,
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.detected_indicators,
        explanation=result.explanation,
        metadata=result.metadata,
    )
    
    # Ensure positive structural protocol finding is present for backwards-compatibility
    findings = list(result.detected_indicators)
    parsed = urlparse(result.scanned_url)
    if parsed.scheme.lower() == "https":
        https_msg = "Transport protocol verified: HTTPS with TLS encapsulation"
        if https_msg not in findings:
            findings.insert(0, https_msg)

    # Record scan into audit history
    badge = result.classification.lower()
    summary = f"Risk Score: {result.risk_score}/100 ({result.classification})"
    record_scan_event(
        "URL",
        result.scanned_url,
        summary,
        badge,
        risk_score=result.risk_score,
        classification=result.classification,
        user_id=user_id,
        details={
            "scanned_url": result.scanned_url,
            "findings": findings,
            "explanation": result.explanation,
            "recommendation": result.recommendation,
            "detected_indicators": result.detected_indicators,
            "metadata": result.metadata,
        },
    )

    return URLScanResponse(
        status="inspected",
        scan_type="url",
        target=result.scanned_url,
        scanned_url=result.scanned_url,
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=result.risk_score,
        classification=result.classification,
        findings=findings,
        detected_indicators=result.detected_indicators,
        explanation=result.explanation,
        finding_explanations=result.finding_explanations,
        recommendation=result.recommendation,
        metadata=result.metadata,
        engine_status="heuristic_threat_inspector_active",
    )


def _build_sms_scan_payload(raw_message: str, user_id: Optional[str] = None) -> SMSScanResponse:
    """Run SMSThreatDetector and compile backwards-compatible, structured response."""
    result: SMSAnalysisResult = sms_detector.analyze(raw_message)
    result.explanation = _apply_ai_enrichment(
        module_name="SMS Threat Scanner",
        target=result.scanned_message[:120],
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.findings,
        explanation=result.explanation,
        metadata=result.metadata,
    )

    # Record scan into audit history
    badge = result.classification.lower()
    summary = f"Risk Score: {result.risk_score}/100 ({result.classification})"
    record_scan_event(
        "SMS",
        f"{result.scanned_message[:40]}...",
        summary,
        badge,
        risk_score=result.risk_score,
        classification=result.classification,
        user_id=user_id,
        details={
            "scanned_message": result.scanned_message,
            "threat_categories": result.threat_categories,
            "findings": result.findings,
            "explanation": result.explanation,
            "recommendation": result.recommendation,
            "detected_indicators": result.detected_indicators,
            "embedded_urls": result.embedded_urls,
            "metadata": result.metadata,
        },
    )

    return SMSScanResponse(
        status="inspected",
        scan_type="sms",
        target=f"{result.scanned_message[:60]}..." if len(result.scanned_message) > 60 else result.scanned_message,
        scanned_message=result.scanned_message,
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=result.risk_score,
        classification=result.classification,
        threat_categories=result.threat_categories,
        findings=result.findings,
        detected_indicators=result.detected_indicators,
        explanation=result.explanation,
        finding_explanations=result.finding_explanations,
        recommendation=result.recommendation,
        embedded_urls=result.embedded_urls,
        metadata=result.metadata,
        engine_status="sms_threat_inspector_active",
    )


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["System"])
async def root_status():
    """Root landing endpoint for cloud uptime probes and browser checks."""
    return {
        "service": "CyberShield API",
        "version": "1.0.0",
        "status": "online",
        "health": "/health",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health", response_model=HealthResponse, tags=["System"])
@app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint providing service uptime and module availability."""
    return HealthResponse(
        status="healthy",
        service="CyberShield API",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


class StructuredAIAnalyzeRequest(BaseModel):
    module_name: str = Field(..., min_length=1, max_length=120, description="Source CyberShield module")
    target: str = Field(..., min_length=1, max_length=2000, description="Target payload, URL, message, or file summary")
    risk_score: int = Field(default=0, ge=0, le=100, description="Deterministic detector risk score (0-100)")
    classification: str = Field(default="Unverified", max_length=60, description="Deterministic detector classification")
    findings: List[str] = Field(default_factory=list, description="Deterministic detector findings")
    base_explanation: str = Field(default="", max_length=2000, description="Baseline deterministic explanation")


@app.get("/api/v1/ai/status", tags=["AI Security Assistant"])
def ai_provider_status():
    """Verify configured OpenRouter model availability & token usage without exposing API keys."""
    return ai_service.verify_model_availability()


@app.post("/api/v1/ai/analyze", tags=["AI Security Assistant"])
def ai_structured_analyze(
    request: StructuredAIAnalyzeRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Run structured OpenRouter AI security analysis returning standardized response fields."""
    res = ai_service.generate_structured_security_analysis_sync(
        module_name=request.module_name,
        target=request.target,
        risk_score=request.risk_score,
        classification=request.classification,
        findings=request.findings,
        base_explanation=request.base_explanation,
    )
    return res.to_dict()


@app.post(
    "/api/v1/url/scan",
    response_model=URLScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan URL for threats (POST /api/v1/url/scan)",
    tags=["URL Threat Detection"],
)
def scan_url_threat(
    request: URLThreatScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Perform heuristic URL threat detection:
    - Insecure plain HTTP transport
    - IPv4/IPv6 address instead of domain
    - URL shortening services
    - Suspicious phishing & social engineering keywords
    - Excessive subdomains
    - User-info '@' symbol delimiter abuse
    - High-risk top-level domains (TLDs)

    Calculates a risk score (0-100), classifies the URL as Safe, Suspicious, or Malicious,
    and returns granular explanations and actionable recommendations.
    """
    try:
        return _build_url_scan_payload(request.url, user_id=current_user.uid)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to parse or inspect URL: {str(e)}",
        )


@app.post(
    "/api/v1/scan/url",
    response_model=URLScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan URL (POST /api/v1/scan/url)",
    tags=["URL Threat Detection"],
)
def scan_url(
    request: URLScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Existing URL scan endpoint upgraded with risk_score, classification,
    finding explanations, and actionable user recommendation while preserving
    all existing fields and compatibility.
    """
    try:
        return _build_url_scan_payload(request.url, user_id=current_user.uid)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to parse or inspect URL: {str(e)}",
        )


@app.post(
    "/api/v1/sms/scan",
    response_model=SMSScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan SMS for threats (POST /api/v1/sms/scan)",
    tags=["SMS Threat Detection"],
)
def scan_sms_threat(
    request: SMSScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Perform deep heuristic SMS and smishing threat detection:
    - Urgency and fear-based psychological coercion
    - Fake bank/KYC/account suspension alerts
    - OTP and credential harvesting scams
    - Prize/lottery advance-fee scams
    - Suspicious embedded URLs (bare IPs, shortening services, suspicious TLDs)
    - Requests for PIN, password, OTP, or advance payments
    - Impersonation of financial institutions, postal couriers, and government agencies
    """
    try:
        clean_text = request.get_clean_text()
        return _build_sms_scan_payload(clean_text, user_id=current_user.uid)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to inspect SMS text: {str(e)}",
        )


@app.post(
    "/api/v1/scan/sms",
    response_model=SMSScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan SMS (POST /api/v1/scan/sms)",
    tags=["SMS Threat Detection"],
)
def scan_sms(
    request: SMSScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Existing SMS scan endpoint upgraded with risk_score, classification,
    granular findings, explanations, and actionable user recommendations while
    preserving all existing fields and compatibility.
    """
    try:
        clean_text = request.get_clean_text()
        return _build_sms_scan_payload(clean_text, user_id=current_user.uid)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to inspect SMS text: {str(e)}",
        )


@app.post("/api/v1/scan/apk", response_model=SMSScanResultResponse, tags=["Scanners"])
async def scan_apk(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Inspect uploaded Android APK package metadata."""
    findings = [
        f"Uploaded APK package: {file.filename}",
        f"Content type reported: {file.content_type}",
        "Static bytecode and AndroidManifest analyzer ready for Phase 2 pipeline",
    ]
    summary = f"APK package received: {file.filename}"
    record_scan_event(
        "APK",
        file.filename or "unknown.apk",
        summary,
        "info",
        user_id=current_user.uid,
    )

    return SMSScanResultResponse(
        status="received",
        scan_type="apk",
        target=file.filename or "package.apk",
        scanned_message=f"APK package: {file.filename}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=0,
        classification="Safe",
        explanation="Legacy APK endpoint stub received the file.",
        recommendation="Use POST /api/v1/apk/analyze for full static security analysis.",
        findings=findings,
        metadata={"filename": file.filename, "content_type": file.content_type},
        engine_status="apk_pipeline_ready",
    )


@app.post(
    "/api/v1/apk/analyze",
    response_model=APKAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze Android APK package for security risks (POST /api/v1/apk/analyze)",
    tags=["APK Security Analysis"],
)
async def analyze_apk(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Inspect an uploaded Android APK package (.apk).
    Performs static analysis of package metadata, AndroidManifest permissions,
    SDK targets, and highlights dangerous permission combinations without
    falsely claiming confirmed malware.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing filename. Please upload a valid .apk file.",
        )

    ext = os.path.splitext(file.filename)[1].lower()
    if ext != ".apk":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Only .apk files are accepted for APK security analysis.",
        )

    try:
        content = await _read_upload_bounded(
            file,
            max_bytes=APKSecurityAnalyzer.MAX_SIZE_BYTES,
            label="APK file",
        )
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded APK file is empty (0 bytes).",
            )

        def _analyze_and_enrich_apk() -> APKAnalysisResult:
            res = apk_analyzer.analyze_bytes(content, filename=file.filename)
            res.explanation = _apply_ai_enrichment(
                module_name="APK Security Analyzer",
                target=res.package_name or (file.filename or "package.apk"),
                risk_score=res.risk_score,
                classification=res.classification,
                findings=res.findings,
                explanation=res.explanation,
                metadata=res.metadata,
            )
            return res

        result: APKAnalysisResult = await asyncio.to_thread(_analyze_and_enrich_apk)
    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to analyze APK package: {str(e)}",
        )

    badge = "danger" if result.classification == "High Risk" else ("warning" if result.classification == "Suspicious" else "safe")
    summary = f"Risk Score: {result.risk_score}/100 ({result.classification})"
    record_scan_event(
        "APK",
        file.filename or "package.apk",
        summary,
        badge,
        risk_score=result.risk_score,
        classification=result.classification,
        user_id=current_user.uid,
        details={
            "package_name": result.package_name,
            "app_name": result.app_name,
            "version_name": result.version_name,
            "version_code": result.version_code,
            "min_sdk": result.min_sdk,
            "target_sdk": result.target_sdk,
            "permissions": result.permissions,
            "dangerous_permissions": result.dangerous_permissions,
            "combo_findings": result.combo_findings,
            "findings": result.findings,
            "explanation": result.explanation,
            "recommendation": result.recommendation,
        },
    )

    return APKAnalysisResponse(
        status="inspected",
        scan_type="apk",
        filename=result.filename,
        package_name=result.package_name,
        app_name=result.app_name,
        version_name=result.version_name,
        version_code=result.version_code,
        min_sdk=result.min_sdk,
        target_sdk=result.target_sdk,
        permissions=result.permissions,
        dangerous_permissions=result.dangerous_permissions,
        combo_findings=result.combo_findings,
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.findings,
        detected_indicators=result.detected_indicators,
        explanation=result.explanation,
        finding_explanations=result.finding_explanations,
        recommendation=result.recommendation,
        metadata=result.metadata,
        engine_status=result.engine_status,
    )


# ---------------------------------------------------------------------------
# Permission Analyzer Endpoints
# ---------------------------------------------------------------------------


def _map_permission_result_to_response(
    result: PermissionAnalysisResult,
    user_id: Optional[str] = None,
) -> PermissionAnalysisResponse:
    badge = (
        "safe"
        if result.classification == "Safe"
        else ("warning" if result.classification == "Suspicious" else "danger")
    )
    summary = (
        f"Permissions: {result.dangerous_permissions_count}/{result.total_permissions_count} "
        f"dangerous ({result.classification})"
    )

    record_scan_event(
        scan_type="PERMISSIONS",
        target=result.package_name or result.app_name,
        summary=summary,
        status_badge=badge,
        risk_score=result.risk_score,
        classification=result.classification,
        details={
            "app_name": result.app_name,
            "package_name": result.package_name,
            "total_permissions_count": result.total_permissions_count,
            "dangerous_permissions_count": result.dangerous_permissions_count,
            "dangerous_permissions": result.dangerous_permissions,
            "combo_findings": result.combo_findings,
            "findings": result.findings,
            "recommendation": result.recommendation,
        },
        user_id=user_id,
    )

    return PermissionAnalysisResponse(
        status="analyzed",
        scan_type="permissions",
        package_name=result.package_name,
        app_name=result.app_name,
        version_name=result.version_name,
        version_code=result.version_code,
        min_sdk=result.min_sdk,
        target_sdk=result.target_sdk,
        total_permissions_count=result.total_permissions_count,
        dangerous_permissions_count=result.dangerous_permissions_count,
        permissions=result.permissions,
        dangerous_permissions=result.dangerous_permissions,
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.findings,
        detected_indicators=result.detected_indicators,
        combo_findings=result.combo_findings,
        finding_explanations=result.finding_explanations,
        explanation=result.explanation,
        recommendation=result.recommendation,
        recommendations=result.recommendations,
        metadata=result.metadata,
        engine_status=result.engine_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post(
    "/api/v1/permissions/analyze",
    response_model=PermissionAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze AndroidManifest permissions from an uploaded APK file",
    tags=["Permission Analyzer"],
)
async def analyze_permissions_apk(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Extract and inspect AndroidManifest.xml permissions from an APK file.
    Identifies dangerous permissions, suspicious combinations, computes risk score (0-100),
    and classifies into Safe, Suspicious, High Risk, or Critical.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing filename. Please upload a valid .apk file.",
        )

    ext = os.path.splitext(file.filename)[1].lower()
    if ext != ".apk":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Only .apk files are accepted for permission analysis.",
        )

    try:
        content = await _read_upload_bounded(
            file,
            max_bytes=PermissionAnalyzer.MAX_FILE_SIZE,
            label="APK file",
        )
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded APK file is empty (0 bytes).",
            )

        result: PermissionAnalysisResult = await asyncio.to_thread(
            permission_analyzer.analyze_apk_bytes, content, file.filename
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to analyze APK permissions: {str(e)}",
        )

    return _map_permission_result_to_response(result, user_id=current_user.uid)


@app.post(
    "/api/v1/permissions/analyze-list",
    response_model=PermissionAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze a list of Android permissions (installed app profile)",
    tags=["Permission Analyzer"],
)
async def analyze_permissions_list_endpoint(
    request: PermissionListRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Analyze an array of Android permission strings, such as those extracted
    from an installed application or custom user selection.
    """
    result: PermissionAnalysisResult = permission_analyzer.analyze_permissions_list(
        permissions=request.permissions,
        app_name=request.app_name,
        package_name=request.package_name,
        min_sdk=request.min_sdk or 0,
        target_sdk=request.target_sdk or 0,
        version_name=request.version_name or "1.0",
    )
    return _map_permission_result_to_response(result, user_id=current_user.uid)


@app.post(
    "/api/v1/scan/permissions",
    response_model=PermissionAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Alias: Analyze a list of Android permissions",
    tags=["Permission Analyzer"],
)
async def scan_permissions_alias(
    request: PermissionListRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Scan permissions alias endpoint."""
    return await analyze_permissions_list_endpoint(request, current_user=current_user)


@app.post(
    "/api/v1/permissions/analyze-batch",
    response_model=BatchPermissionAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch analyze permissions of installed applications on an Android device",
    tags=["Permission Analyzer", "Real-Time Android Protection"],
)
async def analyze_installed_apps_batch_endpoint(
    request: BatchPermissionAnalysisRequest,
    current_user: AuthenticatedUser = Depends(get_current_user_optional),
):
    """
    Evaluates permission inventory for multiple installed Android packages.
    Identifies dangerous permission combinations, computes risk profiles,
    and surfaces overall device security posture.
    """
    analyzed_apps: List[InstalledAppAnalysisResult] = []
    high_risk_apps: List[InstalledAppAnalysisResult] = []

    safe_count = 0
    suspicious_count = 0
    high_risk_count = 0
    critical_count = 0
    max_app_risk = 0

    for app in request.apps:
        res: PermissionAnalysisResult = permission_analyzer.analyze_permissions_list(
            permissions=app.permissions,
            app_name=app.app_name,
            package_name=app.package_name,
            min_sdk=app.min_sdk or 0,
            target_sdk=app.target_sdk or 0,
            version_name=app.version_name or "1.0",
        )

        app_item = InstalledAppAnalysisResult(
            package_name=res.package_name,
            app_name=res.app_name,
            version_name=res.version_name,
            is_system_app=bool(app.is_system_app),
            risk_score=res.risk_score,
            classification=res.classification,
            total_permissions_count=res.total_permissions_count,
            dangerous_permissions_count=res.dangerous_permissions_count,
            dangerous_permissions=res.dangerous_permissions,
            combo_findings=res.combo_findings,
            finding_explanations=res.finding_explanations,
            explanation=res.explanation,
            recommendations=res.recommendations,
        )
        analyzed_apps.append(app_item)

        if res.risk_score > max_app_risk:
            max_app_risk = res.risk_score

        if res.risk_score >= 70 or res.classification == "Critical":
            critical_count += 1
            high_risk_apps.append(app_item)
            alert_repo.create_alert(
                title=f"Critical App Risk: {app.app_name}",
                severity="critical",
                category="PERMISSIONS",
                target=app.package_name,
                risk_score=res.risk_score,
                explanation=res.explanation,
                recommended_actions=res.recommendations,
                user_id=current_user.uid,
                event_key=f"{current_user.uid}:{app.package_name}:PERMISSIONS:critical",
            )
        elif res.risk_score >= 50 or res.classification == "High Risk":
            high_risk_count += 1
            high_risk_apps.append(app_item)
            alert_repo.create_alert(
                title=f"High Risk App: {app.app_name}",
                severity="high",
                category="PERMISSIONS",
                target=app.package_name,
                risk_score=res.risk_score,
                explanation=res.explanation,
                recommended_actions=res.recommendations,
                user_id=current_user.uid,
                event_key=f"{current_user.uid}:{app.package_name}:PERMISSIONS:high",
            )
        elif res.risk_score >= 35 or res.classification == "Suspicious":
            suspicious_count += 1
        else:
            safe_count += 1

    if critical_count > 0:
        overall_device_risk_score = min(100, max(75, max_app_risk))
        overall_classification = "Critical"
    elif high_risk_count > 0:
        overall_device_risk_score = min(85, max(50, max_app_risk + (high_risk_count * 3)))
        overall_classification = "High Risk"
    elif suspicious_count > 0:
        overall_device_risk_score = min(49, max(35, max_app_risk + (suspicious_count * 2)))
        overall_classification = "Suspicious"
    else:
        overall_device_risk_score = max(0, min(20, max_app_risk))
        overall_classification = "Safe"

    summary = (
        f"Audited {len(request.apps)} installed applications: "
        f"{critical_count} critical, {high_risk_count} high-risk, {suspicious_count} suspicious, {safe_count} safe. "
        f"Overall device posture: {overall_classification} ({overall_device_risk_score}/100)."
    )

    device_recommendations: List[str] = []
    if critical_count > 0 or high_risk_count > 0:
        device_recommendations.append("Uninstall or revoke sensitive permissions from identified high-risk packages.")
        device_recommendations.append("Ensure accessibility services and overlay permissions are restricted to trusted tools.")
    if suspicious_count > 0:
        device_recommendations.append("Review suspicious apps with elevated background or telephony permissions.")
    if not device_recommendations:
        device_recommendations.append("Installed applications maintain a safe permission profile. Regular audits recommended.")

    record_scan_event(
        scan_type="INSTALLED_APPS",
        target=f"{len(request.apps)} Installed Apps",
        summary=summary,
        status_badge="danger" if overall_device_risk_score >= 50 else ("warning" if overall_device_risk_score >= 35 else "safe"),
        risk_score=overall_device_risk_score,
        classification=overall_classification,
        details={
            "total_apps": len(request.apps),
            "critical_count": critical_count,
            "high_risk_count": high_risk_count,
            "suspicious_count": suspicious_count,
            "safe_count": safe_count,
            "high_risk_packages": [a.package_name for a in high_risk_apps],
        },
        user_id=current_user.uid,
    )

    return BatchPermissionAnalysisResponse(
        status="analyzed",
        scan_type="installed_applications_batch",
        total_apps_analyzed=len(request.apps),
        safe_count=safe_count,
        suspicious_count=suspicious_count,
        high_risk_count=high_risk_count,
        critical_count=critical_count,
        overall_device_risk_score=overall_device_risk_score,
        overall_classification=overall_classification,
        summary=summary,
        high_risk_apps=high_risk_apps,
        all_apps=analyzed_apps,
        recommendations=device_recommendations,
        engine_status="installed_apps_batch_analyzer_active",
    )


def _analyze_phone_heuristics(
    raw_number: str,
    norm_phone: str,
    caller_name: Optional[str] = None,
) -> Tuple[int, List[str], List[str]]:
    """
    Deterministic telecom & spam numbering heuristic analyzer for incoming/manual call checks.
    Detects Indian TRAI telemarketing/commercial series (140 / 160 / 1600), toll-free outbound
    spoofing, high-risk international Wangiri/premium-rate prefixes, synthetic VoIP caller IDs,
    and spam caller-name labels without false-flagging normal local numbers.
    """
    digits = re.sub(r"\D", "", raw_number or norm_phone or "")
    has_intl_plus = (raw_number or "").strip().startswith("+") or (raw_number or "").strip().startswith("00")
    score = 0
    tags: List[str] = []
    reasons: List[str] = []

    # Normalize national Indian form (strip +91 / 91 prefix or leading trunk 0)
    national = digits
    if digits.startswith("91") and len(digits) >= 11:
        national = digits[2:]
    elif digits.startswith("0") and len(digits) >= 10:
        national = digits[1:]

    # 1. Indian TRAI 140 series (official promotional telemarketing spam series)
    if national.startswith("140") and 9 <= len(national) <= 11:
        score = max(score, 75)
        tags.append("trai_140_telemarketing_spam")
        reasons.append(
            "Matches Indian TRAI 140 telemarketing series (registered promotional/spam commercial calling block)."
        )

    # 2. Indian TRAI 160 / 1600 series (automated service/banking/NBFC commercial calling series)
    elif national.startswith("160") and 9 <= len(national) <= 11:
        base_160_score = 55
        if national.startswith("16000") or "000" in national[:6]:
            base_160_score = 65
        score = max(score, base_160_score)
        tags.append("trai_1600_commercial_spam")
        reasons.append(
            "Matches Indian TRAI 160/1600 commercial & automated calling series — frequently used for unsolicited "
            "tele-calling, loan/credit offers, and impersonated bank KYC calls."
        )

    # 3. Toll-free outbound spoofing (1800 / 1860 calling outbound is a classic vishing indicator)
    elif national.startswith(("1800", "1860")) and len(national) >= 10:
        score = max(score, 45)
        tags.append("toll_free_outbound_spoof_risk")
        reasons.append(
            "Toll-free prefix (1800/1860) appearing as an outbound caller ID — legitimate support lines "
            "receive inbound calls; outbound calls requesting OTP/KYC are commonly spoofed."
        )

    # 4. High-risk international Wangiri / satellite / premium-rate prefixes
    if has_intl_plus:
        intl_digits = digits[2:] if (raw_number or "").strip().startswith("00") else digits
        wangiri_prefixes = ("234", "224", "252", "216", "371", "375", "381", "881", "882", "883", "1900", "900")
        if intl_digits.startswith(wangiri_prefixes):
            score = max(score, 70)
            tags.append("wangiri_international_premium_risk")
            reasons.append(
                "Originates from a high-risk international premium-rate or Wangiri one-ring callback scam prefix."
            )

    # 5. Synthetic / spoofed VoIP caller ID anomalies (5+ repeated digits or invalid length)
    if len(digits) < 7 or len(digits) > 15 or re.search(r"(\d)\1{4,}", digits):
        score = max(score, 65)
        tags.append("spoofed_voip_pattern")
        reasons.append(
            "Abnormal or repetitive digit pattern consistent with spoofed VoIP / automated dialer caller IDs."
        )

    # 6. Caller display name spam indicators
    if caller_name:
        low_name = caller_name.lower()
        if any(k in low_name for k in ("spam", "scam", "fraud", "telemarket", "telecaller", "loan offer", "kyc", "lottery")):
            score = max(score, 55)
            tags.append("suspicious_caller_label")
            reasons.append(f"Caller label '{caller_name}' contains known spam/scam telemarketing indicators.")

    return min(100, score), tags, reasons


@app.post(
    "/api/v1/calls/screen",
    response_model=CallScreenResponse,
    status_code=status.HTTP_200_OK,
    summary="Screen incoming phone number against community threat intelligence",
    tags=["Call Screening", "Real-Time Android Protection"],
)
def screen_incoming_call_endpoint(
    request: CallScreenRequest,
    current_user: AuthenticatedUser = Depends(get_current_user_optional),
):
    """
    Screen an incoming or manually entered caller number. Combines verified
    community threat reports with telecom/spam numbering heuristics (TRAI 140/1600,
    toll-free outbound spoofing, Wangiri international prefixes, spoofed VoIP IDs)
    to advise whether to allow, warn, or silence the call.
    """
    raw_number = request.phone_number.strip()
    try:
        norm_phone, display_phone = normalize_target("phone", raw_number)
    except ValueError:
        digits = re.sub(r"[^\d+]", "", raw_number)
        norm_phone = digits if digits.startswith("+") else f"+{digits}"
        display_phone = norm_phone

    rep = community_repo.get_reputation("phone", norm_phone)
    community_score = int(rep.get("suspicion_score") or rep.get("crowd_suspicion_score") or 0)
    verified = bool(rep.get("is_verified_threat") or rep.get("verified_threat") or False)
    report_count = int(rep.get("total_reports") or rep.get("report_count") or 0)
    confidence = str(rep.get("confidence") or "Low")
    raw_tags = rep.get("evidence_tags", [])
    evidence_tags = [t["tag"] if isinstance(t, dict) and "tag" in t else str(t) for t in raw_tags]

    # Run deterministic telecom & spam numbering heuristics
    heuristic_score, heuristic_tags, heuristic_reasons = _analyze_phone_heuristics(
        raw_number=raw_number,
        norm_phone=norm_phone,
        caller_name=request.caller_name,
    )
    for t in heuristic_tags:
        if t not in evidence_tags:
            evidence_tags.append(t)

    spam_score = min(
        100,
        max(community_score, heuristic_score) + (15 if community_score > 0 and heuristic_score > 0 else 0),
    )
    if heuristic_score >= 60 and confidence == "Low":
        confidence = "Medium"

    is_known_spam = verified or spam_score >= 25 or report_count >= 1

    if verified or spam_score >= 70:
        recommended_action = "silence"
        classification = "Critical" if verified else "High Risk"
        detail_parts = []
        if report_count > 0:
            detail_parts.append(f"Confirmed by {report_count} community threat report(s).")
        detail_parts.extend(heuristic_reasons)
        explanation = (
            f"Caller {display_phone} is flagged as a high-risk spam or fraud number. "
            + " ".join(detail_parts)
            + " Recommended to silence or decline."
        )
        alert_repo.create_alert(
            title=f"Spam Call Flagged: {display_phone}",
            severity="critical" if verified else "high",
            category="SPAM_CALLER",
            target=display_phone,
            risk_score=spam_score,
            explanation=explanation,
            recommended_actions=["Decline or silence the call.", "Do not provide personal, banking, or OTP details."],
            user_id=current_user.uid,
            event_key=f"{current_user.uid}:{norm_phone}:CALL:spam",
        )
    elif spam_score >= 50:
        recommended_action = "warn"
        classification = "High Risk"
        detail_parts = []
        if report_count > 0:
            detail_parts.append(f"Reported {report_count} time(s) by community members.")
        detail_parts.extend(heuristic_reasons)
        explanation = (
            f"Caller {display_phone} exhibits high-risk telemarketing or spam indicators. "
            + " ".join(detail_parts)
            + " Exercise strong caution and never share OTPs, PINs, or KYC details."
        )
        alert_repo.create_alert(
            title=f"High-Risk Spam Caller: {display_phone}",
            severity="high",
            category="SPAM_CALLER",
            target=display_phone,
            risk_score=spam_score,
            explanation=explanation,
            recommended_actions=["Avoid answering or silence the call.", "Never reveal passwords, KYC, or OTP codes."],
            user_id=current_user.uid,
            event_key=f"{current_user.uid}:{norm_phone}:CALL:high_risk",
        )
    elif spam_score >= 25 or report_count >= 1:
        recommended_action = "warn"
        classification = "Suspicious"
        detail_parts = []
        if report_count > 0:
            detail_parts.append(f"Reported {report_count} time(s) by community members.")
        detail_parts.extend(heuristic_reasons)
        explanation = (
            f"Caller {display_phone} shows suspicious spam or commercial calling patterns. "
            + " ".join(detail_parts)
        )
        alert_repo.create_alert(
            title=f"Suspicious Caller: {display_phone}",
            severity="medium",
            category="SPAM_CALLER",
            target=display_phone,
            risk_score=spam_score,
            explanation=explanation,
            recommended_actions=["Exercise caution if answering.", "Never reveal passwords or OTP codes."],
            user_id=current_user.uid,
            event_key=f"{current_user.uid}:{norm_phone}:CALL:suspicious",
        )
    else:
        recommended_action = "allow"
        classification = "Safe"
        explanation = (
            f"No spam prefix patterns or community threat reports found for {display_phone}. "
            "If this caller is unsolicited or suspicious, submit a report in Community Reports to warn others."
        )

    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name="call_screening",
        source="communication",
        event_category="spam_call",
        target_identifier=display_phone,
        risk_score=spam_score,
        classification=classification,
        findings=evidence_tags,
        explanation=explanation,
        recommended_actions=[f"Recommended action: {recommended_action}"],
        analysis_status="analyzed",
        create_alert=False,
        metadata={"caller_name": request.caller_name, "report_count": report_count, "recommended_action": recommended_action},
    )

    return CallScreenResponse(
        phone_number=raw_number,
        normalized_number=norm_phone,
        caller_name=request.caller_name,
        is_known_spam=is_known_spam,
        spam_score=spam_score,
        classification=classification,
        confidence=confidence,
        report_count=report_count,
        evidence_tags=evidence_tags,
        recommended_action=recommended_action,
        explanation=explanation,
        engine_status="call_screening_active",
    )


def sanitize_and_redact_notification_text(raw_text: str) -> Tuple[str, bool]:
    """
    Sanitizes notification content by masking sensitive credentials,
    one-time passwords (OTP), credit card numbers, and PINs.
    Returns (sanitized_text, was_redacted).
    """
    if not raw_text:
        return "", False

    redacted = False
    text = raw_text

    cc_pattern = r'\b(?:\d{4}[ -]?){3}\d{1,4}\b'
    if re.search(cc_pattern, text):
        text = re.sub(cc_pattern, "[REDACTED_CARD]", text)
        redacted = True

    # 2. Mask OTP / verification codes (4 to 8 digits)
    otp_pattern = r'(?i)\b(?:code|otp|pin|password|secret|verification code|auth code|passcode)[\s:=#\-]+(\d{4,8})\b'
    def _mask_otp(m: re.Match) -> str:
        nonlocal redacted
        redacted = True
        code = m.group(1)
        masked_code = code[:1] + ("*" * max(1, len(code) - 2)) + code[-1:] if len(code) > 2 else "****"
        return m.group(0).replace(code, masked_code)

    if re.search(otp_pattern, text):
        text = re.sub(otp_pattern, _mask_otp, text)

    # 3. Mask CVV
    cvv_pattern = r'(?i)\bcvv[\s:=]+(\d{3,4})\b'
    if re.search(cvv_pattern, text):
        text = re.sub(cvv_pattern, "cvv: ***", text)
        redacted = True

    # 4. Mask phrase patterns like "OTP is 123456"
    otp_phrase_pattern = r'(?i)\b(?:otp|code|pin)\s+(?:is|was)\s+(\d{4,8})\b'
    def _mask_phrase(m: re.Match) -> str:
        nonlocal redacted
        redacted = True
        code = m.group(1)
        masked = code[:1] + ("*" * max(1, len(code) - 2)) + code[-1:]
        return m.group(0).replace(code, masked)

    if re.search(otp_phrase_pattern, text):
        text = re.sub(otp_phrase_pattern, _mask_phrase, text)

    return text, redacted


@app.post(
    "/api/v1/notifications/analyze",
    response_model=NotificationAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze incoming notification for phishing links, scam language, and fraud",
    tags=["Real-Time Android Protection"],
)
async def analyze_notification_endpoint(
    request: NotificationAnalyzeRequest,
    current_user: AuthenticatedUser = Depends(get_current_user_optional),
):
    """
    Analyzes an incoming Android notification. Extracts embedded URLs,
    evaluates phishing risks and social engineering manipulation,
    redacts private OTPs/cards, and generates immediate security alerts.
    """
    sanitized_title, title_redacted = sanitize_and_redact_notification_text(request.title or "")
    sanitized_text, text_redacted = sanitize_and_redact_notification_text(request.text or "")
    was_redacted = title_redacted or text_redacted

    combined_text = f"{sanitized_title} {sanitized_text} {request.sub_text or ''}".strip()

    raw_content = f"{request.title or ''} {request.text or ''}".strip()
    url_pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
    raw_urls = re.findall(url_pattern, raw_content)
    detected_urls = list(dict.fromkeys(raw_urls))

    url_analyses: List[Dict[str, Any]] = []
    has_phishing_url = False
    max_url_risk = 0

    for u in detected_urls[:5]:
        u_res = url_detector.analyze(u)
        url_analyses.append({
            "url": u,
            "risk_score": u_res.risk_score,
            "classification": u_res.classification,
            "detected_indicators": u_res.detected_indicators,
            "explanation": u_res.explanation,
        })
        if u_res.risk_score > max_url_risk:
            max_url_risk = u_res.risk_score
        if u_res.risk_score >= 50 or u_res.classification in ["High Risk", "Critical"]:
            has_phishing_url = True

    sms_res = sms_detector.analyze(combined_text)
    threat_types = list(sms_res.threat_categories)
    if has_phishing_url and "phishing_url" not in threat_types:
        threat_types.append("phishing_url")

    has_financial_urgency = any(
        "urgency" in c.lower() or "fraud" in c.lower() or "financial" in c.lower() or "coercion" in c.lower()
        for c in threat_types
    )
    has_impersonation = any("impersonat" in c.lower() for c in threat_types)

    overall_risk_score = max(sms_res.risk_score, max_url_risk)
    if has_phishing_url and overall_risk_score < 70:
        overall_risk_score = max(70, overall_risk_score)

    if overall_risk_score >= 70:
        classification = "Critical"
        explanation = (
            f"Notification from '{request.package_name}' exhibits severe threat indicators: "
            f"{', '.join(threat_types) if threat_types else 'Malicious intent detected'}."
        )
        recommended_action = "Do not open, click links, or follow instructions in this notification."
    elif overall_risk_score >= 50:
        classification = "High Risk"
        explanation = (
            f"Notification from '{request.package_name}' contains suspicious links or coercive urgency. "
            f"Identified risks: {', '.join(threat_types)}."
        )
        recommended_action = "Verify the message directly via the organization's official app or portal."
    elif overall_risk_score >= 35:
        classification = "Suspicious"
        explanation = f"Notification from '{request.package_name}' displays possible unsolicited or manipulative patterns."
        recommended_action = "Exercise caution. Do not disclose personal or account information."
    else:
        classification = "Safe"
        explanation = f"No threat indicators found in notification from '{request.package_name}'."
        recommended_action = "Safe to view."

    if overall_risk_score >= 35:
        alert_category = "PHISHING_URL" if has_phishing_url else ("SCAM_SMS" if "sms" in request.package_name.lower() or "messag" in request.package_name.lower() else "NOTIFICATION")
        target_disp = detected_urls[0] if detected_urls else (sanitized_title or sanitized_text[:30])
        alert_repo.create_alert(
            title=f"Suspicious Notification ({request.package_name})",
            severity="critical" if overall_risk_score >= 70 else ("high" if overall_risk_score >= 50 else "medium"),
            category=alert_category,
            target=target_disp,
            risk_score=overall_risk_score,
            explanation=explanation,
            recommended_actions=[recommended_action],
            user_id=current_user.uid,
            event_key=f"{current_user.uid}:{request.package_name}:{target_disp}:{classification}",
        )

    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name="notification_monitor",
        source="communication",
        event_category="notification_threat",
        target_identifier=detected_urls[0] if detected_urls else (sanitized_title or request.package_name),
        risk_score=overall_risk_score,
        classification=classification,
        findings=threat_types,
        explanation=explanation,
        recommended_actions=[recommended_action],
        analysis_status="analyzed",
        create_alert=False,
        metadata={"package_name": request.package_name, "redacted_sensitive_data": was_redacted, "detected_urls_count": len(detected_urls)},
    )

    return NotificationAnalyzeResponse(
        status="analyzed",
        package_name=request.package_name,
        sanitized_text=sanitized_text,
        detected_urls=detected_urls,
        url_analyses=url_analyses,
        sms_risk_score=sms_res.risk_score,
        overall_risk_score=overall_risk_score,
        classification=classification,
        threat_types=threat_types,
        has_phishing_url=has_phishing_url,
        has_financial_urgency=has_financial_urgency,
        has_impersonation=has_impersonation,
        redacted_sensitive_data=was_redacted,
        explanation=explanation,
        recommended_action=recommended_action,
        engine_status="notification_threat_detector_active",
    )


# ---------------------------------------------------------------------------
# Email Threat Scanner Endpoints
# ---------------------------------------------------------------------------


def _map_email_result_to_response(
    result: EmailAnalysisResult,
    user_id: Optional[str] = None,
    is_gmail: bool = False,
) -> EmailScanResponse:
    badge = (
        "safe"
        if result.classification == "Safe"
        else ("warning" if result.classification == "Suspicious" else "danger")
    )
    target_summary = (result.subject or result.sender or result.body[:40]).strip()
    result.explanation = _apply_ai_enrichment(
        module_name="Email Phishing Scanner",
        target=target_summary[:120],
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.findings,
        explanation=result.explanation,
        metadata=result.metadata,
    )
    summary = f"Risk Score: {result.risk_score}/100 ({result.classification})"

    scan_details: Dict[str, Any] = {
        "sender": result.sender,
        "subject": result.subject,
        "threat_categories": result.threat_categories,
        "findings": result.findings,
        "embedded_urls": result.embedded_urls,
        "recommendation": result.recommendation,
    }
    if is_gmail:
        scan_details["module_override"] = "gmail_integration"
        scan_details["source_override"] = "communication"

    record_scan_event(
        scan_type="EMAIL",
        target=target_summary[:80],
        summary=summary,
        status_badge=badge,
        risk_score=result.risk_score,
        classification=result.classification,
        details=scan_details,
        user_id=user_id,
    )

    return EmailScanResponse(
        status="inspected",
        scan_type="email",
        sender=result.sender,
        subject=result.subject,
        body=result.body[:500],
        risk_score=result.risk_score,
        classification=result.classification,
        threat_categories=result.threat_categories,
        detected_indicators=result.detected_indicators,
        findings=result.findings,
        finding_explanations=result.finding_explanations,
        explanation=result.explanation,
        recommendation=result.recommendation,
        recommendations=result.recommendations,
        embedded_urls=result.embedded_urls,
        url_scan_results=result.url_scan_results,
        metadata=result.metadata,
        engine_status=result.engine_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post(
    "/api/v1/email/scan",
    response_model=EmailScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan email text, sender, and subject for phishing and malicious links",
    tags=["Email Scanner"],
)
def scan_email_endpoint(
    request: EmailScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Analyze email content, sender headers, subject line, urgency manipulation,
    and embedded links for phishing indicators.
    """
    result: EmailAnalysisResult = email_detector.analyze(
        body=request.body,
        sender=request.sender,
        subject=request.subject,
        reply_to=request.reply_to,
    )
    return _map_email_result_to_response(result, user_id=current_user.uid)


@app.post(
    "/api/v1/scan/email",
    response_model=EmailScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Alias: Scan email for phishing and malicious links",
    tags=["Email Scanner"],
)
def scan_email_alias(
    request: EmailScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Scan email alias endpoint."""
    return scan_email_endpoint(request, current_user=current_user)


@app.post(
    "/api/v1/scan/gmail-message",
    response_model=EmailScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan ingested Gmail message for phishing lures and suspicious embedded URLs",
    tags=["Email Scanner"],
)
def scan_gmail_message_endpoint(
    request: GmailMessageScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Dedicated endpoint for Gmail OAuth integration.
    Performs deep heuristic phishing detection on messages fetched from Gmail API.
    """
    result: EmailAnalysisResult = email_detector.analyze(
        body=request.body,
        sender=request.sender,
        subject=request.subject,
        reply_to=request.reply_to,
    )
    result.metadata["gmail_message_id"] = request.message_id
    if request.date:
        result.metadata["email_date"] = request.date
    return _map_email_result_to_response(result, user_id=current_user.uid, is_gmail=True)


# ---------------------------------------------------------------------------
# File Threat Scanner Endpoints
# ---------------------------------------------------------------------------


def _map_file_result_to_response(
    result: FileAnalysisResult,
    user_id: Optional[str] = None,
) -> FileScanResponse:
    badge = (
        "safe"
        if result.classification == "Safe"
        else ("warning" if result.classification == "Suspicious" else "danger")
    )
    summary = f"Risk Score: {result.risk_score}/100 ({result.classification})"

    record_scan_event(
        scan_type="FILE",
        target=result.filename,
        summary=summary,
        status_badge=badge,
        risk_score=result.risk_score,
        classification=result.classification,
        details={
            "filename": result.filename,
            "file_size_bytes": result.file_size_bytes,
            "detected_mime": result.detected_mime,
            "file_extension": result.file_extension,
            "threat_categories": result.threat_categories,
            "findings": result.findings,
            "archive_contents": result.archive_contents,
            "recommendation": result.recommendation,
        },
        user_id=user_id,
    )

    return FileScanResponse(
        status="inspected",
        scan_type="file",
        filename=result.filename,
        file_size_bytes=result.file_size_bytes,
        detected_mime=result.detected_mime,
        file_extension=result.file_extension,
        is_archive=result.is_archive,
        risk_score=result.risk_score,
        classification=result.classification,
        threat_categories=result.threat_categories,
        detected_indicators=result.detected_indicators,
        findings=result.findings,
        finding_explanations=result.finding_explanations,
        explanation=result.explanation,
        recommendation=result.recommendation,
        recommendations=result.recommendations,
        archive_contents=result.archive_contents,
        md5=result.md5,
        sha1=result.sha1,
        sha256=result.sha256,
        metadata=result.metadata,
        engine_status=result.engine_status,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post(
    "/api/v1/file/scan",
    response_model=FileScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan uploaded file for deceptive signatures, dangerous scripts, and archives",
    tags=["File Scanner"],
)
async def scan_file_endpoint(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Perform static heuristic inspection on uploaded files without execution:
    validates magic bytes, detects double extensions, examines archive contents safely,
    and detects stealth scripting commands.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is missing from upload request.",
        )

    # Sanitize filename to prevent path traversal
    safe_filename = os.path.basename(file.filename)
    if not safe_filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename supplied.",
        )

    try:
        content = await _read_upload_bounded(
            file,
            max_bytes=FileThreatDetector.MAX_FILE_SIZE,
            label="File",
        )
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes).",
            )

        def _analyze_and_enrich_file() -> FileAnalysisResult:
            res = file_detector.analyze_bytes(
                file_bytes=content,
                filename=safe_filename,
                content_type=file.content_type,
            )
            res.explanation = _apply_ai_enrichment(
                module_name="File Threat Scanner",
                target=res.filename,
                risk_score=res.risk_score,
                classification=res.classification,
                findings=res.findings,
                explanation=res.explanation,
                metadata=res.metadata,
            )
            return res

        result: FileAnalysisResult = await asyncio.to_thread(_analyze_and_enrich_file)
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to analyze file: {str(e)}",
        )

    return _map_file_result_to_response(result, user_id=current_user.uid)


@app.post(
    "/api/v1/scan/file",
    response_model=FileScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Alias: Scan uploaded file for threats",
    tags=["File Scanner"],
)
async def scan_file_alias(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Scan file alias endpoint."""
    return await scan_file_endpoint(file=file, current_user=current_user)


def _build_qr_scan_payload(raw_payload: str, user_id: Optional[str] = None) -> QRScanResponse:
    """Run QRThreatDetector and compile structured response."""
    result: QRAnalysisResult = qr_detector.analyze(raw_payload)
    result.explanation = _apply_ai_enrichment(
        module_name="QR Content Security Scanner",
        target=result.decoded_payload[:120],
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.findings,
        explanation=result.explanation,
        metadata=result.metadata,
    )

    # Record scan into audit history
    badge = result.classification.lower()
    summary = f"Risk Score: {result.risk_score}/100 ({result.classification})"
    record_scan_event(
        "QR",
        f"{raw_payload[:60]}...",
        summary,
        badge,
        risk_score=result.risk_score,
        classification=result.classification,
        user_id=user_id,
        details={
            "content_type": result.content_type,
            "decoded_payload": result.decoded_payload,
            "findings": result.findings,
            "explanation": result.explanation,
            "recommendation": result.recommendation,
            "detected_indicators": result.detected_indicators,
            "metadata": result.metadata,
        },
    )

    return QRScanResponse(
        status="inspected",
        scan_type="qr",
        content_type=result.content_type,
        decoded_payload=result.decoded_payload,
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.findings,
        detected_indicators=result.detected_indicators,
        explanation=result.explanation,
        finding_explanations=result.finding_explanations,
        recommendation=result.recommendation,
        metadata=result.metadata,
        engine_status="qr_threat_inspector_active",
    )


@app.post(
    "/api/v1/qr/scan",
    response_model=QRScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan decoded QR code payload for threats (POST /api/v1/qr/scan)",
    tags=["QR Threat Detection"],
)
def scan_qr_payload(
    request: QRScanRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Analyse a decoded QR code payload for cyber threats:
    - URL payloads: full heuristic threat detection via URLThreatDetector
    - UPI payment links: payee validation, fraud pattern analysis
    - vCard / Contact: embedded URL and phishing keyword inspection
    - WiFi: suspicious SSID / open network detection
    - Plain text: phishing keyword analysis

    Returns risk_score (0-100), classification (Safe/Suspicious/Malicious),
    granular findings, and actionable recommendations.
    """
    try:
        clean_payload = request.get_clean_payload()
        return _build_qr_scan_payload(clean_payload, user_id=current_user.uid)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to inspect QR payload: {str(e)}",
        )


@app.post(
    "/api/v1/qr/scan-image",
    response_model=QRScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Decode QR code from uploaded image and analyze for threats (POST /api/v1/qr/scan-image)",
    tags=["QR Threat Detection"],
)
async def scan_qr_image_upload(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Decodes a 2D QR code barcode or barcode pattern from an uploaded image
    using computer vision (OpenCV QRCodeDetector) with OCR fallback, and audits
    the resulting payload for cybersecurity threats.
    """
    try:
        content = await _read_upload_bounded(
            file,
            max_bytes=15 * 1024 * 1024,
            label="QR image",
        )
        def _decode_and_scan_qr_image() -> QRScanResponse:
            import cv2
            import numpy as np

            np_arr = np.frombuffer(content, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

            decoded_payload = ""
            if img is not None:
                detector = cv2.QRCodeDetector()
                val, pts, _ = detector.detectAndDecode(img)
                if val and val.strip():
                    decoded_payload = val.strip()
                else:
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    val_gray, _, _ = detector.detectAndDecode(gray)
                    if val_gray and val_gray.strip():
                        decoded_payload = val_gray.strip()

            if not decoded_payload:
                ocr_res = screenshot_detector.analyze_image_bytes(content, filename=file.filename or "qr.png")
                ocr_text = getattr(ocr_res, "ocr_text", "") or getattr(ocr_res, "extracted_text", "")
                if ocr_res.extracted_urls:
                    decoded_payload = ocr_res.extracted_urls[0]
                elif ocr_text.strip():
                    decoded_payload = ocr_text.strip()
                else:
                    return QRScanResponse(
                        content_type="UNRECOGNIZED",
                        decoded_payload="No legible QR barcode recognized",
                        risk_score=0,
                        classification="Unverified",
                        status="unrecognized",
                        detected_indicators=[],
                        findings=["No legible QR code barcode or embedded link could be recognized in the image."],
                        explanation="The uploaded image does not contain a decipherable 2D QR barcode.",
                        finding_explanations=[],
                        recommendation="Center the QR code inside the live scanner frame with good lighting, or paste the payload manually.",
                        metadata={"filename": file.filename},
                        engine_status="qr_cv_decoder_active",
                    )

            return _build_qr_scan_payload(decoded_payload, user_id=current_user.uid)

        return await asyncio.to_thread(_decode_and_scan_qr_image)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to decode QR image: {str(e)}",
        )


@app.post("/api/v1/scan/qr", response_model=SMSScanResultResponse, tags=["Scanners"])
async def scan_qr(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Inspect QR code image file upload."""
    findings = [
        f"QR code image received: {file.filename}",
        "Computer vision barcode decoder active",
    ]
    summary = f"QR image uploaded: {file.filename}"
    record_scan_event(
        "QR",
        file.filename or "qr_code.png",
        summary,
        "info",
        user_id=current_user.uid,
    )

    return SMSScanResultResponse(
        status="received",
        scan_type="qr",
        target=file.filename or "qr.png",
        timestamp=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        metadata={"filename": file.filename},
        engine_status="cv_decoder_ready",
    )


@app.post(
    "/api/v1/screenshot/analyze",
    response_model=ScreenshotAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze screenshot image for cyber threats (POST /api/v1/screenshot/analyze)",
    tags=["Screenshot Threat Detection"],
)
async def analyze_screenshot(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Extract textual tokens from uploaded screenshot image using OCR
    and inspect for phishing, fake bank/KYC alerts, OTP theft, suspicious URLs,
    and payment deception.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid image file must be uploaded.",
        )

    ext = os.path.splitext(file.filename)[1].lower()
    allowed_exts = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff"}
    if ext and ext not in allowed_exts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '{ext}'. Allowed image formats: {', '.join(allowed_exts)}",
        )

    try:
        content = await _read_upload_bounded(
            file,
            max_bytes=15 * 1024 * 1024,
            label="Screenshot image",
        )
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes).",
            )
        result: ScreenshotAnalysisResult = await asyncio.to_thread(
            screenshot_detector.analyze_image_bytes, content, file.filename
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to process screenshot: {str(e)}",
        )

    badge = result.classification.lower()
    summary = f"Risk Score: {result.risk_score}/100 ({result.classification})"
    record_scan_event(
        "SCREENSHOT",
        file.filename or "screenshot.png",
        summary,
        badge,
        risk_score=result.risk_score,
        classification=result.classification,
        user_id=current_user.uid,
        details={
            "filename": result.filename,
            "ocr_text": result.ocr_text,
            "findings": result.findings,
            "explanation": result.explanation,
            "recommendation": result.recommendation,
            "detected_indicators": result.detected_indicators,
            "threat_categories": result.threat_categories,
            "extracted_urls": result.extracted_urls,
        },
    )

    return ScreenshotAnalysisResponse(
        status="inspected",
        scan_type="screenshot",
        filename=result.filename,
        ocr_text=result.ocr_text,
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=result.risk_score,
        classification=result.classification,
        findings=result.findings,
        detected_indicators=result.detected_indicators,
        explanation=result.explanation,
        finding_explanations=result.finding_explanations,
        recommendation=result.recommendation,
        extracted_urls=result.extracted_urls,
        threat_categories=result.threat_categories,
        metadata=result.metadata,
        engine_status=result.engine_status,
    )


@app.post("/api/v1/scan/screenshot", response_model=SMSScanResultResponse, tags=["Scanners"])
async def scan_screenshot(
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Inspect screenshot image file upload."""
    findings = [
        f"Screenshot received: {file.filename}",
        "OCR text extraction and UI layout scanner ready",
    ]
    summary = f"Screenshot uploaded: {file.filename}"
    record_scan_event(
        "SCREENSHOT",
        file.filename or "screen.png",
        summary,
        "info",
        user_id=current_user.uid,
    )

    return SMSScanResultResponse(
        status="received",
        scan_type="screenshot",
        target=file.filename or "screenshot.png",
        scanned_message=f"Screenshot image: {file.filename}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        risk_score=0,
        classification="Safe",
        explanation="Legacy screenshot endpoint stub received the file.",
        recommendation="Use POST /api/v1/screenshot/analyze for OCR threat analysis.",
        findings=findings,
        metadata={"filename": file.filename},
        engine_status="ocr_pipeline_ready",
    )


@app.get(
    "/api/v1/history",
    response_model=HistoryResponse,
    tags=["History"],
    summary="Retrieve audit scan history with filtering (GET /api/v1/history)",
)
async def get_history(
    scan_type: Optional[str] = Query(None, description="Filter by scan type: URL, SMS, QR, SCREENSHOT, APK"),
    classification: Optional[str] = Query(None, description="Filter by classification: Safe, Suspicious, Malicious, High Risk"),
    limit: int = Query(100, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Retrieve scan history from persistent SQLite database with optional
    filtering by scan type and threat classification.
    """
    scans = history_repo.get_all(
        scan_type=scan_type,
        classification=classification,
        limit=limit,
        offset=offset,
    )
    total_count = history_repo.count()
    filtered_count = history_repo.count(scan_type=scan_type, classification=classification)

    return HistoryResponse(
        total_count=total_count,
        filtered_count=filtered_count,
        scans=scans,
    )


@app.get(
    "/api/v1/history/{scan_id}",
    response_model=HistoryDetailResponse,
    tags=["History"],
    summary="Retrieve a single scan record by ID (GET /api/v1/history/{scan_id})",
)
async def get_history_detail(
    scan_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve full details of a specific scan by its scan_id."""
    record = history_repo.get_by_id(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )
    return HistoryDetailResponse(**record)


@app.delete(
    "/api/v1/history/{scan_id}",
    response_model=HistoryDeleteResponse,
    tags=["History"],
    summary="Delete a scan record by ID (DELETE /api/v1/history/{scan_id})",
)
async def delete_history_item(
    scan_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Remove a single scan record from persistent SQLite storage and cache."""
    deleted = history_repo.delete_by_id(scan_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )
    # Remove from in-memory cache
    global SCAN_HISTORY
    SCAN_HISTORY[:] = [
        s for s in SCAN_HISTORY
        if s.get("id") != scan_id and s.get("scan_id") != scan_id
    ]
    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name="audit_history",
        source="system_event",
        event_category="audit_record",
        target_identifier=scan_id,
        risk_score=0,
        classification="Safe",
        explanation=f"Audit history record '{scan_id}' deleted by user.",
        recommended_actions=["Audit trail updated."],
        analysis_status="analyzed",
        create_alert=False,
        metadata={"action": "delete_history_item", "scan_id": scan_id},
    )
    return HistoryDeleteResponse(
        status="deleted",
        scan_id=scan_id,
        message=f"Scan record '{scan_id}' successfully removed from audit history.",
    )


# ---------------------------------------------------------------------------
# Community Threat Reporting & Reputation Endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/api/v1/community/report",
    response_model=CommunityReportResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Community Reporting"],
    summary="Submit a community threat report",
)
async def submit_community_report(
    request: CommunityReportCreateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Submit a crowd-sourced threat report for a phone number, SMS message,
    URL, QR payload, email, or application.
    Protected with Firebase authentication.
    Applies rate limiting (max 10 / 10m) and 24-hour duplicate prevention.
    """
    try:
        created = community_repo.submit_report(
            category=request.category,
            raw_target=request.target,
            title=request.title,
            description=request.description or "",
            tags=request.tags,
            user_uid=current_user.uid,
        )
        rep = community_repo.get_reputation(created["category"], created["target"])
        crowd_score = int(rep.get("suspicion_score") or rep.get("crowd_suspicion_score") or 45)
        smart_event_engine.safe_record(
            user_id=current_user.uid,
            module_name="community_threat_intel",
            source="community",
            event_category="community_report",
            target_identifier=created["target"],
            risk_score=max(45, crowd_score),
            findings=list(request.tags or []),
            explanation=f"Community threat report submitted for {created['category']}: {request.title}.",
            recommended_actions=["Avoid interacting with reported target until verified."],
            analysis_status="analyzed",
            create_alert=True,
            metadata={"report_id": created["id"], "category": created["category"], "total_reports": rep.get("total_reports", 1)},
        )
        return CommunityReportResponse(**created)
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(pe),
        )
    except ValueError as ve:
        err_msg = str(ve)
        if "Duplicate report" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=err_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err_msg,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred while recording community report: {str(e)}",
        )


@app.get(
    "/api/v1/community/reports",
    response_model=CommunityReportListResponse,
    tags=["Community Reporting"],
    summary="List recent community threat reports with optional filtering",
)
async def list_community_reports(
    category: Optional[str] = Query(None, description="Filter by category: phone, sms, url, qr, email, app"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: PENDING, UNDER_REVIEW, VERIFIED_THREAT, REJECTED"),
    search: Optional[str] = Query(None, description="Search term for target or title"),
    limit: int = Query(50, ge=1, le=200, description="Max reports to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Retrieve community threat reports.
    Reporter private information (UID, email) is never exposed.
    """
    reports_data = community_repo.get_reports(
        category=category,
        status=status_filter,
        search_query=search,
        limit=limit,
        offset=offset,
    )
    # Fetch reputation summaries for each report
    detailed_reports = []
    for r in reports_data:
        rep = community_repo.get_reputation(r["category"], r["target"])
        detailed_reports.append(CommunityReportResponse(**r, reputation=CommunityReputationResponse(**rep)))

    return CommunityReportListResponse(
        total_count=len(detailed_reports),
        reports=detailed_reports,
    )


@app.get(
    "/api/v1/community/reports/{report_id}",
    response_model=CommunityReportResponse,
    tags=["Community Reporting"],
    summary="Get single community report details by ID",
)
async def get_community_report(
    report_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve full details of a specific community report by report_id."""
    report = community_repo.get_report_by_id(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Community report '{report_id}' not found.",
        )
    return CommunityReportResponse(**report)


@app.get(
    "/api/v1/community/reputation",
    response_model=CommunityReputationResponse,
    tags=["Community Reporting"],
    summary="Lookup community reputation for a target",
)
async def get_community_reputation(
    category: str = Query(..., description="Target category: phone, sms, url, qr, email, app"),
    target: str = Query(..., min_length=1, description="Target string or identifier to check"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Query community reputation for a given target.
    Calculates crowd suspicion score (0-100, unverified capped at 75),
    confidence level, evidence tags, and verified threat flag.
    """
    try:
        norm_tgt, _ = normalize_target(category, target)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    rep = community_repo.get_reputation(category, norm_tgt)
    crowd_score = int(rep.get("suspicion_score") or rep.get("crowd_suspicion_score") or 0)
    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name="community_threat_intel",
        source="community",
        event_category="reputation_lookup",
        target_identifier=norm_tgt,
        risk_score=crowd_score,
        findings=[t["tag"] if isinstance(t, dict) and "tag" in t else str(t) for t in rep.get("evidence_tags", [])],
        explanation=f"Community reputation lookup for {category} '{norm_tgt}': score {crowd_score}/100 ({rep.get('total_reports', 0)} report(s)).",
        recommended_actions=["Verify source authenticity before engaging."] if crowd_score >= 41 else ["No community threat reports recorded."],
        analysis_status="analyzed",
        create_alert=crowd_score >= 61,
        metadata={"category": category, "verified_threat": bool(rep.get("is_verified_threat") or rep.get("verified_threat"))},
    )
    return CommunityReputationResponse(**rep)


@app.get(
    "/api/v1/community/stats",
    response_model=CommunityStatsResponse,
    tags=["Community Reporting"],
    summary="Get aggregated community threat statistics",
)
async def get_community_stats(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve macro-level community threat metrics across all categories."""
    stats = community_repo.get_stats()
    return CommunityStatsResponse(**stats)


# ---------------------------------------------------------------------------
# AI Security Assistant Endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/api/v1/assistant/chat",
    response_model=AssistantChatResponse,
    status_code=status.HTTP_200_OK,
    tags=["AI Security Assistant"],
    summary="Chat with CyberShield AI Security Assistant",
)
async def assistant_chat(
    request: AssistantChatRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Interact with CyberShield AI Assistant for threat explanations,
    cyber defense advice, and security awareness.
    Protected with Firebase ID token. Enforces rate limits & prompt injection guards.
    """
    try:
        ctx_dict = request.scan_context.model_dump() if request.scan_context else None
        result = await assistant_service.chat(
            user_uid=current_user.uid,
            message=request.message,
            session_id=request.session_id,
            scan_context=ctx_dict,
            language=request.language or "en",
        )
        ctx_score = int((ctx_dict or {}).get("risk_score") or 0)
        ctx_target = str((ctx_dict or {}).get("target") or request.message[:60])
        smart_event_engine.safe_record(
            user_id=current_user.uid,
            module_name="ai_security_assistant",
            source="assistant",
            event_category="ai_advisory",
            target_identifier=ctx_target,
            risk_score=ctx_score,
            explanation=str(result.get("reply") or "AI security advisory generated.")[:240],
            recommended_actions=list(result.get("recommendations") or [])[:4],
            analysis_status="analyzed",
            create_alert=False,
            metadata={"session_id": result.get("session_id"), "has_scan_context": ctx_dict is not None},
        )
        return AssistantChatResponse(**result)
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(pe),
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Assistant failed to process inquiry: {str(e)}",
        )


@app.post(
    "/api/v1/assistant/explain-scan",
    response_model=AssistantChatResponse,
    status_code=status.HTTP_200_OK,
    tags=["AI Security Assistant"],
    summary="Generate targeted AI threat explanation for a scan result",
)
async def assistant_explain_scan(
    request: ScanContextInput,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Convenience endpoint to immediately explain a URL, SMS, QR, Email, File,
    or APK scan result without requiring a manual user prompt.
    """
    prompt = (
        f"Explain this {request.scan_type} scan result: target '{request.target}', "
        f"risk score {request.risk_score}/100, classification '{request.classification}'. "
        f"Explain the technical risks and give me step-by-step recommendations."
    )
    try:
        result = await assistant_service.chat(
            user_uid=current_user.uid,
            message=prompt,
            scan_context=request.model_dump(),
        )
        smart_event_engine.safe_record(
            user_id=current_user.uid,
            module_name="ai_security_assistant",
            source="assistant",
            event_category="ai_scan_explanation",
            target_identifier=request.target,
            risk_score=int(request.risk_score or 0),
            classification=request.classification,
            explanation=str(result.get("reply") or "Scan explanation generated.")[:240],
            recommended_actions=list(result.get("recommendations") or [])[:4],
            analysis_status="analyzed",
            create_alert=False,
            metadata={"scan_type": request.scan_type, "session_id": result.get("session_id")},
        )
        return AssistantChatResponse(**result)
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(pe),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to explain scan: {str(e)}",
        )


@app.get(
    "/api/v1/assistant/history",
    response_model=AssistantHistoryResponse,
    tags=["AI Security Assistant"],
    summary="Retrieve user-specific assistant chat history",
)
async def get_assistant_history(
    session_id: Optional[str] = Query(None, description="Optional session filter"),
    limit: int = Query(50, ge=1, le=100, description="Max messages to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve chat history isolated to the authenticated Firebase user."""
    history = assistant_service.history_repo.get_history(
        user_id=current_user.uid,
        session_id=session_id,
        limit=limit,
        offset=offset,
    )
    return AssistantHistoryResponse(
        user_id=current_user.uid,
        session_id=session_id,
        total_messages=len(history),
        messages=history,
    )


@app.delete(
    "/api/v1/assistant/history",
    response_model=AssistantClearHistoryResponse,
    tags=["AI Security Assistant"],
    summary="Clear user-specific assistant chat history",
)
async def clear_assistant_history(
    session_id: Optional[str] = Query(None, description="Optional session filter"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Delete chat history for the authenticated user from SQLite."""
    count = assistant_service.history_repo.clear_history(
        user_id=current_user.uid,
        session_id=session_id,
    )
    return AssistantClearHistoryResponse(
        status="cleared",
        deleted_count=count,
        message=f"Successfully purged {count} chat messages.",
    )


# ---------------------------------------------------------------------------
# Security Dashboard & Analytics Endpoints
# ---------------------------------------------------------------------------


@app.get(
    "/api/v1/analytics/dashboard",
    response_model=DashboardAnalyticsResponse,
    status_code=status.HTTP_200_OK,
    tags=["Security Analytics"],
    summary="Retrieve comprehensive security dashboard analytics",
)
async def get_dashboard_analytics(
    days: int = Query(30, ge=0, le=365, description="Analysis window in days (0 for all-time)"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Retrieve aggregated security telemetry, risk distribution, trends,
    transparent CyberShield security score, scanner breakdown, and community metrics.
    User-isolated: returns metrics corresponding to the authenticated Firebase UID.
    """
    data = analytics_service.get_dashboard_analytics(
        user_id=current_user.uid,
        days=days,
    )
    score_obj = data.get("security_score")
    posture_val = int(score_obj.get("score", 100)) if isinstance(score_obj, dict) else int(score_obj or 100)
    summary_obj = data.get("summary")
    total_scans_val = int(summary_obj.get("total_scans", 0)) if isinstance(summary_obj, dict) else int(data.get("total_scans", 0))
    hour_bucket = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name="dashboard_analytics",
        source="system_event",
        event_category="analytics_telemetry",
        target_identifier=f"dashboard_{days}d",
        risk_score=max(0, min(100, 100 - posture_val)),
        explanation=(
            f"Dashboard security telemetry evaluated ({days}d window): "
            f"posture score {posture_val}/100 across {total_scans_val} scan(s)."
        ),
        recommended_actions=["Review unified analytics for module-wise threat breakdown."],
        analysis_status="analyzed",
        idempotency_key=f"dash:{days}:{hour_bucket}",
        create_alert=False,
        metadata={"days": days, "security_score": posture_val},
    )
    return DashboardAnalyticsResponse(**data)


# ---------------------------------------------------------------------------
# Security Alerts Models & Endpoints
# ---------------------------------------------------------------------------

class CreateAlertRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    severity: str = Field(..., description="critical, high, medium, low, info")
    category: str = Field(..., description="URL, SMS, QR, APK, PERMISSIONS, EMAIL, FILE, COMMUNITY, SYSTEM")
    target: str = Field(..., min_length=1, max_length=1024)
    risk_score: int = Field(0, ge=0, le=100)
    explanation: str = Field(..., min_length=1)
    recommended_actions: List[str] = Field(default_factory=list)
    scan_id: Optional[str] = None
    event_key: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class SecurityAlertResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    scan_id: Optional[str] = None
    event_key: Optional[str] = None
    title: str
    severity: str
    category: str
    target: str
    risk_score: int
    explanation: str
    recommended_actions: List[str] = Field(default_factory=list)
    status: str
    is_read: bool
    is_resolved: bool
    timestamp: str
    resolved_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertStatsResponse(BaseModel):
    total: int
    unread: int
    critical: int
    high: int
    medium: int
    low: int
    resolved: int


class AlertListResponse(BaseModel):
    status: str = "success"
    alerts: List[SecurityAlertResponse]
    stats: AlertStatsResponse
    total_returned: int


@app.get(
    "/api/v1/alerts",
    response_model=AlertListResponse,
    status_code=status.HTTP_200_OK,
    tags=["Security Alerts"],
    summary="Retrieve user-isolated security alerts with optional filtering",
)
async def list_security_alerts(
    severity: Optional[str] = Query(None, description="critical, high, medium, low, info"),
    is_read: Optional[bool] = Query(None, description="Filter by read/unread state"),
    is_resolved: Optional[bool] = Query(None, description="Filter by resolved state"),
    limit: int = Query(50, ge=1, le=200),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List security alerts isolated to authenticated Firebase user."""
    alerts = alert_repo.list_alerts(
        user_id=current_user.uid,
        severity=severity,
        is_read=is_read,
        is_resolved=is_resolved,
        limit=limit,
    )
    stats = alert_repo.get_alert_stats(user_id=current_user.uid)
    return AlertListResponse(
        status="success",
        alerts=[SecurityAlertResponse(**a) for a in alerts],
        stats=AlertStatsResponse(**stats),
        total_returned=len(alerts),
    )


@app.get(
    "/api/v1/alerts/stats",
    response_model=AlertStatsResponse,
    status_code=status.HTTP_200_OK,
    tags=["Security Alerts"],
    summary="Retrieve security alerts counts and unread badges",
)
async def get_security_alerts_stats(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve aggregate alert stats for authenticated user."""
    stats = alert_repo.get_alert_stats(user_id=current_user.uid)
    return AlertStatsResponse(**stats)


@app.get(
    "/api/v1/alerts/{alert_id}",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    tags=["Security Alerts"],
    summary="Retrieve details and remediation actions for a specific alert",
)
async def get_security_alert_detail(
    alert_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve detailed explanation and recommended actions for a specific alert."""
    alert = alert_repo.get_alert(alert_id=alert_id, user_id=current_user.uid)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return SecurityAlertResponse(**alert)


@app.patch(
    "/api/v1/alerts/{alert_id}/read",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    tags=["Security Alerts"],
    summary="Mark an alert as read or unread",
)
async def mark_alert_read(
    alert_id: str,
    is_read: bool = Query(True, description="Target read status"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update read status of an alert."""
    alert = alert_repo.mark_as_read(alert_id=alert_id, user_id=current_user.uid, is_read=is_read)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    return SecurityAlertResponse(**alert)


@app.patch(
    "/api/v1/alerts/{alert_id}/resolve",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_200_OK,
    tags=["Security Alerts"],
    summary="Mark an alert as resolved or unresolved",
)
async def mark_alert_resolved(
    alert_id: str,
    is_resolved: bool = Query(True, description="Target resolved status"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update resolved status of an alert."""
    alert = alert_repo.mark_as_resolved(alert_id=alert_id, user_id=current_user.uid, is_resolved=is_resolved)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{alert_id}' not found.",
        )
    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name="security_alerts",
        source="system_event",
        event_category="alert_lifecycle",
        target_identifier=alert.get("target") or alert_id,
        risk_score=0 if is_resolved else int(alert.get("risk_score") or 0),
        explanation=f"Alert '{alert.get('title', alert_id)}' marked as {'resolved' if is_resolved else 'unresolved'}.",
        recommended_actions=["Continue monitoring for recurring indicators."],
        analysis_status="analyzed",
        create_alert=False,
        metadata={"alert_id": alert_id, "is_resolved": is_resolved},
    )
    return SecurityAlertResponse(**alert)


@app.post(
    "/api/v1/alerts",
    response_model=SecurityAlertResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Security Alerts"],
    summary="Create or deduplicate a security alert",
)
async def create_security_alert(
    req: CreateAlertRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Create a security alert with automatic deduplication."""
    alert = alert_repo.create_alert(
        title=req.title,
        severity=req.severity,
        category=req.category,
        target=req.target,
        risk_score=req.risk_score,
        explanation=req.explanation,
        recommended_actions=req.recommended_actions,
        user_id=current_user.uid,
        scan_id=req.scan_id,
        event_key=req.event_key,
        metadata=req.metadata,
    )
    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name="security_alerts",
        source="system_event",
        event_category="alert_lifecycle",
        target_identifier=req.target,
        risk_score=req.risk_score,
        explanation=f"Security alert recorded: {req.title} — {req.explanation}",
        recommended_actions=req.recommended_actions,
        analysis_status="analyzed",
        create_alert=False,
        metadata={"alert_id": alert["id"], "category": req.category, "severity": req.severity},
    )
    return SecurityAlertResponse(**alert)


# ---------------------------------------------------------------------------
# Communication History & Threat Percentage Tracking API
# ---------------------------------------------------------------------------

class CommunicationIngestRequest(BaseModel):
    communication_type: str = Field(
        ..., description="One of: sms, notification, call, email, whatsapp, other"
    )
    source_app: str = Field(..., min_length=1, max_length=120)
    sender_identifier: str = Field(..., min_length=1, max_length=256)
    caller_name: Optional[str] = Field(None, max_length=256)
    subject: Optional[str] = Field(None, max_length=500)
    content: Optional[str] = Field(None, max_length=10000)
    timestamp: Optional[str] = None
    store_preview: bool = True
    is_known_contact: Optional[bool] = None
    call_status: Optional[str] = None
    external_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class CommunicationRecordResponse(BaseModel):
    record_id: str
    user_id: str
    communication_type: str
    source_app: str
    sender_identifier: str
    caller_name: Optional[str] = None
    message_preview: str = ""
    timestamp: str
    risk_score: int
    classification: str
    threat_categories: List[str] = []
    findings: List[str] = []
    explanation: str = ""
    recommended_action: str = ""
    analysis_status: str = "analyzed"
    is_known_contact: Optional[bool] = None
    call_status: Optional[str] = None
    spam_reputation: Optional[str] = None
    metadata: Dict[str, Any] = {}
    is_duplicate: bool = False


class CommunicationHistoryListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    has_more: bool
    records: List[CommunicationRecordResponse]


@app.post(
    "/api/v1/communications/ingest",
    response_model=CommunicationRecordResponse,
    status_code=status.HTTP_200_OK,
    tags=["Communication History"],
    summary="Analyze and record an eligible incoming communication (SMS, notification, call, email, WhatsApp)",
)
async def ingest_communication_endpoint(
    req: CommunicationIngestRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Analyzes any eligible incoming communication using CyberShield's real deterministic
    threat engines (SMS, URL, Email, Community Phone Reputation), applies 0-100 risk
    percentage scoring, redacts sensitive secrets/OTPs, deduplicates rapid repeats,
    persists both safe and suspicious records, and raises alerts only for meaningful threats.
    """
    comm_type = (req.communication_type or "notification").strip().lower()
    if comm_type not in ("sms", "notification", "call", "email", "whatsapp", "other"):
        comm_type = "other"

    raw_sender = req.sender_identifier.strip()
    sanitized_sender, _ = redact_sensitive_communication(raw_sender)
    raw_content = (req.content or "").strip()
    raw_subject = (req.subject or "").strip()
    sanitized_content, was_redacted = redact_sensitive_communication(raw_content)
    sanitized_subject, subj_redacted = redact_sensitive_communication(raw_subject)
    was_redacted = was_redacted or subj_redacted

    risk_score = 0
    threat_categories: List[str] = []
    findings: List[str] = []
    explanation = ""
    recommended_action = "No action needed."
    analysis_status = "analyzed"
    spam_reputation: Optional[str] = None
    preview_text = ""

    if comm_type == "call":
        # Incoming call screening: caller reputation ONLY — never claims audio analysis
        try:
            norm_phone, display_phone = normalize_target("phone", raw_sender)
        except ValueError:
            digits = re.sub(r"[^\d+]", "", raw_sender)
            norm_phone = digits if digits.startswith("+") else f"+{digits}"
            display_phone = norm_phone or raw_sender

        rep = community_repo.get_reputation("phone", norm_phone)
        spam_score = int(rep.get("suspicion_score") or rep.get("crowd_suspicion_score") or 0)
        verified = bool(rep.get("is_verified_threat") or rep.get("verified_threat") or False)
        report_count = int(rep.get("total_reports") or rep.get("report_count") or 0)
        raw_tags = rep.get("evidence_tags", [])
        evidence_tags = [
            t["tag"] if isinstance(t, dict) and "tag" in t else str(t)
            for t in raw_tags
        ]

        # Unknown callers are NOT assumed malicious; risk derives purely from verified/community spam evidence
        if verified:
            risk_score = max(spam_score, 85)
            spam_reputation = "verified_spam"
            threat_categories = list(dict.fromkeys(evidence_tags or ["verified_spam_caller"]))
            findings.append(f"Verified scam/spam caller with {report_count} community report(s).")
            explanation = (
                f"Caller reputation analysis flagged {display_phone} as a verified spam/fraud number "
                f"({report_count} reports). Note: Caller reputation only — call audio is never analyzed."
            )
            recommended_action = "Silence or decline call. Never share OTPs or financial credentials."
        elif spam_score >= 41 or report_count >= 2:
            risk_score = min(80, max(spam_score, 45))
            spam_reputation = "reported_suspicious"
            threat_categories = list(dict.fromkeys(evidence_tags or ["reported_spam_caller"]))
            findings.append(f"Caller reported {report_count} time(s) by community members.")
            explanation = (
                f"Caller {display_phone} has {report_count} community spam report(s) "
                f"(reputation score {risk_score}%). Note: Caller reputation only — call audio is never analyzed."
            )
            recommended_action = "Exercise caution if answering. Verify caller identity independently."
        elif spam_score > 0 or report_count == 1:
            risk_score = min(40, max(spam_score, 25))
            spam_reputation = "low_concern"
            threat_categories = list(dict.fromkeys(evidence_tags or ["single_community_report"]))
            findings.append("Single unverified community report on file.")
            explanation = (
                f"Caller {display_phone} has limited unverified report history ({risk_score}%). "
                "Note: Caller reputation only — call audio is never analyzed."
            )
            recommended_action = "Use normal caution."
        else:
            risk_score = 0
            spam_reputation = "clean"
            findings.append("No spam reports found in CyberShield community threat intelligence.")
            if req.is_known_contact is False:
                findings.append("Caller is not in device contacts (unknown callers are not treated as malicious).")
            explanation = (
                f"No spam or fraud reputation found for {display_phone}. "
                "Note: Caller reputation only — call audio is never analyzed."
            )
            recommended_action = "Allow normally."

        preview_text = (
            f"Incoming call ({req.call_status or 'incoming'}) • "
            f"{'Known contact' if req.is_known_contact else ('Unknown caller' if req.is_known_contact is False else 'Caller')}"
        )

    elif comm_type == "email":
        if not raw_subject and not raw_content:
            analysis_status = "unanalyzed"
            explanation = "Email metadata received without analyzable subject or body content."
            recommended_action = "Open email in CyberShield Email Scanner for full analysis."
        else:
            e_res = email_detector.analyze(
                sender=raw_sender,
                subject=raw_subject or "(No Subject)",
                body=raw_content or raw_subject,
            )
            risk_score = int(max(0, min(100, e_res.risk_score)))
            threat_categories = list(dict.fromkeys(e_res.threat_categories or []))
            findings = list(dict.fromkeys((e_res.findings or []) + (e_res.detected_indicators or [])))[:10]
            explanation = e_res.explanation
            recommended_action = (
                e_res.recommendation
                or (e_res.recommendations[0] if e_res.recommendations else "")
                or "Verify sender authenticity before clicking links."
            )
        if req.store_preview:
            combined_prev = f"{sanitized_subject}: {sanitized_content}".strip(": ")
            preview_text = combined_prev[:220]

    else:
        # SMS, WhatsApp notification, or general notification
        combined_raw = f"{raw_subject} {raw_content}".strip()
        if not combined_raw:
            analysis_status = "unanalyzed"
            explanation = "Notification received without analyzable text payload."
            recommended_action = "No action required."
        else:
            sms_res = sms_detector.analyze(combined_raw)
            max_url_score = 0
            url_pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
            urls = list(dict.fromkeys(re.findall(url_pattern, combined_raw)))
            url_findings: List[str] = []
            for u in urls[:5]:
                u_res = url_detector.analyze(u)
                if u_res.risk_score > max_url_score:
                    max_url_score = u_res.risk_score
                if u_res.risk_score >= 30:
                    url_findings.append(f"Suspicious link ({u_res.risk_score}%): {u}")

            risk_score = int(max(0, min(100, max(sms_res.risk_score, max_url_score))))
            cats: List[str] = [
                c for c in (sms_res.threat_categories or [])
                if c and str(c).strip().lower() not in ("none", "safe", "benign")
            ]
            if max_url_score >= 41:
                cats.append("phishing_url")
            if was_redacted:
                cats.append("sensitive_otp_redacted")
            threat_categories = list(dict.fromkeys(cats))

            findings = list(
                dict.fromkeys((sms_res.findings or []) + (sms_res.detected_indicators or []) + url_findings)
            )[:10]
            explanation = sms_res.explanation
            if max_url_score > sms_res.risk_score:
                explanation = f"Embedded URL threat detected ({max_url_score}% risk). {explanation}"
            recommended_action = (
                sms_res.recommendation
                or (
                    "Do not tap links or reply with personal/banking details."
                    if risk_score >= 41
                    else "Message appears safe. No action required."
                )
            )
        if req.store_preview:
            preview_text = (sanitized_content or sanitized_subject)[:220]

    classification = (
        classify_communication_risk(risk_score)
        if analysis_status == "analyzed"
        else "Unavailable"
    )

    extra_meta = dict(req.metadata or {})
    extra_meta["was_redacted"] = was_redacted
    extra_meta["preview_stored"] = req.store_preview
    if comm_type == "call":
        extra_meta["audio_analyzed"] = False

    record, is_dup = communication_repo.upsert_record(
        user_id=current_user.uid,
        communication_type=comm_type,
        source_app=req.source_app.strip(),
        sender_identifier=sanitized_sender,
        caller_name=req.caller_name,
        message_preview=preview_text,
        timestamp=req.timestamp,
        risk_score=risk_score,
        classification=classification,
        threat_categories=threat_categories,
        findings=findings,
        explanation=explanation,
        recommended_action=recommended_action,
        analysis_status=analysis_status,
        is_known_contact=req.is_known_contact,
        call_status=req.call_status,
        spam_reputation=spam_reputation,
        metadata=extra_meta,
        external_id=req.external_id,
        dedup_source_text=sanitized_content or sanitized_subject or preview_text,
    )

    # Only generate security alerts for meaningful threats (>= 41%), never for normal communications
    if not is_dup and analysis_status == "analyzed" and is_threat_flagged(risk_score, classification):
        severity = "critical" if risk_score >= 81 else ("high" if risk_score >= 61 else "medium")
        category = "SPAM_CALLER" if comm_type == "call" else (
            "PHISHING_EMAIL" if comm_type == "email" else "SMS_SCAM"
        )
        alert_repo.create_alert(
            title=f"{classification} {req.source_app}: {sanitized_sender}",
            severity=severity,
            category=category,
            target=sanitized_sender,
            risk_score=risk_score,
            explanation=explanation,
            recommended_actions=[recommended_action],
            user_id=current_user.uid,
            event_key=f"{current_user.uid}:comm:{record['record_id']}",
        )

    # Mirror into Centralized Smart Event Engine (deduped by communication record_id)
    comm_module = (
        "call_screening"
        if comm_type == "call"
        else (
            "gmail_integration"
            if comm_type == "email" and "gmail" in req.source_app.lower()
            else (
                "email_scanner"
                if comm_type == "email"
                else ("sms_scanner" if comm_type == "sms" else "notification_monitor")
            )
        )
    )
    smart_event_engine.safe_record(
        user_id=current_user.uid,
        module_name=comm_module,
        source="communication",
        event_category=f"comm_{comm_type}",
        target_identifier=sanitized_sender,
        risk_score=risk_score if analysis_status == "analyzed" else None,
        classification=classification,
        findings=findings,
        explanation=explanation,
        recommended_actions=[recommended_action],
        analysis_status=analysis_status,
        detection_timestamp=record["timestamp"],
        idempotency_key=f"comm:{record['record_id']}",
        create_alert=False,
        metadata={"record_id": record["record_id"], "source_app": req.source_app, "communication_type": comm_type},
    )

    return CommunicationRecordResponse(**record, is_duplicate=is_dup)


@app.get(
    "/api/v1/communications/history",
    response_model=CommunicationHistoryListResponse,
    status_code=status.HTTP_200_OK,
    tags=["Communication History"],
    summary="List user-isolated communication history (Message History & Call History) with search, filters, and pagination",
)
async def list_communication_history_endpoint(
    category: str = Query("all", description="all | messages | calls"),
    communication_type: Optional[str] = Query(None, description="sms | notification | call | email | whatsapp | other"),
    classification: Optional[str] = Query(None, description="all | safe | low_risk | suspicious | high_risk | critical | unknown"),
    search: Optional[str] = Query(None, description="Search by sender, date, source app, or threat category"),
    start_date: Optional[str] = Query(None, description="ISO start date filter (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="ISO end date filter (YYYY-MM-DD)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    data = communication_repo.list_records(
        user_id=current_user.uid,
        category=category,
        communication_type=communication_type,
        classification=classification,
        search=search,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )
    return CommunicationHistoryListResponse(
        total=data["total"],
        limit=data["limit"],
        offset=data["offset"],
        has_more=data["has_more"],
        records=[CommunicationRecordResponse(**r) for r in data["records"]],
    )


@app.get(
    "/api/v1/communications/analytics",
    status_code=status.HTTP_200_OK,
    tags=["Communication History"],
    summary="Get real stored-record communication security analytics (daily, weekly, monthly)",
)
async def get_communication_analytics_endpoint(
    period: str = Query("daily", description="daily | weekly | monthly"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    return communication_repo.get_analytics(
        user_id=current_user.uid,
        period=period,
    )


@app.delete(
    "/api/v1/communications/{record_id}",
    status_code=status.HTTP_200_OK,
    tags=["Communication History"],
    summary="Delete a single communication record owned by the authenticated user",
)
async def delete_communication_record_endpoint(
    record_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    deleted = communication_repo.delete_record(user_id=current_user.uid, record_id=record_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Communication record '{record_id}' not found.",
        )
    return {"deleted": True, "record_id": record_id}


@app.delete(
    "/api/v1/communications",
    status_code=status.HTTP_200_OK,
    tags=["Communication History"],
    summary="Delete all communication history or apply retention cleanup (older_than_days)",
)
async def purge_communication_history_endpoint(
    older_than_days: Optional[int] = Query(None, ge=1, le=3650),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    count = communication_repo.delete_records(
        user_id=current_user.uid,
        older_than_days=older_than_days,
    )
    return {
        "deleted_count": count,
        "older_than_days": older_than_days,
    }


# ---------------------------------------------------------------------------
# Centralized Smart Alert & All-18-Module Security Event Engine API
# ---------------------------------------------------------------------------

class SmartSecurityEventRequest(BaseModel):
    module_name: str = Field(..., min_length=1, max_length=64)
    event_category: Optional[str] = Field(None, max_length=64)
    source: Optional[str] = Field(None, max_length=64)
    target_identifier: str = Field(..., min_length=1, max_length=512)
    risk_score: Optional[int] = Field(0, ge=0, le=100)
    classification: Optional[str] = Field(None, max_length=64)
    findings: List[str] = Field(default_factory=list)
    explanation: str = Field(default="", max_length=4000)
    recommended_actions: List[str] = Field(default_factory=list)
    analysis_status: str = Field(
        default="analyzed",
        description="analyzed | failed | unverified | unavailable",
    )
    detection_timestamp: Optional[str] = None
    idempotency_key: Optional[str] = Field(None, max_length=256)
    create_alert: bool = True
    metadata: Optional[Dict[str, Any]] = None


class NotificationStatusPatchRequest(BaseModel):
    notification_status: str = Field(
        ...,
        description="delivered_immediate | queued_preference | suppressed_safe | dismissed | acknowledged",
    )


@app.get(
    "/api/v1/events/modules",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="List all 18 integrated CyberShield modules registered in the Smart Event Engine",
)
async def list_registered_modules_endpoint(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    return {
        "total_modules": len(ALL_18_MODULES),
        "modules": [
            {"module_name": k, **v}
            for k, v in ALL_18_MODULES.items()
        ],
    }


@app.post(
    "/api/v1/events/process",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="Submit any module or system security event through the centralized Smart Alert Engine",
)
async def process_smart_security_event_endpoint(
    req: SmartSecurityEventRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    event, is_dup = smart_event_engine.process_event(
        user_id=current_user.uid,
        module_name=req.module_name,
        event_category=req.event_category,
        source=req.source,
        target_identifier=req.target_identifier,
        risk_score=req.risk_score,
        classification=req.classification,
        findings=req.findings,
        explanation=req.explanation,
        recommended_actions=req.recommended_actions,
        analysis_status=req.analysis_status,
        detection_timestamp=req.detection_timestamp,
        idempotency_key=req.idempotency_key,
        create_alert=req.create_alert,
        metadata=req.metadata,
    )
    return event


@app.post(
    "/api/v1/events/daily-report",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="Generate and store a real-data Daily Security Report event for the authenticated user",
)
async def generate_daily_security_report_endpoint(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    analytics = smart_event_engine.get_unified_analytics(
        user_id=current_user.uid,
        period="daily",
    )
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    explanation = (
        f"Daily Security Report ({today}): {analytics['total_analyzed_events']} analyzed event(s), "
        f"{analytics['total_threats_detected']} threat(s) detected "
        f"({analytics['threat_detection_rate_percent']}% detection rate), "
        f"{analytics['failed_or_unavailable_events']} unavailable/failed, "
        f"Device Posture Score {analytics['device_security_posture_score']}/100."
    )
    event, _ = smart_event_engine.process_event(
        user_id=current_user.uid,
        module_name="realtime_protection",
        event_category="daily_report",
        source="system_event",
        target_identifier=f"daily_report_{today}",
        risk_score=max(0, min(100, 100 - int(analytics["device_security_posture_score"]))),
        findings=[
            f"Analyzed Events: {analytics['total_analyzed_events']}",
            f"Critical: {analytics['critical_count']}, High Risk: {analytics['high_risk_count']}, Suspicious: {analytics['suspicious_count']}",
            f"Active Modules Reporting: {analytics['active_modules_count']}/{analytics['total_registered_modules']}",
        ],
        explanation=explanation,
        recommended_actions=[
            "Review any high-risk or critical findings in Unified Event Center.",
            "Keep Real-Time Protection and Notification Access enabled.",
        ],
        analysis_status="analyzed",
        idempotency_key=f"daily_report:{today}",
        create_alert=False,
        metadata={"analytics_snapshot": analytics},
    )
    return {"report_event": event, "analytics": analytics}


@app.get(
    "/api/v1/events/history",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="Query unified security history across all 18 modules with rich filters",
)
async def list_unified_events_history_endpoint(
    module_name: Optional[str] = Query(None, description="Module key or 'all'"),
    event_category: Optional[str] = Query(None),
    source: Optional[str] = Query(None, description="manual_scan | communication | device_audit | realtime_monitor | community | assistant | system_event"),
    severity: Optional[str] = Query(None, description="critical | high | medium | low | info"),
    classification: Optional[str] = Query(None, description="safe | low_risk | suspicious | high_risk | critical | failed | unverified | unavailable"),
    min_risk: Optional[int] = Query(None, ge=0, le=100),
    max_risk: Optional[int] = Query(None, ge=0, le=100),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    return smart_event_engine.list_events(
        user_id=current_user.uid,
        module_name=module_name,
        event_category=event_category,
        source=source,
        severity=severity,
        classification=classification,
        min_risk=min_risk,
        max_risk=max_risk,
        start_date=start_date,
        end_date=end_date,
        search=search,
        limit=limit,
        offset=offset,
    )


@app.get(
    "/api/v1/events/analytics",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="Get real unified security analytics across all 18 modules (daily, weekly, monthly)",
)
async def get_unified_events_analytics_endpoint(
    period: str = Query("daily", description="daily | weekly | monthly"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    return smart_event_engine.get_unified_analytics(
        user_id=current_user.uid,
        period=period,
    )


@app.patch(
    "/api/v1/events/{event_id}/notification-status",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="Update notification delivery status for a stored security event",
)
async def patch_event_notification_status_endpoint(
    event_id: str,
    req: NotificationStatusPatchRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    updated = smart_event_engine.update_notification_status(
        user_id=current_user.uid,
        event_id=event_id,
        notification_status=req.notification_status,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )
    return updated


@app.delete(
    "/api/v1/events/{event_id}",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="Delete a single security event owned by the authenticated user",
)
async def delete_security_event_endpoint(
    event_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    deleted = smart_event_engine.delete_event(user_id=current_user.uid, event_id=event_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )
    return {"deleted": True, "event_id": event_id}


@app.delete(
    "/api/v1/events",
    status_code=status.HTTP_200_OK,
    tags=["Unified Security Events"],
    summary="Delete all unified security events or apply retention cleanup (older_than_days)",
)
async def purge_security_events_endpoint(
    older_than_days: Optional[int] = Query(None, ge=1, le=3650),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    count = smart_event_engine.delete_events(
        user_id=current_user.uid,
        older_than_days=older_than_days,
    )
    return {"deleted_count": count, "older_than_days": older_than_days}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

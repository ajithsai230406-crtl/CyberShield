"""Firebase Authentication module for CyberShield FastAPI backend."""

import asyncio
import base64
import json
import os
import logging
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

import firebase_admin
from firebase_admin import auth, credentials
from google.auth.exceptions import DefaultCredentialsError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger("cybershield.auth")

# Reusable HTTP Bearer security scheme for Swagger / OpenAPI documentation
# auto_error=False allows returning custom 401 responses with WWW-Authenticate header
security_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="FirebaseBearerAuth",
    description="Firebase ID Token. Attach as 'Bearer <token>'.",
)

_firebase_initialized = False
_has_service_account_creds = False
_cached_google_request: Optional[google_requests.Request] = None


def _get_google_request() -> google_requests.Request:
    """Reuse a single HTTP session so Google public x509 certs are cached in memory."""
    global _cached_google_request
    if _cached_google_request is None:
        _cached_google_request = google_requests.Request()
    return _cached_google_request


def initialize_firebase_admin() -> None:
    """
    Initialize Firebase Admin SDK using service account credentials or project ID.
    Reads FIREBASE_SERVICE_ACCOUNT_JSON, FIREBASE_SERVICE_ACCOUNT_PATH or GOOGLE_APPLICATION_CREDENTIALS from env.
    Falls back gracefully to default project configuration.
    """
    global _firebase_initialized, _has_service_account_creds
    if _firebase_initialized or (hasattr(firebase_admin, "_apps") and firebase_admin._apps):
        _firebase_initialized = True
        return

    service_account_json = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH")
    google_creds_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    project_id = os.getenv("FIREBASE_PROJECT_ID", "cybersheild-30cc7")

    # 1. Cloud-friendly inline JSON (or base64-encoded JSON) environment variable
    if service_account_json:
        try:
            raw_json = service_account_json
            if not raw_json.startswith("{"):
                raw_json = base64.b64decode(raw_json).decode("utf-8")
            cert_dict = json.loads(raw_json)
            cred = credentials.Certificate(cert_dict)
            firebase_admin.initialize_app(cred)
            _firebase_initialized = True
            _has_service_account_creds = True
            logger.info("Firebase Admin initialized from FIREBASE_SERVICE_ACCOUNT_JSON.")
            return
        except Exception as e:
            logger.warning("Failed to initialize Firebase Admin from FIREBASE_SERVICE_ACCOUNT_JSON: %s", e)

    target_path = service_account_path or google_creds_path

    if target_path and os.path.exists(target_path):
        try:
            cred = credentials.Certificate(target_path)
            firebase_admin.initialize_app(cred)
            _firebase_initialized = True
            _has_service_account_creds = True
            logger.info("Firebase Admin initialized with certificate from %s", target_path)
            return
        except Exception as e:
            logger.warning("Failed to initialize Firebase Admin with certificate: %s", e)

    # Initialize with project ID
    try:
        firebase_admin.initialize_app(options={"projectId": project_id})
        _firebase_initialized = True
        logger.info("Firebase Admin initialized with project ID: %s", project_id)
    except Exception as e:
        logger.warning(
            "Firebase Admin default initialization deferred/skipped (%s).",
            e,
        )


class AuthenticatedUser(BaseModel):
    """Represents an authenticated Firebase user verified from an ID token."""
    uid: str = Field(..., description="Unique Firebase User Identifier (UID)")
    email: Optional[str] = Field(None, description="User email address")
    email_verified: bool = Field(False, description="Whether email has been verified")
    claims: Dict[str, Any] = Field(default_factory=dict, description="Decoded token claims")


async def get_current_user(
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> AuthenticatedUser:
    """
    Reusable FastAPI dependency that verifies Firebase ID token:
    - Extracts token from 'Authorization: Bearer <Firebase ID Token>'
    - Verifies token signature and expiration via Firebase Admin SDK
    - Extracts verified Firebase UID and claims
    - Returns HTTP 401 for missing, malformed, expired, or invalid tokens.
    """
    if auth_header is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided. Expected 'Authorization: Bearer <Firebase ID Token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not auth_header.scheme or auth_header.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. 'Bearer' scheme is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header.credentials
    if not token or not token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token cannot be empty.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Ensure Firebase Admin is initialized
        initialize_firebase_admin()

        def _verify_sync():
            # Use Admin SDK only when explicit service account credentials are loaded (or in unit tests).
            # On cloud hosts without GCP metadata server (Railway/Render), calling auth.verify_id_token()
            # without a cert blocks ~12s per request timing out on 169.254.169.254 before falling back.
            if _has_service_account_creds or os.getenv("PYTEST_CURRENT_TEST"):
                try:
                    return auth.verify_id_token(token)
                except (auth.ExpiredIdTokenError, auth.InvalidIdTokenError, auth.RevokedIdTokenError):
                    raise
                except Exception as inner_e:
                    logger.debug("Admin SDK verification deferred; verifying via Google public certs: %s", inner_e)

            project_id = os.getenv("FIREBASE_PROJECT_ID", "cybersheild-30cc7")
            req = _get_google_request()
            return google_id_token.verify_firebase_token(
                token, req, audience=project_id
            )

        decoded_token = await asyncio.to_thread(_verify_sync)

        uid = (
            decoded_token.get("uid")
            or decoded_token.get("user_id")
            or decoded_token.get("sub")
        )

        if not uid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token does not contain a valid user identifier (uid).",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return AuthenticatedUser(
            uid=uid,
            email=decoded_token.get("email"),
            email_verified=decoded_token.get("email_verified", False),
            claims=decoded_token,
        )
    except auth.ExpiredIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please refresh your session.",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token", error_description="Token has expired"'},
        )
    except (auth.InvalidIdTokenError, auth.RevokedIdTokenError, ValueError) as e:
        err_msg = str(e)
        if "expired" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired. Please refresh your session.",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token", error_description="Token has expired"'},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {err_msg}",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Token verification encountered an unexpected error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


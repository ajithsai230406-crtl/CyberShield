"""CyberShield Centralized Google Gemini AI Service.

Single centralized backend client for all Google Gemini text & multimodal vision requests:
- Loads GEMINI_API_KEY and GEMINI_MODEL strictly from backend environment variables.
- Never exposes API keys in logs, exceptions, responses, or client bundles.
- Classifies all failure modes explicitly: invalid_api_key, unsupported_model,
  quota_exhausted, rate_limited, network_timeout, server_error, network_error.
- Enriches deterministic threat detector outputs without ever fabricating risk scores
  or marking failed AI calls as Safe.
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("cybershield.gemini")


DEFAULT_GEMINI_MODEL = "gemini-3-flash-preview"
FALLBACK_FLASH_MODELS = ["gemini-3-flash-preview", "gemini-2.5-flash", "gemini-flash-latest"]
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"


@dataclass
class GeminiResponse:
    ok: bool
    text: str = ""
    model: str = DEFAULT_GEMINI_MODEL
    error_code: Optional[str] = None
    # unconfigured | invalid_api_key | unsupported_model | quota_exhausted |
    # rate_limited | network_timeout | server_error | network_error | empty_response
    error_message: Optional[str] = None
    http_status: Optional[int] = None

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "ai_provider": "google_gemini",
            "ai_model": self.model,
            "ai_ok": self.ok,
            "ai_error_code": self.error_code,
            "ai_error_message": self.error_message,
        }


class GeminiAIService:
    """Centralized, fault-isolated Google Gemini AI service for all CyberShield modules."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: float = 18.0,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_model = model
        self.timeout_seconds = timeout_seconds

    @property
    def api_key(self) -> Optional[str]:
        if self._explicit_api_key is not None:
            return self._explicit_api_key.strip() or None
        key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or ""
        return key.strip() or None

    @property
    def model(self) -> str:
        if self._explicit_model is not None and self._explicit_model.strip():
            return self._explicit_model.strip()
        env_model = (os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL).strip()
        return env_model or DEFAULT_GEMINI_MODEL

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    @staticmethod
    def _classify_http_error(status_code: int, body_text: str) -> tuple[str, str]:
        low = (body_text or "").lower()
        if status_code in (401, 403) or (status_code == 400 and ("api key" in low or "api_key" in low)):
            return "invalid_api_key", "Gemini API key is invalid or lacks permission."
        if status_code == 404 or ("not found" in low and "model" in low):
            return "unsupported_model", "Configured Gemini model is not supported or unavailable for this API key."
        if status_code == 429:
            if "quota" in low or "billing" in low or "resource_exhausted" in low:
                return "quota_exhausted", "Gemini API quota exhausted. Please check billing or quota limits."
            return "rate_limited", "Gemini API rate limit reached. Please retry shortly."
        if status_code >= 500:
            return "server_error", f"Gemini service returned server error (HTTP {status_code})."
        return "network_error", f"Gemini API returned HTTP {status_code}."

    @staticmethod
    def _extract_candidate_text(data: Dict[str, Any]) -> str:
        candidates = data.get("candidates") or []
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts") or []
        return "\n".join(str(p.get("text", "")) for p in parts if isinstance(p, dict) and p.get("text")).strip()

    def verify_model_availability(self) -> Dict[str, Any]:
        """Query Google's official ListModels API to verify the configured model is available."""
        key = self.api_key
        target_model = self.model
        if not key:
            return {
                "configured": False,
                "model": target_model,
                "model_available": False,
                "error_code": "unconfigured",
                "message": "GEMINI_API_KEY is not configured in backend environment.",
            }
        try:
            url = f"{GEMINI_API_BASE}/models"
            with httpx.Client(timeout=12.0) as client:
                resp = client.get(url, params={"key": key})
            if resp.status_code != 200:
                code, msg = self._classify_http_error(resp.status_code, resp.text)
                return {
                    "configured": True,
                    "model": target_model,
                    "model_available": False,
                    "error_code": code,
                    "message": msg,
                }
            models_raw = resp.json().get("models", [])
            supported_names = [
                m["name"].replace("models/", "")
                for m in models_raw
                if "generateContent" in (m.get("supportedGenerationMethods") or [])
            ]
            flash_models = [m for m in supported_names if "flash" in m.lower()]
            return {
                "configured": True,
                "model": target_model,
                "model_available": target_model in supported_names,
                "available_flash_models": flash_models[:10],
                "error_code": None if target_model in supported_names else "unsupported_model",
                "message": (
                    f"Model '{target_model}' verified available."
                    if target_model in supported_names
                    else f"Model '{target_model}' not found in available models."
                ),
            }
        except httpx.TimeoutException:
            return {
                "configured": True,
                "model": target_model,
                "model_available": False,
                "error_code": "network_timeout",
                "message": "Timed out querying Gemini ListModels API.",
            }
        except Exception as exc:
            logger.warning("Gemini ListModels check failed: %s", type(exc).__name__)
            return {
                "configured": True,
                "model": target_model,
                "model_available": False,
                "error_code": "network_error",
                "message": f"Failed to reach Gemini API ({type(exc).__name__}).",
            }

    async def generate_text_async(
        self,
        *,
        contents: List[Dict[str, Any]],
        system_instruction: Optional[str] = None,
        temperature: float = 0.35,
        max_output_tokens: int = 850,
    ) -> GeminiResponse:
        """Async text generation call for FastAPI endpoints & AI Assistant."""
        key = self.api_key
        model_name = self.model
        if not key:
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="unconfigured",
                error_message="GEMINI_API_KEY is not configured on backend.",
            )

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
            },
        }
        if system_instruction:
            payload["system_instruction"] = {"parts": [{"text": system_instruction}]}

        url = f"{GEMINI_API_BASE}/models/{model_name}:generateContent"
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.post(url, params={"key": key}, json=payload)

            if resp.status_code != 200:
                code, msg = self._classify_http_error(resp.status_code, resp.text)
                logger.warning("Gemini async error [%s] HTTP %s (model=%s)", code, resp.status_code, model_name)
                return GeminiResponse(
                    ok=False,
                    model=model_name,
                    error_code=code,
                    error_message=msg,
                    http_status=resp.status_code,
                )

            text = self._extract_candidate_text(resp.json())
            if not text:
                return GeminiResponse(
                    ok=False,
                    model=model_name,
                    error_code="empty_response",
                    error_message="Gemini returned an empty response.",
                    http_status=200,
                )
            return GeminiResponse(ok=True, text=text, model=model_name, http_status=200)
        except httpx.TimeoutException:
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="network_timeout",
                error_message="Gemini request timed out.",
            )
        except Exception as exc:
            logger.warning("Gemini async transport error: %s", type(exc).__name__)
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="network_error",
                error_message=f"Gemini transport failure ({type(exc).__name__}).",
            )

    def generate_text_sync(
        self,
        *,
        prompt: str,
        system_instruction: Optional[str] = None,
        temperature: float = 0.25,
        max_output_tokens: int = 320,
        timeout_seconds: float = 8.0,
    ) -> GeminiResponse:
        """Synchronous text generation call for scanner enrichment."""
        key = self.api_key
        model_name = self.model
        if not key:
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="unconfigured",
                error_message="GEMINI_API_KEY is not configured on backend.",
            )

        payload: Dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
            },
        }
        if system_instruction:
            payload["system_instruction"] = {"parts": [{"text": system_instruction}]}

        url = f"{GEMINI_API_BASE}/models/{model_name}:generateContent"
        try:
            with httpx.Client(timeout=timeout_seconds) as client:
                resp = client.post(url, params={"key": key}, json=payload)

            if resp.status_code != 200:
                code, msg = self._classify_http_error(resp.status_code, resp.text)
                logger.warning("Gemini sync error [%s] HTTP %s (model=%s)", code, resp.status_code, model_name)
                return GeminiResponse(
                    ok=False,
                    model=model_name,
                    error_code=code,
                    error_message=msg,
                    http_status=resp.status_code,
                )

            text = self._extract_candidate_text(resp.json())
            if not text:
                return GeminiResponse(
                    ok=False,
                    model=model_name,
                    error_code="empty_response",
                    error_message="Gemini returned an empty response.",
                    http_status=200,
                )
            return GeminiResponse(ok=True, text=text, model=model_name, http_status=200)
        except httpx.TimeoutException:
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="network_timeout",
                error_message="Gemini request timed out.",
            )
        except Exception as exc:
            logger.warning("Gemini sync transport error: %s", type(exc).__name__)
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="network_error",
                error_message=f"Gemini transport failure ({type(exc).__name__}).",
            )

    def analyze_image_sync(
        self,
        *,
        image_bytes: bytes,
        mime_type: str = "image/png",
        prompt: str,
        temperature: float = 0.1,
        max_output_tokens: int = 1024,
        timeout_seconds: float = 18.0,
    ) -> GeminiResponse:
        """Multimodal Gemini Vision call for screenshot OCR & image threat inspection."""
        key = self.api_key
        model_name = self.model
        if not key:
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="unconfigured",
                error_message="GEMINI_API_KEY is not configured on backend.",
            )

        b64_img = base64.b64encode(image_bytes).decode("ascii")
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt},
                        {"inline_data": {"mime_type": mime_type, "data": b64_img}},
                    ]
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
            },
        }
        url = f"{GEMINI_API_BASE}/models/{model_name}:generateContent"
        try:
            with httpx.Client(timeout=timeout_seconds) as client:
                resp = client.post(url, params={"key": key}, json=payload)

            if resp.status_code != 200:
                code, msg = self._classify_http_error(resp.status_code, resp.text)
                logger.warning("Gemini vision error [%s] HTTP %s (model=%s)", code, resp.status_code, model_name)
                return GeminiResponse(
                    ok=False,
                    model=model_name,
                    error_code=code,
                    error_message=msg,
                    http_status=resp.status_code,
                )

            text = self._extract_candidate_text(resp.json())
            if not text:
                return GeminiResponse(
                    ok=False,
                    model=model_name,
                    error_code="empty_response",
                    error_message="Gemini vision returned empty content.",
                    http_status=200,
                )
            return GeminiResponse(ok=True, text=text, model=model_name, http_status=200)
        except httpx.TimeoutException:
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="network_timeout",
                error_message="Gemini vision request timed out.",
            )
        except Exception as exc:
            logger.warning("Gemini vision transport error: %s", type(exc).__name__)
            return GeminiResponse(
                ok=False,
                model=model_name,
                error_code="network_error",
                error_message=f"Gemini vision transport failure ({type(exc).__name__}).",
            )

    def enrich_security_explanation(
        self,
        *,
        module_name: str,
        target: str,
        risk_score: int,
        classification: str,
        findings: List[str],
        base_explanation: str,
    ) -> Dict[str, Any]:
        """Optional AI enrichment for deterministic scanner results.

        Never modifies deterministic risk_score or classification.
        Never fabricates a safe result when Gemini fails.
        """
        # Skip live external AI calls during pytest unless explicitly enabled
        if os.getenv("PYTEST_CURRENT_TEST") and os.getenv("GEMINI_RUN_IN_TESTS") != "1":
            return {
                "ai_enriched": False,
                "ai_model": self.model,
                "ai_explanation": None,
                "ai_status": "skipped_in_test",
            }
        if not self.is_configured:
            return {
                "ai_enriched": False,
                "ai_model": self.model,
                "ai_explanation": None,
                "ai_status": "unconfigured",
            }

        prompt = (
            f"You are CyberShield's cybersecurity analyst explaining a deterministic {module_name} scan.\n"
            f"Target (sanitized): {target[:160]}\n"
            f"Deterministic Risk Score: {risk_score}/100 ({classification})\n"
            f"Detected Findings: {', '.join(findings[:8]) if findings else 'None'}\n"
            f"Base Technical Summary: {base_explanation[:300]}\n\n"
            "Write a concise 2-sentence user-friendly explanation of WHY this score was assigned "
            "and 1 concrete protective action. Do NOT contradict or change the deterministic risk score."
        )
        res = self.generate_text_sync(
            prompt=prompt,
            temperature=0.2,
            max_output_tokens=160,
            timeout_seconds=6.5,
        )
        if res.ok and res.text:
            return {
                "ai_enriched": True,
                "ai_model": res.model,
                "ai_explanation": res.text,
                "ai_status": "ok",
            }
        return {
            "ai_enriched": False,
            "ai_model": res.model,
            "ai_explanation": None,
            "ai_status": res.error_code or "unavailable",
            "ai_error": res.error_message,
        }


_singleton: Optional[GeminiAIService] = None


def get_gemini_service() -> GeminiAIService:
    global _singleton
    if _singleton is None:
        _singleton = GeminiAIService()
    return _singleton

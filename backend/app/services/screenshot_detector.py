"""Screenshot Threat Detection Engine for CyberShield.

Extracts text from uploaded screenshot images using Optical Character Recognition (OCR)
via Tesseract / pytesseract, and inspects the extracted text for:
- Phishing messages & credential harvesting
- Fake bank & KYC suspension alerts
- OTP / PIN solicitation scams
- Malicious & suspicious embedded URLs (via URLThreatDetector)
- UPI & payment fraud / fake receipt deception
- Institutional & customer helpline impersonation (via SMSThreatDetector)
"""

from dataclasses import dataclass, field
import base64
import io
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Set, Tuple

from PIL import Image
import pytesseract

from app.services.url_detector import URLAnalysisResult, URLThreatDetector
from app.services.sms_detector import SMSAnalysisResult, SMSThreatDetector

# Cross-platform Tesseract binary detection (Linux cloud containers, macOS, and Windows)
_env_tesseract = os.getenv("TESSERACT_CMD", "").strip()
if _env_tesseract and os.path.exists(_env_tesseract):
    pytesseract.pytesseract.tesseract_cmd = _env_tesseract
else:
    _which_tesseract = shutil.which("tesseract")
    if _which_tesseract:
        pytesseract.pytesseract.tesseract_cmd = _which_tesseract
    elif os.name == "nt":
        # Windows fallback search paths when tesseract is not on PATH
        TESSERACT_COMMON_PATHS = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
        ]
        for _path in TESSERACT_COMMON_PATHS:
            if os.path.exists(_path):
                pytesseract.pytesseract.tesseract_cmd = _path
                break


@dataclass
class ScreenshotAnalysisResult:
    """Structured result of OCR screenshot threat inspection."""

    filename: str
    ocr_text: str
    risk_score: int
    classification: str
    findings: List[str] = field(default_factory=list)
    detected_indicators: List[str] = field(default_factory=list)
    explanation: str = ""
    finding_explanations: List[Dict[str, str]] = field(default_factory=list)
    recommendation: str = ""
    extracted_urls: List[str] = field(default_factory=list)
    threat_categories: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    engine_status: str = "screenshot_threat_inspector_active"


class ScreenshotThreatDetector:
    """Heuristic OCR and visual content analyzer for mobile screenshots."""

    # UI Deception patterns common in screenshot-based scams
    SCREENSHOT_FRAUD_PATTERNS: List[Tuple[str, str, str, str, str]] = [
        (
            r"\b(?:payment\s+successful|transaction\s+successful|money\s+transferred|paid\s+to\s+you|credited\s+to\s+your\s+account)\b",
            "fake_payment_receipt",
            "Screenshot contains payment receipt / credit confirmation claim (common in overpayment scams)",
            "Fake Payment Confirmation Receipt",
            "High",
        ),
        (
            r"\b(?:virus\s+detected|trojan\s+found|phone\s+infected|critical\s+threat\s+detected|call\s+apple\s+support|call\s+google\s+support)\b",
            "scareware_alert",
            "Deceptive scareware or rogue malware warning dialog detected in image",
            "Scareware / Rogue Alert",
            "High",
        ),
        (
            r"\b(?:scan\s+qr\s+to\s+receive|enter\s+upi\s+pin\s+to\s+receive|receive\s+money\s+by\s+entering\s+pin)\b",
            "fake_receive_scam",
            "Misleading instruction claiming UPI PIN is required to receive money",
            "Fake 'Receive Money' Scam",
            "High",
        ),
    ]

    def __init__(
        self,
        url_detector: Optional[URLThreatDetector] = None,
        sms_detector: Optional[SMSThreatDetector] = None,
    ) -> None:
        self.url_detector = url_detector or URLThreatDetector()
        self.sms_detector = sms_detector or SMSThreatDetector()

    def extract_text_from_bytes(self, image_bytes: bytes) -> Tuple[str, Dict[str, Any]]:
        """Perform OCR on image bytes and return extracted string and metadata."""
        if not image_bytes:
            raise ValueError("Empty image byte payload provided.")

        try:
            image = Image.open(io.BytesIO(image_bytes))
            metadata = {
                "format": image.format or "UNKNOWN",
                "width": image.width,
                "height": image.height,
                "mode": image.mode,
            }
        except Exception as e:
            raise ValueError(f"Invalid or corrupted image format: {str(e)}")

        # Convert to RGB if palette/RGBA
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")

        try:
            text = pytesseract.image_to_string(image)
            clean_text = text.strip()
            metadata["ocr_engine"] = "tesseract"
        except Exception as ocr_err:
            clean_text = ""
            metadata["ocr_error"] = str(ocr_err)

        # Fallback to centralized OpenRouter Vision (NVIDIA Nemotron 3.5 Super VL) if Tesseract is unavailable or returned no text
        if not clean_text:
            vision_text, vision_meta = self._extract_text_via_openrouter_vision(
                image_bytes, metadata.get("format", "PNG")
            )
            if vision_meta:
                metadata.update(vision_meta)
            if vision_text:
                clean_text = vision_text
                metadata["ocr_engine"] = "openrouter_vision"
            else:
                metadata.setdefault("ocr_engine", "none")

        metadata["extracted_character_count"] = len(clean_text)
        metadata["extracted_word_count"] = len(clean_text.split())
        return clean_text, metadata

    def _extract_text_via_openrouter_vision(
        self, image_bytes: bytes, fmt: str
    ) -> Tuple[str, Dict[str, Any]]:
        """Delegate cloud multimodal OCR to centralized OpenRouterAIService when Tesseract is unavailable."""
        if os.getenv("PYTEST_CURRENT_TEST") and os.getenv("OPENROUTER_RUN_IN_TESTS") != "1":
            return "", {}
        from app.services.openrouter_service import get_openrouter_service

        ai_svc = get_openrouter_service()
        if not ai_svc.is_configured:
            return "", {}

        mime = "image/png" if fmt.upper() in ("PNG", "UNKNOWN") else f"image/{fmt.lower()}"
        res = ai_svc.analyze_image_sync(
            image_bytes=image_bytes,
            mime_type=mime,
            prompt=(
                "Extract all visible text, messages, URLs, phone numbers, and payment details "
                "from this screenshot image verbatim. Return only the extracted text without any preamble."
            ),
            timeout_seconds=28.0,
        )
        return (res.text if res.success else ""), res.to_metadata()

    def analyze_image_bytes(
        self,
        image_bytes: bytes,
        filename: str = "screenshot.png",
    ) -> ScreenshotAnalysisResult:
        """Run OCR extraction and composite threat detection on screenshot image bytes."""
        clean_text, image_meta = self.extract_text_from_bytes(image_bytes)

        if not clean_text:
            return ScreenshotAnalysisResult(
                filename=filename,
                ocr_text="",
                risk_score=0,
                classification="Safe",
                findings=["No readable text or threat indicators detected in screenshot"],
                explanation="OCR extraction did not detect readable text in the image. No threats identified.",
                recommendation="No suspicious textual or phishing indicators were found in this image.",
                metadata=image_meta,
            )

        return self.analyze_extracted_text(clean_text, filename=filename, metadata=image_meta)

    def analyze_extracted_text(
        self,
        text: str,
        filename: str = "screenshot.png",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScreenshotAnalysisResult:
        """Inspect OCR-extracted text using SMS, URL, and screenshot-specific heuristic detectors."""
        meta = metadata or {}
        findings: List[str] = []
        detected_indicators: List[str] = []
        finding_explanations: List[Dict[str, str]] = []
        threat_categories: Set[str] = set()
        max_score = 0

        # Step 1: Detect and scan embedded URLs
        url_matches = re.findall(r"https?://[^\s]+|www\.[^\s]+", text)
        extracted_urls = list(dict.fromkeys(url_matches))

        for url in extracted_urls:
            url_res: URLAnalysisResult = self.url_detector.analyze(url)
            if url_res.risk_score > 0:
                max_score = max(max_score, url_res.risk_score)
                threat_categories.add("embedded_url")
                findings.extend(url_res.detected_indicators)
                detected_indicators.extend(url_res.detected_indicators)
                finding_explanations.extend(url_res.finding_explanations)

        # Step 2: Leverage SMS/text threat detector (social engineering, urgency, KYC, OTP)
        sms_res: SMSAnalysisResult = self.sms_detector.analyze(text)
        if sms_res.risk_score > 0:
            max_score = max(max_score, sms_res.risk_score)
            threat_categories.update(sms_res.threat_categories)
            findings.extend(sms_res.findings)
            detected_indicators.extend(sms_res.detected_indicators)
            finding_explanations.extend(sms_res.finding_explanations)

        # Step 3: Screenshot-specific UI fraud patterns
        for pattern, cat, ind_text, title, risk_lvl in self.SCREENSHOT_FRAUD_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                threat_categories.add(cat)
                findings.append(ind_text)
                detected_indicators.append(ind_text)
                finding_explanations.append({
                    "indicator": ind_text,
                    "title": title,
                    "risk_level": risk_lvl,
                    "explanation": (
                        "Attackers frequently share fabricated screenshots or alerts to manipulate "
                        "victims into believing an authorized transaction or critical malware infection has occurred."
                    ),
                })
                max_score = max(max_score, 75 if risk_lvl == "High" else 50)

        # Deduplicate findings & indicators
        unique_findings = list(dict.fromkeys(findings))
        unique_indicators = list(dict.fromkeys(detected_indicators))

        # Deduplicate explanations by indicator
        unique_explanations: List[Dict[str, str]] = []
        seen_ind = set()
        for f_expl in finding_explanations:
            ind_key = f_expl.get("indicator") or f_expl.get("title")
            if ind_key not in seen_ind:
                seen_ind.add(ind_key)
                unique_explanations.append(f_expl)

        # Final score & classification
        final_score = min(max(max_score, 0), 100)
        if final_score >= 70:
            classification = "Malicious"
            explanation = (
                f"Screenshot analysis detected severe cyber threat signatures (Score: {final_score}/100): "
                f"{'; '.join(unique_indicators[:3])}. High probability of phishing, credential theft, or financial fraud."
            )
            recommendation = (
                "DO NOT follow any instructions shown in this screenshot, do not call displayed numbers, "
                "and NEVER share OTPs, PINs, or credentials. Delete the message or report the sender."
            )
        elif final_score >= 30:
            classification = "Suspicious"
            explanation = (
                f"Screenshot contains potential risk indicators (Score: {final_score}/100): "
                f"{'; '.join(unique_indicators[:2])}. Exercise elevated caution."
            )
            recommendation = (
                "Verify the authenticity of this message through official channels before taking any action. "
                "Do not open unverified links displayed in the image."
            )
        else:
            classification = "Safe"
            unique_findings.append("No active phishing, urgency, or credential theft patterns identified in screenshot")
            explanation = "OCR extracted text contains no recognized social engineering, smishing, or malicious link signatures."
            recommendation = "Content appears benign. Always exercise standard vigilance with unsolicited messages."

        meta["extracted_urls_count"] = len(extracted_urls)
        meta["threat_categories_count"] = len(threat_categories)

        return ScreenshotAnalysisResult(
            filename=filename,
            ocr_text=text,
            risk_score=final_score,
            classification=classification,
            findings=unique_findings,
            detected_indicators=unique_indicators,
            explanation=explanation,
            finding_explanations=unique_explanations,
            recommendation=recommendation,
            extracted_urls=extracted_urls,
            threat_categories=sorted(threat_categories),
            metadata=meta,
        )

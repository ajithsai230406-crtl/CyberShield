"""QR Code Content Analysis Engine for CyberShield.

Analyses decoded QR payloads for cyber threats across content types:
- URL payloads (delegates to URLThreatDetector)
- UPI payment links (payee validation, suspicious patterns)
- vCard / Contact payloads (embedded URL inspection)
- WiFi network configs (suspicious SSID detection)
- Plain text (keyword-based phishing indicators)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import re
from urllib.parse import urlparse, parse_qs

from app.services.url_detector import URLThreatDetector, URLAnalysisResult


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known legitimate UPI handle suffixes
LEGITIMATE_UPI_HANDLES = {
    "@okaxis",
    "@okicici",
    "@oksbi",
    "@okhdfc",
    "@ybl",
    "@paytm",
    "@upi",
    "@ibl",
    "@axl",
    "@apl",
    "@barodampay",
    "@unionbank",
    "@mahb",
    "@pnb",
    "@cnrb",
}

# Suspicious SSID patterns (phishing hotspot indicators)
SUSPICIOUS_SSID_PATTERNS: List[re.Pattern] = [
    re.compile(r"free[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"airport[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"hotel[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"login[-_\s]?here", re.IGNORECASE),
    re.compile(r"connect[-_\s]?here", re.IGNORECASE),
    re.compile(r"secure[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"atm[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"bank[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"government[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"police[-_\s]?wifi", re.IGNORECASE),
    re.compile(r"verify[-_\s]?network", re.IGNORECASE),
]

# Plain-text phishing keyword indicators
PHISHING_TEXT_KEYWORDS: List[str] = [
    "phishing",
    "urgent",
    "click here",
    "verify",
    "otp",
    "password",
    "credit card",
    "pin",
    "bank account",
    "suspended",
    "immediate action",
    "claim now",
    "prize",
    "lottery",
    "winner",
    "congratulations",
    "free gift",
    "limited time",
]

# Random-looking alphanumeric UPI payee pattern (e.g. a8f72b3c9d@upi)
def _is_suspicious_payee_id(payee_id: str) -> bool:
    """Detect randomly generated or machine-generated VPA usernames."""
    pid = payee_id.lower()
    digits = sum(c.isdigit() for c in pid)
    letters = sum(c.isalpha() for c in pid)
    if digits >= 3 and letters >= 3 and len(pid) >= 8:
        return True
    if len(pid) >= 8 and re.match(r"^[a-f0-9]+$", pid) and digits > 0:
        return True
    if len(pid) >= 12 and pid.isdigit():
        return True
    return False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class QRFindingDetail:
    indicator: str
    title: str
    risk_level: str
    explanation: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "indicator": self.indicator,
            "title": self.title,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
        }


@dataclass
class QRAnalysisResult:
    content_type: str          # 'url', 'upi', 'contact', 'wifi', 'text'
    decoded_payload: str       # raw QR content
    risk_score: int            # 0-100
    classification: str        # Safe / Suspicious / Malicious
    findings: List[str] = field(default_factory=list)
    detected_indicators: List[str] = field(default_factory=list)
    explanation: str = ""
    finding_explanations: List[Dict[str, str]] = field(default_factory=list)
    recommendation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# QR Threat Detector
# ---------------------------------------------------------------------------

class QRThreatDetector:
    """Heuristic QR Code Content Analysis Engine."""

    def __init__(self) -> None:
        self.url_detector = URLThreatDetector()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, payload: str) -> QRAnalysisResult:
        """Analyse a decoded QR payload and return a QRAnalysisResult."""
        cleaned = payload.strip()
        content_type = self._detect_content_type(cleaned)

        if content_type == "url":
            return self._analyze_url(cleaned)
        elif content_type == "upi":
            return self._analyze_upi(cleaned)
        elif content_type == "contact":
            return self._analyze_contact(cleaned)
        elif content_type == "wifi":
            return self._analyze_wifi(cleaned)
        else:
            return self._analyze_text(cleaned)

    # ------------------------------------------------------------------
    # Content-type detection
    # ------------------------------------------------------------------

    def _detect_content_type(self, payload: str) -> str:
        """Detect the type of content encoded in the QR payload."""
        lower = payload.lower()
        if lower.startswith(("http://", "https://", "ftp://", "www.")):
            return "url"
        if lower.startswith("upi://") or "pa=" in lower:
            return "upi"
        if payload.upper().startswith("BEGIN:VCARD"):
            return "contact"
        if payload.upper().startswith("WIFI:"):
            return "wifi"
        return "text"

    # ------------------------------------------------------------------
    # URL analysis
    # ------------------------------------------------------------------

    def _analyze_url(self, payload: str) -> QRAnalysisResult:
        """Delegate URL analysis to URLThreatDetector."""
        url = payload if not payload.lower().startswith("www.") else f"https://{payload}"
        result: URLAnalysisResult = self.url_detector.analyze(url)

        return QRAnalysisResult(
            content_type="url",
            decoded_payload=payload,
            risk_score=result.risk_score,
            classification=result.classification,
            findings=list(result.detected_indicators),
            detected_indicators=list(result.detected_indicators),
            explanation=result.explanation,
            finding_explanations=list(result.finding_explanations),
            recommendation=result.recommendation,
            metadata={
                **result.metadata,
                "scanned_url": result.scanned_url,
            },
        )

    # ------------------------------------------------------------------
    # UPI analysis
    # ------------------------------------------------------------------

    def _analyze_upi(self, payload: str) -> QRAnalysisResult:
        """Analyse a UPI payment QR payload for fraud indicators."""
        findings: List[str] = []
        finding_details: List[QRFindingDetail] = []
        score: int = 0
        metadata: Dict[str, Any] = {}

        # Extract query parameters (handle both upi://pay?... and bare pa=... strings)
        if payload.lower().startswith("upi://"):
            parsed = urlparse(payload)
            params = parse_qs(parsed.query)
        else:
            # Treat the whole string as a query string
            params = parse_qs(payload.lstrip("?"))

        def first(key: str) -> Optional[str]:
            vals = params.get(key, [])
            return vals[0] if vals else None

        payee_address = first("pa") or ""
        payee_name = first("pn") or ""
        amount = first("am") or ""
        currency = first("cu") or ""
        transaction_note = first("tn") or ""

        metadata["payee_address"] = payee_address
        metadata["payee_name"] = payee_name
        metadata["amount"] = amount
        metadata["currency"] = currency
        metadata["transaction_note"] = transaction_note

        # Check 1: Unknown/suspicious UPI handle
        if payee_address:
            handle_lower = payee_address.lower()
            known_handle = any(handle_lower.endswith(h) for h in LEGITIMATE_UPI_HANDLES)
            if not known_handle:
                score += 20
                ind = f"Payee address '{payee_address}' uses an unrecognized UPI handle"
                findings.append(ind)
                finding_details.append(QRFindingDetail(
                    indicator=ind,
                    title="Unrecognized UPI Handle",
                    risk_level="Medium",
                    explanation=(
                        "The payee VPA (Virtual Payment Address) does not end with a "
                        "known legitimate bank handle. This may indicate a fraudulent or "
                        "recently registered payment address."
                    ),
                ))

            # Check 2: Random-looking alphanumeric payee ID
            local_part = payee_address.split("@")[0] if "@" in payee_address else payee_address
            if _is_suspicious_payee_id(local_part):
                score += 20
                ind = f"Payee ID '{local_part}' appears random or auto-generated (high fraud risk)"
                findings.append(ind)
                finding_details.append(QRFindingDetail(
                    indicator=ind,
                    title="Random-Looking Payee ID",
                    risk_level="High",
                    explanation=(
                        "Fraudsters often register randomly generated UPI IDs that do not "
                        "correspond to a real business or individual. This pattern is "
                        "strongly associated with UPI payment scams."
                    ),
                ))

            # Check 3: Excessively long payee address
            if len(payee_address) > 50:
                score += 15
                ind = f"Payee address is unusually long ({len(payee_address)} chars)"
                findings.append(ind)
                finding_details.append(QRFindingDetail(
                    indicator=ind,
                    title="Excessively Long Payee Address",
                    risk_level="Medium",
                    explanation=(
                        "Legitimate UPI addresses are typically short and recognisable. "
                        "An unusually long payee address may be obfuscating the real recipient."
                    ),
                ))
        else:
            # Missing payee address entirely
            score += 25
            ind = "UPI payload is missing the required payee address (pa=)"
            findings.append(ind)
            finding_details.append(QRFindingDetail(
                indicator=ind,
                title="Missing Payee Address",
                risk_level="High",
                explanation=(
                    "A valid UPI payment link must include a payee VPA (pa= field). "
                    "The absence of a payee address is a strong indicator of a malformed "
                    "or fraudulent QR code."
                ),
            ))

        # Check 4: Missing or blank payee name
        if not payee_name or not payee_name.strip():
            score += 15
            ind = "Payee name (pn=) is missing or blank"
            findings.append(ind)
            finding_details.append(QRFindingDetail(
                indicator=ind,
                title="Missing Payee Name",
                risk_level="Medium",
                explanation=(
                    "Legitimate merchant UPI QRs always include a readable payee name. "
                    "A blank or absent payee name makes it impossible to verify who will "
                    "receive the payment."
                ),
            ))

        # Check 5: Amount specified with suspicious payee
        if amount and score > 0:
            score += 10
            ind = f"Pre-filled payment amount (₹{amount}) with suspicious payee details"
            findings.append(ind)
            finding_details.append(QRFindingDetail(
                indicator=ind,
                title="Pre-filled Amount with Suspicious Payee",
                risk_level="High",
                explanation=(
                    "A QR code that pre-fills a payment amount to a suspicious payee is "
                    "a hallmark of UPI payment fraud. The victim may not notice the amount "
                    "or recipient before confirming the transaction."
                ),
            ))

        # Check 6: Non-INR currency
        if currency and currency.upper() != "INR":
            score += 30
            ind = f"Non-standard currency detected: {currency} (expected INR for UPI)"
            findings.append(ind)
            finding_details.append(QRFindingDetail(
                indicator=ind,
                title="Non-INR Currency",
                risk_level="High",
                explanation=(
                    "UPI is an Indian payment standard and only supports INR. "
                    "A non-INR currency parameter indicates a malformed or forged QR code."
                ),
            ))

        score = max(0, min(100, score))
        classification = self._classify(score)
        explanation = self._build_explanation("upi", classification, score, findings)
        recommendation = self._build_recommendation(classification)

        return QRAnalysisResult(
            content_type="upi",
            decoded_payload=payload,
            risk_score=score,
            classification=classification,
            findings=findings,
            detected_indicators=findings,
            explanation=explanation,
            finding_explanations=[d.to_dict() for d in finding_details],
            recommendation=recommendation,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Contact / vCard analysis
    # ------------------------------------------------------------------

    def _analyze_contact(self, payload: str) -> QRAnalysisResult:
        """Analyse a vCard QR payload for suspicious embedded content."""
        findings: List[str] = []
        finding_details: List[QRFindingDetail] = []
        score: int = 0
        metadata: Dict[str, Any] = {"format": "vCard"}

        lines = payload.splitlines()
        for line in lines:
            stripped = line.strip()
            upper = stripped.upper()

            # Check for embedded URLs in URL: field
            if upper.startswith("URL:"):
                embedded_url = stripped[4:].strip()
                metadata["embedded_url"] = embedded_url
                url_result = self.url_detector.analyze(embedded_url)
                if url_result.risk_score >= 30:
                    score += min(40, url_result.risk_score // 2)
                    ind = f"Suspicious URL embedded in vCard URL field: {embedded_url}"
                    findings.append(ind)
                    finding_details.append(QRFindingDetail(
                        indicator=ind,
                        title="Suspicious Embedded vCard URL",
                        risk_level="High" if url_result.risk_score >= 70 else "Medium",
                        explanation=(
                            f"The vCard contains a URL ({embedded_url}) that scored "
                            f"{url_result.risk_score}/100 in threat analysis: "
                            f"{url_result.explanation}"
                        ),
                    ))

            # Check NOTE: field for phishing content
            if upper.startswith("NOTE:"):
                note_text = stripped[5:].strip().lower()
                matched = [kw for kw in PHISHING_TEXT_KEYWORDS if kw in note_text]
                if matched:
                    score += min(30, len(matched) * 10)
                    ind = f"Suspicious keywords in vCard NOTE field: {', '.join(matched)}"
                    findings.append(ind)
                    finding_details.append(QRFindingDetail(
                        indicator=ind,
                        title="Phishing Keywords in vCard Note",
                        risk_level="Medium",
                        explanation=(
                            "The NOTE field of the vCard contains phishing-associated keywords "
                            f"({', '.join(matched)}), suggesting the contact may be used in "
                            "a social engineering attack."
                        ),
                    ))

        score = max(0, min(40, score))
        classification = self._classify(score)
        explanation = self._build_explanation("contact", classification, score, findings)
        recommendation = self._build_recommendation(classification)

        return QRAnalysisResult(
            content_type="contact",
            decoded_payload=payload,
            risk_score=score,
            classification=classification,
            findings=findings,
            detected_indicators=findings,
            explanation=explanation,
            finding_explanations=[d.to_dict() for d in finding_details],
            recommendation=recommendation,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # WiFi analysis
    # ------------------------------------------------------------------

    def _analyze_wifi(self, payload: str) -> QRAnalysisResult:
        """Analyse a WiFi QR payload for phishing hotspot indicators."""
        findings: List[str] = []
        finding_details: List[QRFindingDetail] = []
        score: int = 0
        metadata: Dict[str, Any] = {"format": "WiFi"}

        # Parse WIFI:T:WPA;S:SSID;P:password;H:false;;
        ssid_match = re.search(r"S:([^;]+)", payload)
        security_match = re.search(r"T:([^;]+)", payload)
        hidden_match = re.search(r"H:([^;]+)", payload)

        ssid = ssid_match.group(1).strip() if ssid_match else ""
        security = security_match.group(1).strip() if security_match else ""
        hidden = hidden_match.group(1).strip().lower() if hidden_match else "false"

        metadata["ssid"] = ssid
        metadata["security_type"] = security
        metadata["hidden"] = hidden == "true"

        # Check 1: Suspicious SSID name
        for pattern in SUSPICIOUS_SSID_PATTERNS:
            if ssid and pattern.search(ssid):
                score += 35
                ind = f"Suspicious WiFi SSID name detected: '{ssid}'"
                findings.append(ind)
                finding_details.append(QRFindingDetail(
                    indicator=ind,
                    title="Phishing Hotspot SSID",
                    risk_level="High",
                    explanation=(
                        f"The SSID '{ssid}' matches a pattern commonly used by fraudulent "
                        "WiFi hotspots designed to capture credentials via captive portal attacks."
                    ),
                ))
                break  # One flag is sufficient per SSID

        # Check 2: Open / no-security network
        if security.upper() in ("nopass", "", "NONE"):
            score += 15
            ind = "WiFi network has no password / open security"
            findings.append(ind)
            finding_details.append(QRFindingDetail(
                indicator=ind,
                title="Open WiFi Network",
                risk_level="Medium",
                explanation=(
                    "Connecting to an open WiFi network exposes all unencrypted traffic "
                    "to potential interception by nearby attackers."
                ),
            ))

        score = max(0, min(60, score))
        classification = self._classify(score)
        explanation = self._build_explanation("wifi", classification, score, findings)
        recommendation = self._build_recommendation(classification)

        return QRAnalysisResult(
            content_type="wifi",
            decoded_payload=payload,
            risk_score=score,
            classification=classification,
            findings=findings,
            detected_indicators=findings,
            explanation=explanation,
            finding_explanations=[d.to_dict() for d in finding_details],
            recommendation=recommendation,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Plain text analysis
    # ------------------------------------------------------------------

    def _analyze_text(self, payload: str) -> QRAnalysisResult:
        """Basic keyword analysis for plain-text QR content."""
        findings: List[str] = []
        finding_details: List[QRFindingDetail] = []
        score: int = 0
        metadata: Dict[str, Any] = {"character_count": len(payload)}

        lower_payload = payload.lower()
        matched_keywords = [kw for kw in PHISHING_TEXT_KEYWORDS if kw in lower_payload]

        if matched_keywords:
            keyword_score = min(50, len(matched_keywords) * 10)
            score += keyword_score
            ind = f"Suspicious phishing keywords detected in QR text: {', '.join(matched_keywords)}"
            findings.append(ind)
            finding_details.append(QRFindingDetail(
                indicator=ind,
                title="Phishing Keywords in Plain Text",
                risk_level="High" if keyword_score >= 30 else "Medium",
                explanation=(
                    f"The QR payload contains keywords ({', '.join(matched_keywords)}) "
                    "commonly associated with phishing, social engineering, or scam messages."
                ),
            ))

        metadata["matched_keywords"] = matched_keywords
        score = max(0, min(50, score))
        classification = self._classify(score)
        explanation = self._build_explanation("text", classification, score, findings)
        recommendation = self._build_recommendation(classification)

        return QRAnalysisResult(
            content_type="text",
            decoded_payload=payload,
            risk_score=score,
            classification=classification,
            findings=findings,
            detected_indicators=findings,
            explanation=explanation,
            finding_explanations=[d.to_dict() for d in finding_details],
            recommendation=recommendation,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _classify(self, score: int) -> str:
        """Classify based on risk score."""
        if score <= 29:
            return "Safe"
        elif score <= 69:
            return "Suspicious"
        else:
            return "Malicious"

    def _build_explanation(
        self,
        content_type: str,
        classification: str,
        score: int,
        findings: List[str],
    ) -> str:
        if classification == "Safe":
            return (
                f"The QR {content_type} payload exhibits no suspicious characteristics "
                f"and scored {score}/100. It appears safe to use."
            )
        elif classification == "Suspicious":
            return (
                f"The QR {content_type} payload scored {score}/100 and presents "
                f"{len(findings)} warning indicator(s): {'; '.join(findings)}. "
                "Caution is recommended."
            )
        else:
            return (
                f"The QR {content_type} payload scored {score}/100 and exhibits severe "
                f"threat indicators: {'; '.join(findings)}. High probability of fraud or "
                "malicious intent."
            )

    def _build_recommendation(self, classification: str) -> str:
        if classification == "Safe":
            return (
                "The QR code appears safe. Always verify the destination before "
                "completing any payment or entering sensitive information."
            )
        elif classification == "Suspicious":
            return (
                "Do not enter passwords, complete payments, or share personal information. "
                "Verify the source of this QR code through an independent channel."
            )
        else:
            return (
                "Do not interact with this QR code. Block the sender and report the "
                "QR code as a potential fraud or phishing attempt."
            )

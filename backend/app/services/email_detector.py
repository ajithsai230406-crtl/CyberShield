"""CyberShield Email Threat Detection Engine.

Detects email phishing, social engineering, impersonation, and malicious embedded links:
- Sender display name spoofing & freemail abuse
- Typosquatting and suspicious sender domains
- Mismatched Reply-To headers
- Urgency, psychological coercion & fear triggers
- Financial fraud, wire transfers & fake invoices
- Credential harvesting & fake password reset lures
- Deep embedded URL inspection via URLThreatDetector
- CEO fraud & Business Email Compromise (BEC) patterns
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from app.services.url_detector import URLThreatDetector, SUSPICIOUS_TLDS, KNOWN_SHORTENERS


# ---------------------------------------------------------------------------
# Knowledge Base & Patterns
# ---------------------------------------------------------------------------

FREE_EMAIL_DOMAINS: Set[str] = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "aol.com",
    "protonmail.com",
    "proton.me",
    "icloud.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
    "yandex.ru",
    "gmx.com",
    "gmx.net",
    "tutanota.com",
    "live.com",
}

IMPERSONATED_BRANDS: Dict[str, List[str]] = {
    "PayPal": ["paypal", "pay-pal", "paypal-security", "paypal-service", "paypa1"],
    "Microsoft": ["microsoft", "office365", "m365", "outlook-team", "onedrive-share", "micros0ft"],
    "Google": ["google", "google-security", "gmail-support", "google-workspace"],
    "Apple": ["apple", "icloud-security", "apple-id", "itunes-support", "appleid"],
    "Amazon": ["amazon", "amazon-billing", "prime-service", "amaz0n"],
    "Netflix": ["netflix", "netflix-billing", "netflix-update"],
    "Banking Institution": ["chase", "wellsfargo", "bankofamerica", "citi", "barclays", "hsbc", "sbi", "hdfc", "icici"],
    "Delivery / Courier": ["fedex", "ups", "usps", "dhl", "dhl-express", "postal-service"],
    "Tax Authority": ["irs", "hmrc", "incometax", "cra", "ato"],
}


@dataclass
class EmailFindingDetail:
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
class EmailAnalysisResult:
    sender: str
    subject: str
    body: str
    risk_score: int
    classification: str  # Safe, Suspicious, High Risk, Critical
    threat_categories: List[str] = field(default_factory=list)
    detected_indicators: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    finding_explanations: List[Dict[str, str]] = field(default_factory=list)
    explanation: str = ""
    recommendation: str = ""
    recommendations: List[str] = field(default_factory=list)
    embedded_urls: List[str] = field(default_factory=list)
    url_scan_results: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    engine_status: str = "email_threat_detector_active"


class EmailThreatDetector:
    """Heuristic Phishing and Social Engineering Detector for Emails."""

    def __init__(self, url_detector: Optional[URLThreatDetector] = None) -> None:
        self.url_detector = url_detector or URLThreatDetector()

        # Compile urgency & coercion patterns: (pattern, category, weight, explanation)
        self.urgency_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b(within\s+(?:24|12|48|2)\s+hours?|immediately|right\s+now|urgent(?:ly)?)\b", re.IGNORECASE),
                "Urgency Coercion",
                15,
                "Imposes an artificial deadline to force hasty user action before verification.",
            ),
            (
                re.compile(r"\b(account\s+(?:will\s+be\s+)?(?:suspended|terminated|locked|closed|disabled|deactivated))\b", re.IGNORECASE),
                "Fear / Suspension Threat",
                20,
                "Threatens immediate account closure or suspension to induce panic.",
            ),
            (
                re.compile(r"\b(unauthorized\s+(?:login|activity|access|transaction)|security\s+alert|compromised)\b", re.IGNORECASE),
                "Security Alert Pretext",
                15,
                "Falsely claims unauthorized access to bait the user into clicking a phishing link.",
            ),
            (
                re.compile(r"\b(final\s+notice|last\s+warning|legal\s+action|lawsuit|penalty\s+fee)\b", re.IGNORECASE),
                "Intimidation / Coercion",
                20,
                "Uses extreme coercive threats of legal penalties or final notice to demand compliance.",
            ),
        ]

        # Compile credential harvesting patterns
        self.credential_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b(verify\s+your\s+(?:identity|account|password|credentials|email))\b", re.IGNORECASE),
                "Credential Harvesting",
                20,
                "Prompts the recipient to verify account identity, a common lure for credential theft.",
            ),
            (
                re.compile(r"\b(reset\s+your\s+password|update\s+your\s+(?:billing|payment|account\s+info))\b", re.IGNORECASE),
                "Credential Reset Lure",
                15,
                "Urges updating payment or password details on an external portal.",
            ),
            (
                re.compile(r"\b(enter\s+your\s+(?:otp|pin|cvv|security\s+code|two-factor\s+code))\b", re.IGNORECASE),
                "2FA Interception",
                25,
                "Directly requests one-time passwords (OTP) or card security codes.",
            ),
        ]

        # Compile financial & invoice fraud patterns
        self.financial_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b(unpaid\s+invoice|overdue\s+payment|invoice\s+#?\d+|remittance\s+advice)\b", re.IGNORECASE),
                "Invoice Fraud",
                15,
                "Uses fake invoices or overdue balance notices to prompt malicious attachment downloads.",
            ),
            (
                re.compile(r"\b(wire\s+transfer|direct\s+deposit|payroll\s+update|bitcoin|crypto\s+wallet|gift\s+card)\b", re.IGNORECASE),
                "Financial Scam / BEC",
                20,
                "Requests untraceable funds transfers, gift cards, or cryptocurrency payments.",
            ),
            (
                re.compile(r"\b(refund\s+approved|you\s+have\s+won|claim\s+your\s+(?:prize|lottery|reward))\b", re.IGNORECASE),
                "Advance-Fee / Lottery Lure",
                15,
                "Bates the user with fake lottery winnings or unverified refunds.",
            ),
        ]

        # Delivery / package tracking fraud
        self.courier_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b(package\s+(?:could\s+not\s+be\s+delivered|pending|on\s+hold)|unpaid\s+customs\s+fee|delivery\s+failed)\b", re.IGNORECASE),
                "Courier Phishing Lure",
                15,
                "Impersonates postal delivery services claiming parcel delivery issues.",
            ),
        ]

        # URL extraction regex (supports domain names and IPv4 addresses)
        self.url_pattern = re.compile(
            r"https?://(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?(?:/[^\s\"'<>]*)?",
            re.IGNORECASE,
        )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def analyze(
        self,
        body: str,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> EmailAnalysisResult:
        """
        Analyze an email for phishing, credential harvesting, sender spoofing,
        and dangerous links.
        """
        clean_body = (body or "").strip()
        clean_sender = (sender or "").strip()
        clean_subject = (subject or "").strip()
        clean_reply_to = (reply_to or "").strip()

        if not clean_body and not clean_subject:
            raise ValueError("Email body or subject must be provided for analysis.")

        raw_score = 0
        categories: Set[str] = set()
        indicators: List[str] = []
        findings: List[str] = []
        finding_details: List[EmailFindingDetail] = []
        combined_text = f"{clean_subject} {clean_body}".strip()

        # 1. Analyze Sender Headers & Identity
        sender_score = self._analyze_sender(
            clean_sender, clean_reply_to, combined_text, categories, indicators, findings, finding_details
        )
        raw_score += sender_score

        # 2. Analyze Phishing Language & Psychological Triggers
        content_score = self._analyze_content(
            combined_text, categories, indicators, findings, finding_details
        )
        raw_score += content_score

        # 3. Extract & Analyze Embedded URLs
        extracted_urls = self._extract_urls(clean_body)
        url_scan_results: List[Dict[str, Any]] = []
        url_threat_score = 0

        for url in extracted_urls[:8]:  # Limit to 8 URLs to avoid DOS
            url_res = self.url_detector.analyze(url)
            url_dict = {
                "url": url,
                "risk_score": url_res.risk_score,
                "classification": url_res.classification,
                "detected_indicators": url_res.detected_indicators,
                "explanation": url_res.explanation,
            }
            url_scan_results.append(url_dict)

            if url_res.classification == "Malicious":
                url_threat_score = max(url_threat_score, 40)
                categories.add("Malicious Embedded Link")
                indicators.append("Malicious URL")
                findings.append(f"Contains high-risk link classified as Malicious: {url}")
                finding_details.append(
                    EmailFindingDetail(
                        indicator=f"Malicious Link: {url[:45]}...",
                        title="Known Malicious / Dangerous URL",
                        risk_level="High",
                        explanation="The email directs the user to a destination flagged as dangerous or malicious.",
                    )
                )
            elif url_res.classification == "Suspicious":
                url_threat_score = max(url_threat_score, 20)
                categories.add("Suspicious Embedded Link")
                indicators.append("Suspicious URL")
                findings.append(f"Contains suspicious link: {url}")
                finding_details.append(
                    EmailFindingDetail(
                        indicator=f"Suspicious Link: {url[:45]}...",
                        title="Suspicious External Destination",
                        risk_level="Medium",
                        explanation="The embedded link uses a suspicious TLD, IP host, or redirecting URL shortener.",
                    )
                )

        raw_score += url_threat_score

        # 4. Synergistic Phishing Combination Bonus
        if "Brand Display Name Spoofing" in categories and ("Credential Harvesting" in categories or "Security Alert Pretext" in categories):
            raw_score += 25
            findings.append("Critical Phishing Combo: Brand display name spoofing paired with credential verification request.")
            finding_details.append(
                EmailFindingDetail(
                    indicator="Brand Spoofing + Credential Lure",
                    title="Targeted Brand Phishing Combo",
                    risk_level="Critical",
                    explanation="Impersonating a major brand while asking for credential verification is a classic credential phishing signature.",
                )
            )

        if "Urgency Coercion" in categories and "Malicious Embedded Link" in categories:
            raw_score += 20
            findings.append("Coercive Phishing Combo: Artificial urgency combined with dangerous destination link.")

        # Clamp Risk Score
        risk_score = min(100, max(0, raw_score))

        # 5. Four-Tier Classification: Safe, Suspicious, High Risk, Critical
        if risk_score >= 80 or "Brand Spoofing + Credential Lure" in [d.indicator for d in finding_details]:
            classification = "Critical"
        elif risk_score >= 60:
            classification = "High Risk"
        elif risk_score >= 30:
            classification = "Suspicious"
        else:
            classification = "Safe"

        # 6. Explanations & Actionable Recommendations
        explanation, recommendation, recommendations = self._generate_advice(
            classification, risk_score, clean_sender, findings, categories
        )

        return EmailAnalysisResult(
            sender=clean_sender,
            subject=clean_subject,
            body=clean_body,
            risk_score=risk_score,
            classification=classification,
            threat_categories=sorted(list(categories)),
            detected_indicators=indicators,
            findings=findings,
            finding_explanations=[d.to_dict() for d in finding_details],
            explanation=explanation,
            recommendation=recommendation,
            recommendations=recommendations,
            embedded_urls=extracted_urls,
            url_scan_results=url_scan_results,
            metadata={
                "extracted_url_count": len(extracted_urls),
                "sender_provided": bool(clean_sender),
                "subject_provided": bool(clean_subject),
            },
            engine_status="email_threat_detector_active",
        )

    # -----------------------------------------------------------------------
    # Internal Helpers
    # -----------------------------------------------------------------------

    def _analyze_sender(
        self,
        sender: str,
        reply_to: str,
        combined_text: str,
        categories: Set[str],
        indicators: List[str],
        findings: List[str],
        details: List[EmailFindingDetail],
    ) -> int:
        score = 0
        if not sender:
            return 0

        # Extract email address and display name if present: "Display Name <user@domain.com>"
        match = re.match(r"^(.*?)(?:<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>)?$", sender.strip())
        display_name = match.group(1).strip().strip('"').strip("'") if match else ""
        email_addr = match.group(2).strip() if (match and match.group(2)) else ""

        if not email_addr and "@" in sender:
            email_addr = sender.strip()

        sender_domain = email_addr.split("@")[1].lower() if "@" in email_addr else ""

        # Check for Brand Display Name Spoofing
        if display_name:
            for brand, variations in IMPERSONATED_BRANDS.items():
                if any(v.lower() in display_name.lower() for v in variations):
                    # Check if actual domain matches brand
                    if sender_domain and not any(v.lower() in sender_domain for v in variations):
                        score += 30
                        categories.add("Brand Display Name Spoofing")
                        indicators.append(f"Spoofed {brand}")
                        findings.append(f"Sender display name claims to be '{brand}', but sender domain is '{sender_domain}'.")
                        details.append(
                            EmailFindingDetail(
                                indicator=f"Spoofed Brand: {brand}",
                                title="Display Name Impersonation",
                                risk_level="High",
                                explanation=f"The sender pretends to be '{brand}' in the display name, but sends from an unrelated domain ({sender_domain}).",
                            )
                        )

        # Check for Freemail domain impersonating corporate or financial services
        if sender_domain in FREE_EMAIL_DOMAINS:
            # If body mentions banking or enterprise accounts
            if any(term in combined_text.lower() for term in ["payroll", "invoice", "wire transfer", "bank", "irs", "paypal", "microsoft", "apple id"]):
                score += 20
                categories.add("Freemail Corporate Impersonation")
                indicators.append("Freemail Business Impersonation")
                findings.append(f"Sender uses free public email provider ({sender_domain}) for official/corporate communication.")
                details.append(
                    EmailFindingDetail(
                        indicator="Public Freemail Account",
                        title="Free Email Provider Abuse",
                        risk_level="Medium",
                        explanation="Official organizations and financial institutions do not conduct corporate business from free consumer email addresses.",
                    )
                )

        # Check for Suspicious TLD
        if sender_domain:
            tld = "." + sender_domain.split(".")[-1]
            if tld in SUSPICIOUS_TLDS:
                score += 15
                categories.add("Suspicious Sender Domain TLD")
                indicators.append(f"Suspicious TLD {tld}")
                findings.append(f"Sender domain '{sender_domain}' uses high-risk TLD ({tld}).")
                details.append(
                    EmailFindingDetail(
                        indicator=f"High-Risk TLD {tld}",
                        title="Suspicious Domain Top-Level Domain",
                        risk_level="Medium",
                        explanation="The sender address uses a top-level domain frequently associated with spam and phishing campaigns.",
                    )
                )

        # Check for Mismatched Reply-To
        if reply_to and sender_domain:
            reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
            if reply_domain and reply_domain != sender_domain:
                score += 15
                categories.add("Mismatched Reply-To Address")
                indicators.append("Mismatched Reply-To")
                findings.append(f"Reply-To address ({reply_to}) routes replies to a different domain than sender ({sender_domain}).")
                details.append(
                    EmailFindingDetail(
                        indicator="Mismatched Reply-To Domain",
                        title="Reply-To Routing Anomaly",
                        risk_level="Medium",
                        explanation="Incoming replies will be routed to an alternate mailbox, a common tactic used to bypass sender verification.",
                    )
                )

        return score

    def _analyze_content(
        self,
        text: str,
        categories: Set[str],
        indicators: List[str],
        findings: List[str],
        details: List[EmailFindingDetail],
    ) -> int:
        score = 0

        # Urgency Patterns
        for pattern, cat, weight, expl in self.urgency_patterns:
            m = pattern.search(text)
            if m:
                score += weight
                categories.add(cat)
                indicators.append(m.group(0))
                findings.append(f"Detected urgency/fear trigger: '{m.group(0)}'")
                details.append(
                    EmailFindingDetail(
                        indicator=m.group(0),
                        title=cat,
                        risk_level="Medium" if weight < 20 else "High",
                        explanation=expl,
                    )
                )

        # Credential Patterns
        for pattern, cat, weight, expl in self.credential_patterns:
            m = pattern.search(text)
            if m:
                score += weight
                categories.add(cat)
                indicators.append(m.group(0))
                findings.append(f"Detected credential harvesting cue: '{m.group(0)}'")
                details.append(
                    EmailFindingDetail(
                        indicator=m.group(0),
                        title=cat,
                        risk_level="High" if weight < 25 else "Critical",
                        explanation=expl,
                    )
                )

        # Financial Patterns
        for pattern, cat, weight, expl in self.financial_patterns:
            m = pattern.search(text)
            if m:
                score += weight
                categories.add(cat)
                indicators.append(m.group(0))
                findings.append(f"Detected financial/invoice lure: '{m.group(0)}'")
                details.append(
                    EmailFindingDetail(
                        indicator=m.group(0),
                        title=cat,
                        risk_level="Medium" if weight < 20 else "High",
                        explanation=expl,
                    )
                )

        # Courier Patterns
        for pattern, cat, weight, expl in self.courier_patterns:
            m = pattern.search(text)
            if m:
                score += weight
                categories.add(cat)
                indicators.append(m.group(0))
                findings.append(f"Detected delivery scam lure: '{m.group(0)}'")
                details.append(
                    EmailFindingDetail(
                        indicator=m.group(0),
                        title=cat,
                        risk_level="Medium",
                        explanation=expl,
                    )
                )

        return score

    def _extract_urls(self, text: str) -> List[str]:
        """Extract unique URLs from text."""
        raw_urls = self.url_pattern.findall(text)
        cleaned: List[str] = []
        seen: Set[str] = set()
        for u in raw_urls:
            # strip trailing punctuation
            u_clean = u.rstrip(".,;!?:)'\">]")
            if u_clean and u_clean not in seen:
                seen.add(u_clean)
                cleaned.append(u_clean)
        return cleaned

    def _generate_advice(
        self,
        classification: str,
        score: int,
        sender: str,
        findings: List[str],
        categories: Set[str],
    ) -> Tuple[str, str, List[str]]:
        if classification == "Critical":
            explanation = (
                f"Critical email threat detected with a risk score of {score}/100. "
                "This email exhibits multiple definitive hallmarks of targeted phishing, "
                "including deceptive impersonation, credential harvesting language, and/or dangerous destinations. "
                "Do NOT click any links, open attachments, or reply."
            )
            recs = [
                "Do NOT click any links or download attachments from this email.",
                "Do not reply or provide passwords, verification codes, or personal data.",
                "Report this message as Phishing in your email client and mark as Junk.",
                "If you entered credentials, immediately change your password directly on the official website.",
            ]
            recommendation = recs[0]

        elif classification == "High Risk":
            explanation = (
                f"High-risk email detected with a risk score of {score}/100. "
                f"Contains {len(findings)} suspicious indicator(s) including artificial urgency and financial or account lures. "
                "The email appears engineered to manipulate the recipient into taking hasty actions."
            )
            recs = [
                "Verify the sender's identity through a trusted independent channel (e.g. phone call or official app).",
                "Inspect any embedded links by hovering over them rather than clicking.",
                "Never send gift cards, wire transfers, or cryptocurrency based on email requests.",
                "Ensure your email account has Multi-Factor Authentication (MFA) enabled.",
            ]
            recommendation = recs[0]

        elif classification == "Suspicious":
            explanation = (
                f"Suspicious email characteristics detected with a risk score of {score}/100. "
                "The email contains elevated social engineering cues or unverified external links. "
                "Exercise caution before complying with any requests."
            )
            recs = [
                "Carefully inspect the sender domain to ensure it matches the claimed organization.",
                "Avoid clicking external links if the email was unexpected.",
                "Contact the sender via official contact info if this is an unexpected invoice or alert.",
            ]
            recommendation = recs[0]

        else:
            explanation = (
                f"No significant phishing indicators or malicious patterns detected (Risk Score: {score}/100). "
                "The message structure appears normal for standard communication."
            )
            recs = [
                "No suspicious phishing triggers detected.",
                "Always remain vigilant and verify unexpected requests for sensitive information.",
            ]
            recommendation = recs[0]

        return explanation, recommendation, recs

"""SMS Threat Detection Engine for CyberShield.

Detects mobile smishing (SMS phishing) attack vectors:
- Urgency and fear-based language
- Fake bank / KYC / account suspension alerts
- OTP and credential harvesting scams
- Prize / lottery / reward scams
- Suspicious embedded URLs (bare IPs, shorteners, dangerous TLDs)
- Direct requests for PIN, password, OTP, CVV, or payment
- Impersonation of financial institutions, postal couriers, and government agencies
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

from app.services.url_detector import URLThreatDetector, KNOWN_SHORTENERS, SUSPICIOUS_TLDS


@dataclass
class SMSFindingDetail:
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
class SMSAnalysisResult:
    scanned_message: str
    risk_score: int
    classification: str
    threat_categories: List[str] = field(default_factory=list)
    detected_indicators: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    explanation: str = ""
    finding_explanations: List[Dict[str, str]] = field(default_factory=list)
    recommendation: str = ""
    embedded_urls: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SMSThreatDetector:
    """Heuristic SMS and Smishing Threat Detection Engine."""

    def __init__(self) -> None:
        self.url_detector = URLThreatDetector()

        # Urgency & Psychological Coercion Patterns
        self.urgency_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b(within\s+\d+\s*(?:hours?|hrs?|mins?|minutes?)|immediately|urgent(?:ly)?|act\s+now|action\s+required|right\s+now)\b", re.I),
                "Urgent deadline or time-pressure coercion language detected",
                20,
                "Cybercriminals use artificial time constraints to induce panic and prevent victims from verifying claims.",
            ),
            (
                re.compile(r"\b(account\s+will\s+be\s+(?:blocked|suspended|closed|terminated|deactivated)|last\s+warning|final\s+notice|permanent\s+closure)\b", re.I),
                "Severe penalty and account suspension ultimatum detected",
                25,
                "Threats of account termination or service revocation are typical hallmarks of social engineering scare tactics.",
            ),
            (
                re.compile(r"\b(police|arrest|lawsuit|legal\s+action|court|warrant|fine\s+of|penalty\s+charges)\b", re.I),
                "Coercive legal or criminal prosecution threat language detected",
                30,
                "Scammers use fraudulent claims of warrants or police action to intimidate targets into compliance.",
            ),
        ]

        # Fake Bank / KYC / Account Alert Patterns
        self.kyc_bank_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b((?:kyc|pan|aadhaar)\s+(?:pending|expired|verification|update|incomplete)|(?:pending|update|incomplete)\s+(?:your\s+)?(?:kyc|pan|aadhaar)|pan\s+card\s+(?:[a-z]+\s+)?(?:blocked|linked|unlinked))\b", re.I),
                "Unsolicited KYC or identity verification alert detected",
                35,
                "Fraudsters impersonate banks demanding urgent KYC/PAN renewal via unverified portals to steal identity documents.",
            ),
            (
                re.compile(r"\b(bank\s+account\s+(?:[a-z]+\s+){0,3}(?:blocked|suspended|frozen|debited)|debit\s+card\s+(?:[a-z]+\s+){0,3}(?:blocked|expired|restricted)|credit\s+card\s+(?:[a-z]+\s+){0,3}(?:blocked|suspended)|unauthorized\s+(?:transaction|access|charge|withdrawal|login))\b", re.I),
                "Fabricated banking alert or unauthorized access warning detected",
                30,
                "Fake alerts regarding card blocking or unauthorized access trick users into logging into cloned credential-harvesting portals.",
            ),
        ]

        # OTP & Credential Harvesting Patterns
        self.credential_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b((?:share|send|provide|forward|enter)\s+(?:your\s+)?(?:otp|one\s+time\s+password|pin|password|cvv))\b", re.I),
                "Explicit solicitation for OTP, PIN, password, or card CVV detected",
                45,
                "Legitimate institutions never ask for your OTP, PIN, or CVV via SMS. Sharing these grants unauthorized financial access.",
            ),
            (
                re.compile(r"\b(otp\s+to\s+(?:cancel|reverse|stop|refund|claim))\b", re.I),
                "Deceptive OTP request under the guise of canceling a transaction detected",
                40,
                "Scammers claim that giving an OTP will cancel a fictitious debit, whereas entering the OTP actually authorizes an outbound transfer.",
            ),
        ]

        # Prize, Lottery, & Refund Scams
        self.prize_lottery_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b(congratulations!?(?:\s+you\s+(?:have\s+)?won)?|lottery\s+winner|won\s+(?:\$|£|€|rs\.?|inr)?\s*[\d,]+|claim\s+(?:your\s+)?(?:prize|reward|cash|voucher|jackpot))\b", re.I),
                "Unsolicited lottery, prize, or high-value monetary reward claim detected",
                35,
                "Advance-fee and sweepstakes scams lure victims with bogus winnings to extract advance processing fees or credentials.",
            ),
            (
                re.compile(r"\b((?:processing|courier|customs|registration)\s+fee|(?:refundable\s+deposit|pay\s+(?:\$|£|€|rs\.?|inr)?\s*\d+\s+to\s+(?:receive|claim)))\b", re.I),
                "Advance processing fee or refundable deposit demand detected",
                35,
                "Requesting an upfront fee before delivering supposed winnings or loans is standard advance-fee fraud.",
            ),
        ]

        # Institution & Agency Impersonation Patterns
        self.impersonation_patterns: List[Tuple[re.Pattern, str, int, str]] = [
            (
                re.compile(r"\b(irs(?:\s+[a-z]+){0,2}|income\s+tax(?:\s+department)?|tax\s+refund|hmrc|customs\s+(?:office|border|department)|social\s+security\s+administration)\b", re.I),
                "Impersonation of revenue authority, tax office, or customs agency detected",
                35,
                "Scammers spoof tax authorities claiming a refund is pending or a tax audit requires immediate payment.",
            ),
            (
                re.compile(r"\b(fedex|usps|ups|dhl|india\s+post|royal\s+mail)\b(?=.*?\b(?:delivery\s+failed|package\s+(?:detained|on\s+hold)|update\s+(?:address|delivery)|customs\s+duty)\b)", re.I),
                "Postal / package courier delivery failure impersonation detected",
                30,
                "Fake delivery notifications ask for small fee payments or address confirmation via phishing links.",
            ),
            (
                re.compile(r"\b(sbi|hdfc|icici|axis\s+bank|punjab\s+national\s+bank|pnb|wells\s+fargo|chase\s+bank|bank\s+of\s+america|citibank)\b", re.I),
                "Major commercial banking institution named in message context",
                15,
                "Unsolicited messages naming major financial institutions must be verified directly against official banking mobile apps.",
            ),
        ]

    def analyze(self, raw_message: str) -> SMSAnalysisResult:
        """Analyze an SMS message and calculate threat risk score (0-100)."""
        text = raw_message.strip()
        if not text:
            return SMSAnalysisResult(
                scanned_message=text,
                risk_score=0,
                classification="Safe",
                threat_categories=[],
                detected_indicators=[],
                findings=["Message body is empty"],
                explanation="No message content was provided for analysis.",
                recommendation="Provide SMS text to inspect.",
                metadata={"character_count": 0, "word_count": 0, "embedded_urls": []},
            )

        score = 0
        categories: Set[str] = set()
        indicators: List[str] = []
        finding_details: List[SMSFindingDetail] = []
        is_severe_threat = False

        # 1. Evaluate Urgency & Fear Patterns
        for pattern, label, weight, explanation in self.urgency_patterns:
            if pattern.search(text):
                score += weight
                categories.add("urgency_and_coercion")
                indicators.append(label)
                finding_details.append(
                    SMSFindingDetail(
                        indicator=label,
                        title="Urgency & Psychological Coercion",
                        risk_level="High" if weight >= 25 else "Medium",
                        explanation=explanation,
                    )
                )

        # 2. Evaluate Fake Bank / KYC Alerts
        for pattern, label, weight, explanation in self.kyc_bank_patterns:
            if pattern.search(text):
                score += weight
                categories.add("fake_bank_kyc_alert")
                indicators.append(label)
                is_severe_threat = True
                finding_details.append(
                    SMSFindingDetail(
                        indicator=label,
                        title="Fake Bank / KYC Alert",
                        risk_level="High",
                        explanation=explanation,
                    )
                )

        # 3. Evaluate OTP & Credential Harvesting
        for pattern, label, weight, explanation in self.credential_patterns:
            if pattern.search(text):
                score += weight
                categories.add("credential_harvesting")
                indicators.append(label)
                is_severe_threat = True
                finding_details.append(
                    SMSFindingDetail(
                        indicator=label,
                        title="Credential / OTP Harvesting",
                        risk_level="High",
                        explanation=explanation,
                    )
                )

        # 4. Evaluate Prize & Lottery Scams
        for pattern, label, weight, explanation in self.prize_lottery_patterns:
            if pattern.search(text):
                score += weight
                categories.add("prize_lottery_scam")
                indicators.append(label)
                if weight >= 35:
                    is_severe_threat = True
                finding_details.append(
                    SMSFindingDetail(
                        indicator=label,
                        title="Prize & Lottery Fraud",
                        risk_level="High" if weight >= 35 else "Medium",
                        explanation=explanation,
                    )
                )

        # 5. Evaluate Impersonation Patterns
        for pattern, label, weight, explanation in self.impersonation_patterns:
            if pattern.search(text):
                score += weight
                categories.add("entity_impersonation")
                indicators.append(label)
                finding_details.append(
                    SMSFindingDetail(
                        indicator=label,
                        title="Entity & Authority Impersonation",
                        risk_level="High" if weight >= 30 else "Medium",
                        explanation=explanation,
                    )
                )

        # 6. Extract and Deep-Inspect Embedded URLs
        embedded_urls = re.findall(r"https?://[^\s]+|[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}/[^\s]*", text)
        cleaned_urls: List[str] = []
        for raw_url in embedded_urls:
            candidate = raw_url.strip(".,;:)'\"")
            if "." in candidate and len(candidate) > 4:
                cleaned_urls.append(candidate)

        for url_str in cleaned_urls:
            url_res = self.url_detector.analyze(url_str)
            categories.add("embedded_url")

            primary_ind = url_res.detected_indicators[0] if url_res.detected_indicators else "Threat signals detected"

            if url_res.risk_score >= 70 or any("IPv4" in ind or "bare IP" in ind.lower() for ind in url_res.detected_indicators):
                score += 40
                is_severe_threat = True
                label = f"High-risk malicious URL detected in SMS ({primary_ind}): {url_str}"
                indicators.append(label)
                finding_details.append(
                    SMSFindingDetail(
                        indicator=label,
                        title="Malicious Destination Link",
                        risk_level="High",
                        explanation=f"The embedded link ({url_str}) exhibits critical threat indicators: {'; '.join(url_res.detected_indicators[:2])}.",
                    )
                )
            elif url_res.risk_score >= 30:
                score += 25
                label = f"Suspicious or unverified URL detected in SMS ({primary_ind}): {url_str}"
                indicators.append(label)
                finding_details.append(
                    SMSFindingDetail(
                        indicator=label,
                        title="Suspicious Destination Link",
                        risk_level="Medium",
                        explanation=f"The embedded link ({url_str}) scored {url_res.risk_score}/100 with warning signs: {'; '.join(url_res.detected_indicators[:2])}.",
                    )
                )
            else:
                # Even safe URLs in an unsolicited context get a baseline note
                score += 5

        # Compound Threat Amplification:
        # If SMS combines urgency + fake bank/impersonation + embedded URL, that is a textbook smishing attack
        if ("urgency_and_coercion" in categories or "fake_bank_kyc_alert" in categories) and "embedded_url" in categories:
            score += 20
            is_severe_threat = True
            amp_label = "Multi-vector smishing signature: High-pressure urgency combined with embedded hyperlink"
            if amp_label not in indicators:
                indicators.insert(0, amp_label)
                finding_details.insert(
                    0,
                    SMSFindingDetail(
                        indicator=amp_label,
                        title="Active Smishing Signature",
                        risk_level="High",
                        explanation="Attackers combine urgency and account alerts with destination links to maximize victim click-through rates.",
                    ),
                )

        # Cap score between 0 and 100
        final_score = min(100, max(0, score))

        # Classification mapping
        if is_severe_threat or final_score >= 70:
            classification = "Malicious"
            final_score = max(70, final_score)
        elif final_score >= 30 or len(indicators) >= 1:
            classification = "Suspicious"
            final_score = max(30, final_score)
        else:
            classification = "Safe"
            final_score = min(25, final_score)

        # Generate Findings List (combining indicators or positive note)
        findings = list(indicators)
        if not findings:
            findings.append("No smishing, urgency, credential harvesting, or suspicious links detected")
            findings.append(f"Standard conversational language verified ({len(text)} characters)")

        # Generate Explanation
        if classification == "Malicious":
            explanation = (
                f"This message scored {final_score}/100 and presents severe cyber threat indicators: "
                f"{'; '.join(indicators[:2])}. It displays clear characteristics of financial smishing, "
                "credential harvesting, or impersonation fraud."
            )
        elif classification == "Suspicious":
            explanation = (
                f"This message scored {final_score}/100 and exhibits {len(indicators)} warning indicator(s): "
                f"{'; '.join(indicators[:2])}. Caution is strongly advised before replying or clicking any links."
            )
        else:
            explanation = (
                "The SMS contains no recognized smishing indicators, coercion patterns, or high-risk URLs. "
                "It appears to be typical communication."
            )

        # Generate Recommendation
        if classification == "Malicious":
            recommendation = (
                "Do NOT click any links, do NOT reply, and do NOT share any OTPs, PINs, or banking details. "
                "Block the sender immediately and report the message to your cellular carrier or cybercrime authority."
            )
        elif classification == "Suspicious":
            recommendation = (
                "Do not open links directly from this message. Verify the sender's identity through an independent, "
                "trusted channel (e.g. your official banking app or the organization's published phone number)."
            )
        else:
            recommendation = (
                "Message appears benign. Always exercise standard vigilance with unsolicited messages."
            )

        # Extract matched flagged keywords for metadata compatibility
        flagged_kw_pool = [
            "urgent", "immediately", "suspended", "account suspended", "verify", "otp", "wire transfer",
            "bank", "kyc", "pan", "blocked", "lottery", "prize", "password", "pin", "cvv"
        ]
        matched_keywords = [kw for kw in flagged_kw_pool if kw in text.lower()]

        return SMSAnalysisResult(
            scanned_message=text,
            risk_score=final_score,
            classification=classification,
            threat_categories=sorted(list(categories)),
            detected_indicators=indicators,
            findings=findings,
            explanation=explanation,
            finding_explanations=[d.to_dict() for d in finding_details],
            recommendation=recommendation,
            embedded_urls=cleaned_urls,
            metadata={
                "character_count": len(text),
                "word_count": len(text.split()),
                "embedded_urls_count": len(cleaned_urls),
                "threat_categories_count": len(categories),
                "flagged_keywords_found": matched_keywords,
            },
        )

"""URL Threat Detection Engine for CyberShield.

Performs heuristic and structural threat detection on URLs:
- IP address instead of domain
- URL shortening services
- Suspicious phishing and social engineering keywords
- Excessive subdomains (domain spoofing)
- User-info '@' delimiter abuse
- Plain insecure HTTP transport
- High-abuse / suspicious top-level domains (TLDs)
"""

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse, unquote

# ---------------------------------------------------------------------------
# Constants & Heuristic Dictionaries
# ---------------------------------------------------------------------------

KNOWN_SHORTENERS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
    "bl.ink",
    "tiny.cc",
    "lnkd.in",
    "snip.ly",
    "tr.im",
    "s.id",
    "qr.ae",
    "adf.ly",
    "bit.do",
    "mcaf.ee",
    "cli.re",
}

SUSPICIOUS_TLDS: Set[str] = {
    ".xyz",
    ".top",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".buzz",
    ".work",
    ".click",
    ".rest",
    ".country",
    ".fit",
    ".kim",
    ".live",
    ".loan",
    ".men",
    ".stream",
    ".win",
    ".racing",
    ".surf",
    ".monster",
    ".icu",
    ".sbs",
    ".cfd",
    ".vip",
    ".casa",
    ".date",
    ".faith",
    ".download",
    ".party",
    ".science",
    ".trade",
    ".webcam",
    ".ninja",
}

SUSPICIOUS_KEYWORDS: List[str] = [
    "login",
    "signin",
    "log-in",
    "sign-in",
    "verify",
    "verification",
    "authenticate",
    "authentication",
    "password",
    "credential",
    "security-update",
    "account-update",
    "account-locked",
    "verify-account",
    "suspended",
    "restore-account",
    "recover-account",
    "banking",
    "paypal",
    "wallet",
    "crypto",
    "claim-reward",
    "free-gift",
    "invoice-payment",
    "urgent",
    "wire-transfer",
]

LEGITIMATE_TRUSTED_DOMAINS: Set[str] = {
    "google.com",
    "www.google.com",
    "github.com",
    "www.github.com",
    "microsoft.com",
    "www.microsoft.com",
    "apple.com",
    "www.apple.com",
    "amazon.com",
    "www.amazon.com",
    "python.org",
    "docs.python.org",
    "flutter.dev",
    "dart.dev",
    "wikipedia.org",
    "www.wikipedia.org",
}


@dataclass
class FindingDetail:
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
class URLAnalysisResult:
    scanned_url: str
    risk_score: int
    classification: str
    detected_indicators: List[str] = field(default_factory=list)
    explanation: str = ""
    finding_explanations: List[Dict[str, str]] = field(default_factory=list)
    recommendation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class URLThreatDetector:
    """Heuristic URL Threat Detection Engine."""

    def analyze(self, raw_url: str) -> URLAnalysisResult:
        """Analyze a URL and calculate a risk score from 0 to 100."""
        cleaned_url = raw_url.strip()
        
        # Prepend https if no scheme provided
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned_url):
            parsed_scheme = "http" if cleaned_url.startswith("http:") else "https"
            cleaned_url = f"https://{cleaned_url}"
        
        parsed = urlparse(cleaned_url)
        hostname = (parsed.hostname or "").lower()
        path_and_query = unquote(f"{parsed.path}?{parsed.query}").lower()
        
        indicators: List[str] = []
        finding_details: List[FindingDetail] = []
        score: int = 0
        significant_threat: bool = False

        # Heuristic 1: IP address instead of domain
        is_ip, ip_desc = self._check_ip_address(hostname)
        if is_ip:
            score += 30
            significant_threat = True
            ind_text = f"Host uses bare IPv4 address ({ip_desc}) rather than a registered DNS domain name"
            indicators.append(ind_text)
            finding_details.append(FindingDetail(
                indicator=ind_text,
                title="Raw IP Address Host",
                risk_level="High",
                explanation="Using a raw numeric IP address bypasses DNS reputation filters, domain registration transparency, and standard TLS certification.",
            ))

        # Heuristic 2: URL shortening service
        is_shortener, shortener_name = self._check_url_shortener(hostname)
        if is_shortener:
            score += 20
            significant_threat = True
            ind_text = f"URL shortening service detected ({shortener_name}), which obscures the true destination"
            indicators.append(ind_text)
            finding_details.append(FindingDetail(
                indicator=ind_text,
                title="URL Shortener Obfuscation",
                risk_level="Medium",
                explanation="URL shortening services mask the final target domain and path, concealing destination reputation before navigation.",
            ))

        # Heuristic 3: @ symbol in URL (user-info credential spoofing)
        if "@" in raw_url:
            score += 25
            significant_threat = True
            ind_text = "URL contains '@' symbol (user-info delimiter) commonly used for visual domain spoofing"
            indicators.append(ind_text)
            finding_details.append(FindingDetail(
                indicator=ind_text,
                title="User-Info '@' Spoofing",
                risk_level="High",
                explanation="Browsers treat characters before '@' as authentication user-info and connect to the host following '@', misleading users with fake brand prefixes.",
            ))

        # Heuristic 4: Insecure HTTP protocol
        is_secure_proto = parsed.scheme.lower() == "https"
        if not is_secure_proto:
            score += 15
            ind_text = "Insecure plain HTTP transport protocol detected (lacks TLS encryption)"
            indicators.append(ind_text)
            finding_details.append(FindingDetail(
                indicator=ind_text,
                title="Unencrypted HTTP Transport",
                risk_level="Medium",
                explanation="The request is transmitted in cleartext without TLS encryption, exposing sensitive data to interception and tampering.",
            ))
        else:
            # Positive structural indicator for clean display
            pass

        # Heuristic 5: Suspicious Top-Level Domain (TLD)
        is_suspicious_tld, tld_name = self._check_suspicious_tld(hostname)
        if is_suspicious_tld:
            score += 20
            significant_threat = True
            ind_text = f"High-risk top-level domain detected ({tld_name}) with elevated correlation to abuse"
            indicators.append(ind_text)
            finding_details.append(FindingDetail(
                indicator=ind_text,
                title="High-Abuse Top-Level Domain",
                risk_level="Medium",
                explanation=f"The domain resides on '{tld_name}', a top-level domain with statistically high abuse and disposable phishing rates.",
            ))

        # Heuristic 6: Excessive subdomains
        subdomain_count = self._count_subdomains(hostname)
        if subdomain_count >= 3:
            score += 20
            significant_threat = True
            ind_text = f"Excessive subdomains detected ({subdomain_count} levels), commonly used for brand impersonation"
            indicators.append(ind_text)
            finding_details.append(FindingDetail(
                indicator=ind_text,
                title="Excessive Subdomains",
                risk_level="Medium",
                explanation="Multiple nested subdomain levels are frequently employed to create deceptive URLs that mimic legitimate brand names.",
            ))

        # Heuristic 7: Suspicious phishing keywords
        matched_keywords = self._find_suspicious_keywords(hostname, path_and_query)
        if matched_keywords:
            is_trusted = any(hostname == trusted or hostname.endswith(f".{trusted}") for trusted in LEGITIMATE_TRUSTED_DOMAINS)
            if not is_trusted:
                keyword_penalty = min(30, max(20, len(matched_keywords) * 15))
                score += keyword_penalty
                significant_threat = True
                ind_text = f"Suspicious phishing keyword(s) detected: {', '.join(matched_keywords)}"
                indicators.append(ind_text)
                finding_details.append(FindingDetail(
                    indicator=ind_text,
                    title="Phishing & Urgency Keywords",
                    risk_level="High" if any(k in ["login", "verify", "banking", "password", "credential"] for k in matched_keywords) else "Medium",
                    explanation=f"The URL contains sensitive credential-harvesting or urgency keywords ({', '.join(matched_keywords)}) on an untrusted domain.",
                ))

        # Whitelist mitigation: trusted domains without deceptive tricks stay safe
        if any(hostname == trusted or hostname.endswith(f".{trusted}") for trusted in LEGITIMATE_TRUSTED_DOMAINS):
            if not is_ip and "@" not in raw_url and not is_shortener and is_secure_proto:
                score = 0
                significant_threat = False

        # Requirement 8: Ensure suspicious URLs never get classified Safe when significant indicators exist
        if significant_threat:
            score = max(30, score)

        # Clamp score between 0 and 100
        risk_score = max(0, min(100, score))

        # Classify URL based on score
        classification = self._classify(risk_score)

        # Double check: if significant threat exists, ensure classification is at least Suspicious
        if significant_threat and classification == "Safe":
            classification = "Suspicious"
            risk_score = max(30, risk_score)

        # Build comprehensive explanation and recommendation
        explanation = self._build_explanation(classification, risk_score, indicators)
        recommendation = self._build_recommendation(classification)

        # Backward-compatible metadata
        metadata = {
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "path": parsed.path or "/",
            "port": parsed.port or (443 if is_secure_proto else 80),
            "query_params_count": len(parsed.query.split("&")) if parsed.query else 0,
        }

        return URLAnalysisResult(
            scanned_url=cleaned_url,
            risk_score=risk_score,
            classification=classification,
            detected_indicators=indicators,
            explanation=explanation,
            finding_explanations=[f.to_dict() for f in finding_details],
            recommendation=recommendation,
            metadata=metadata,
        )

    def _check_ip_address(self, hostname: str) -> Tuple[bool, str]:
        """Check if the hostname is an IPv4 or IPv6 address."""
        if not hostname:
            return False, ""
        
        clean_host = hostname.strip("[]")
        try:
            ip = ipaddress.ip_address(clean_host)
            return True, str(ip)
        except ValueError:
            pass

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            return True, hostname

        return False, ""

    def _check_url_shortener(self, hostname: str) -> Tuple[bool, str]:
        """Check if hostname matches known URL shortening services."""
        if hostname in KNOWN_SHORTENERS:
            return True, hostname
        for shortener in KNOWN_SHORTENERS:
            if hostname.endswith(f".{shortener}"):
                return True, shortener
        return False, ""

    def _check_suspicious_tld(self, hostname: str) -> Tuple[bool, str]:
        """Check if hostname ends with a known high-risk TLD."""
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return True, tld
        return False, ""

    def _count_subdomains(self, hostname: str) -> int:
        """Count subdomain levels before domain and TLD."""
        if not hostname or self._check_ip_address(hostname)[0]:
            return 0
        parts = hostname.split(".")
        if len(parts) > 2:
            return len(parts) - 2
        return 0

    def _find_suspicious_keywords(self, hostname: str, path_and_query: str) -> List[str]:
        """Detect keywords commonly used in phishing campaigns."""
        target_text = f"{hostname}/{path_and_query}"
        matched: List[str] = []
        for kw in SUSPICIOUS_KEYWORDS:
            pattern = rf"(^|[^a-zA-Z0-9]){re.escape(kw)}([^a-zA-Z0-9]|$)"
            if re.search(pattern, target_text):
                matched.append(kw)
        return matched

    def _classify(self, score: int) -> str:
        """Classify URL based on risk score."""
        if score <= 29:
            return "Safe"
        elif score <= 69:
            return "Suspicious"
        else:
            return "Malicious"

    def _build_explanation(self, classification: str, score: int, indicators: List[str]) -> str:
        """Construct detailed narrative explanation for the risk score."""
        if classification == "Safe":
            if not indicators:
                return "The URL exhibits no suspicious characteristics. It uses TLS encryption, standard DNS domain registration, and conforms to expected web standards."
            return f"The URL has a low risk score ({score}/100) with minor warnings: {'; '.join(indicators)}."
        elif classification == "Suspicious":
            return f"The URL scored {score}/100 and presents {len(indicators)} significant warning indicator(s): {'; '.join(indicators)}. Caution is recommended."
        else:
            return f"The URL scored {score}/100 and exhibits severe threat indicators: {'; '.join(indicators)}. High probability of phishing, credential harvesting, or malicious intent."

    def _build_recommendation(self, classification: str) -> str:
        """Construct actionable recommendation for the user."""
        if classification == "Safe":
            return "Safe to browse. Always verify that the domain name in the address bar matches the intended organization."
        elif classification == "Suspicious":
            return "Do not enter passwords, credit card details, or sensitive personal information. Verify the sender or link source through an independent communication channel."
        else:
            return "Do not open this URL. Block the sender and report the destination as a malicious phishing attempt."

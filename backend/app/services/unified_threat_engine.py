"""CyberShield Unified Threat Engine.

Provides standard threat scoring, normalized risk levels, confidence scores,
and consistent verdict mapping across all detection vectors:
- URL Phishing
- SMS Smishing
- Email Phishing
- QR Code Phishing (Quishing)
- APK Security & Permission Malware
- Static File Threats
- Screenshot Scam OCR
- Real-Time Notifications
- Caller ID & Spam Phone Screening
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionVerdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CRITICAL = "CRITICAL"


# Configurable risk thresholds
RISK_THRESHOLD_MEDIUM = 25
RISK_THRESHOLD_HIGH = 50
RISK_THRESHOLD_CRITICAL = 75


def score_to_risk_level(score: int) -> RiskLevel:
    """Map a 0-100 score to a standardized RiskLevel enum.

    Mapping:
    - 0–24:   LOW
    - 25–49:  MEDIUM
    - 50–74:  HIGH
    - 75–100: CRITICAL
    """
    clamped = max(0, min(100, int(score)))
    if clamped >= RISK_THRESHOLD_CRITICAL:
        return RiskLevel.CRITICAL
    elif clamped >= RISK_THRESHOLD_HIGH:
        return RiskLevel.HIGH
    elif clamped >= RISK_THRESHOLD_MEDIUM:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def score_to_verdict(score: int, significant_indicators: bool = False) -> DetectionVerdict:
    """Map a 0-100 score to a DetectionVerdict enum."""
    clamped = max(0, min(100, int(score)))
    if clamped >= RISK_THRESHOLD_CRITICAL:
        return DetectionVerdict.CRITICAL
    elif clamped >= RISK_THRESHOLD_HIGH:
        return DetectionVerdict.MALICIOUS
    elif clamped >= RISK_THRESHOLD_MEDIUM or significant_indicators:
        return DetectionVerdict.SUSPICIOUS
    return DetectionVerdict.SAFE


@dataclass
class StandardThreatResult:
    """Standardized result returned across all CyberShield threat detectors."""

    threat_score: int
    risk_level: RiskLevel
    verdict: DetectionVerdict
    confidence: float
    evidence: List[str]
    detection_reasons: List[str]
    suspicious_indicators: List[str]
    recommended_action: str
    source_module: str
    target: str
    scan_id: str = field(default_factory=lambda: f"scan-{uuid.uuid4().hex[:12]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ai_explanation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "threat_score": self.threat_score,
            "risk_score": self.threat_score,  # backward compatibility alias
            "risk_level": self.risk_level.value,
            "classification": self.verdict.value.title(),  # e.g. "Safe", "Suspicious", "Critical"
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence,
            "findings": self.evidence,  # backward compatibility alias
            "detection_reasons": self.detection_reasons,
            "suspicious_indicators": self.suspicious_indicators,
            "detected_indicators": self.suspicious_indicators,  # backward compatibility alias
            "recommended_action": self.recommended_action,
            "source_module": self.source_module,
            "target": self.target,
            "timestamp": self.timestamp,
            "ai_explanation": self.ai_explanation,
            "metadata": self.metadata,
        }


def standardize_scan_result(
    source_module: str,
    target: str,
    score: int,
    indicators: Optional[List[str]] = None,
    findings: Optional[List[str]] = None,
    recommended_action: Optional[str] = None,
    confidence: float = 0.90,
    ai_explanation: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> StandardThreatResult:
    """Factory helper to construct a StandardThreatResult with consistent thresholds."""
    clamped_score = max(0, min(100, int(score)))
    level = score_to_risk_level(clamped_score)
    verdict = score_to_verdict(clamped_score, bool(indicators))

    evidence_list = findings or indicators or []
    if not evidence_list:
        evidence_list = ["No threat signatures or deceptive anomalies detected."]

    indicators_list = indicators or []

    if not recommended_action:
        if level == RiskLevel.CRITICAL:
            recommended_action = "Critical threat: Immediately isolate, block sender, and do not execute or submit credentials."
        elif level == RiskLevel.HIGH:
            recommended_action = "High risk: Highly suspicious indicators present. Do not proceed or enter credentials."
        elif level == RiskLevel.MEDIUM:
            recommended_action = "Suspicious: Exercise caution and independently verify the source before interaction."
        else:
            recommended_action = "Safe: Conforms to expected baseline security standards."

    return StandardThreatResult(
        threat_score=clamped_score,
        risk_level=level,
        verdict=verdict,
        confidence=confidence,
        evidence=evidence_list,
        detection_reasons=evidence_list,
        suspicious_indicators=indicators_list,
        recommended_action=recommended_action,
        source_module=source_module.upper(),
        target=target,
        ai_explanation=ai_explanation,
        metadata=metadata or {},
    )


"""CyberShield Security Analytics & Dashboard Metrics Service.

Provides aggregated scan statistics, scanner-wise telemetry, daily trend analysis,
transparent CyberShield Security Score calculation, and community threat integration.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.services.history_service import HistoryRepository
from app.services.community_service import CommunityRepository


class AnalyticsService:
    """Calculates security metrics, risk distribution, trends, and security scores."""

    def __init__(
        self,
        history_repo: HistoryRepository,
        community_repo: CommunityRepository,
    ):
        self.history_repo = history_repo
        self.community_repo = community_repo
        self._lock = threading.Lock()

    def get_dashboard_analytics(
        self,
        user_id: Optional[str] = None,
        days: int = 30,
    ) -> Dict[str, Any]:
        """
        Aggregate comprehensive dashboard statistics:
        - Total, Safe, Suspicious, High Risk, Critical counts
        - Threat detection rate
        - Scanner-wise distribution
        - Activity trends over time (daily)
        - Security score (0-100) with transparent rationale
        - Community threat intelligence overview
        - Recent scan activity
        """
        now = datetime.now(timezone.utc)
        cutoff_iso = None
        if days > 0:
            cutoff_dt = now - timedelta(days=days)
            cutoff_iso = cutoff_dt.isoformat()

        # Query all matching scans from SQLite
        scans = self._query_scans(user_id=user_id, cutoff_iso=cutoff_iso)

        total_scans = len(scans)
        safe_count = 0
        suspicious_count = 0
        high_risk_count = 0
        critical_count = 0

        # Scanner-wise counters
        known_scanners = [
            "URL",
            "SMS",
            "QR",
            "SCREENSHOT",
            "APK",
            "PERMISSIONS",
            "EMAIL",
            "FILE",
        ]
        scanner_stats: Dict[str, Dict[str, int]] = {
            s: {"total": 0, "safe": 0, "threats": 0} for s in known_scanners
        }

        # Daily trends grouping: { "YYYY-MM-DD": {"total": 0, "safe": 0, "threats": 0} }
        trends_map: Dict[str, Dict[str, int]] = {}

        # Pre-populate trends for the last 7 or N days
        trend_days = min(days if days > 0 else 14, 14)
        for d in range(trend_days - 1, -1, -1):
            day_str = (now - timedelta(days=d)).strftime("%Y-%m-%d")
            trends_map[day_str] = {"total": 0, "safe": 0, "threats": 0}

        for s in scans:
            cls = (s.get("classification") or "Safe").strip().lower()
            score = int(s.get("risk_score") or 0)
            scan_type = (s.get("scan_type") or "URL").strip().upper()
            ts_str = s.get("timestamp") or ""

            # Classification categorization
            is_critical = score >= 80 or cls == "critical"
            is_high_risk = not is_critical and (score >= 60 or cls in ("high risk", "malicious", "danger"))
            is_suspicious = not is_critical and not is_high_risk and (score >= 30 or cls == "suspicious")
            is_safe = not is_critical and not is_high_risk and not is_suspicious

            if is_critical:
                critical_count += 1
            elif is_high_risk:
                high_risk_count += 1
            elif is_suspicious:
                suspicious_count += 1
            else:
                safe_count += 1

            # Scanner-wise tracking
            if scan_type in scanner_stats:
                scanner_stats[scan_type]["total"] += 1
                if is_safe:
                    scanner_stats[scan_type]["safe"] += 1
                else:
                    scanner_stats[scan_type]["threats"] += 1
            else:
                scanner_stats[scan_type] = {
                    "total": 1,
                    "safe": 1 if is_safe else 0,
                    "threats": 0 if is_safe else 1,
                }

            # Date tracking for trends
            if ts_str:
                try:
                    date_key = ts_str[:10]  # YYYY-MM-DD
                    if date_key in trends_map:
                        trends_map[date_key]["total"] += 1
                        if is_safe:
                            trends_map[date_key]["safe"] += 1
                        else:
                            trends_map[date_key]["threats"] += 1
                except Exception:
                    pass

        threat_count = suspicious_count + high_risk_count + critical_count
        threat_rate = (
            round((threat_count / total_scans) * 100, 1) if total_scans > 0 else 0.0
        )

        # Transparent Security Score Calculation (0-100)
        security_score_data = self._calculate_security_score(
            total_scans=total_scans,
            safe_count=safe_count,
            suspicious_count=suspicious_count,
            high_risk_count=high_risk_count,
            critical_count=critical_count,
        )

        # Activity trends list formatted chronologically
        trends_list = [
            {"date": k, "total": v["total"], "safe": v["safe"], "threats": v["threats"]}
            for k, v in sorted(trends_map.items())
        ]

        # Recent scans (up to 5 most recent)
        recent_scans = [
            {
                "id": s["id"],
                "scan_id": s.get("scan_id", s["id"]),
                "scan_type": s["scan_type"],
                "target": s["target"],
                "risk_score": s["risk_score"],
                "classification": s["classification"],
                "timestamp": s["timestamp"],
            }
            for s in scans[:5]
        ]

        # Community threat intelligence metrics
        community_metrics = self.community_repo.get_stats()

        return {
            "time_range_days": days,
            "total_scans": total_scans,
            "safe_scans": safe_count,
            "suspicious_scans": suspicious_count,
            "high_risk_scans": high_risk_count,
            "critical_scans": critical_count,
            "threat_detection_rate": threat_rate,
            "security_score": security_score_data,
            "scanner_breakdown": scanner_stats,
            "risk_distribution": {
                "safe": safe_count,
                "suspicious": suspicious_count,
                "high_risk": high_risk_count,
                "critical": critical_count,
            },
            "activity_trends": trends_list,
            "community_stats": {
                "total_reports": community_metrics.get("total_reports", 0),
                "distinct_targets": community_metrics.get("distinct_targets", 0),
                "active_reporters": community_metrics.get("active_reporters", 0),
                "verified_threats": community_metrics.get("verified_threats", 0),
            },
            "recent_scans": recent_scans,
            "timestamp": now.isoformat(),
        }

    def _query_scans(
        self,
        user_id: Optional[str] = None,
        cutoff_iso: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query persistent SQLite storage, filtering by user_id and cutoff timestamp."""
        conn = sqlite3.connect(self.history_repo.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row

        query = "SELECT * FROM scan_history WHERE 1=1"
        params: List[Any] = []

        if cutoff_iso:
            query += " AND timestamp >= ?"
            params.append(cutoff_iso)

        query += " ORDER BY timestamp DESC"

        try:
            with conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
        finally:
            conn.close()

        results = []
        for r in rows:
            details = {}
            if r["details_json"]:
                try:
                    details = json.loads(r["details_json"])
                except Exception:
                    details = {}

            # User isolation check: if user_id is provided, match against details['user_id']
            if user_id and details.get("user_id"):
                if details["user_id"] != user_id:
                    continue

            results.append(
                {
                    "id": r["id"],
                    "scan_id": r["id"],
                    "scan_type": r["scan_type"],
                    "target": r["target"],
                    "risk_score": r["risk_score"],
                    "classification": r["classification"],
                    "summary": r["summary"],
                    "status_badge": r["status_badge"],
                    "timestamp": r["timestamp"],
                    "details": details,
                }
            )
        return results

    def _calculate_security_score(
        self,
        total_scans: int,
        safe_count: int,
        suspicious_count: int,
        high_risk_count: int,
        critical_count: int,
    ) -> Dict[str, Any]:
        """
        Calculate CyberShield Security Score (0-100).
        Transparently explains the mathematical calculation and
        strictly includes non-absolute protection advisories.
        """
        if total_scans == 0:
            return {
                "score": 70,
                "status": "Baseline Exposure",
                "tier": "Neutral",
                "calculation_explanation": (
                    "No scan telemetry recorded yet. CyberShield assigns a baseline score of 70/100. "
                    "Performing scans across URLs, messages, files, and applications establishes your active defense posture."
                ),
                "disclaimer": (
                    "Advisory Notice: CyberShield Security Score reflects evaluated scan telemetry and cyber hygiene. "
                    "No security system can guarantee 100% device immunity against emerging zero-day vulnerabilities."
                ),
            }

        # Deduct penalties for threat encounters and award bonuses for clean inspections
        penalty = (critical_count * 20) + (high_risk_count * 10) + (suspicious_count * 4)
        reward = safe_count * 2

        raw_score = 100 - penalty + reward
        clamped_score = max(10, min(98, raw_score))  # Never 100% to reflect realistic zero-day defense boundaries

        if clamped_score >= 85:
            status = "Strong Defense Posture"
            tier = "Optimal"
        elif clamped_score >= 65:
            status = "Moderate Protection"
            tier = "Guarded"
        elif clamped_score >= 40:
            status = "Elevated Threat Exposure"
            tier = "Warning"
        else:
            status = "Critical Exposure Detected"
            tier = "Danger"

        explanation = (
            f"Score calculated from {total_scans} recorded scans. "
            f"Baseline 100 pts minus threat penalties (Critical: -{critical_count * 20}, "
            f"High Risk: -{high_risk_count * 10}, Suspicious: -{suspicious_count * 4}) "
            f"plus verified safe interactions (+{min(reward, 20)} pts). "
            f"Current defense rating: {status} ({clamped_score}/100)."
        )

        disclaimer = (
            "Advisory Notice: The CyberShield Security Score reflects evaluated scan telemetry and observed digital hygiene. "
            "Never assume total immunity: no software can guarantee absolute protection against targeted zero-day exploits."
        )

        return {
            "score": clamped_score,
            "status": status,
            "tier": tier,
            "calculation_explanation": explanation,
            "disclaimer": disclaimer,
        }


"""CyberShield Security Alerts Service & SQLite Repository.

Generates and manages actionable security alerts for Critical, High Risk, and Suspicious
scan findings (URLs, SMS, QR, APKs, Files, Permissions) and community-confirmed threats,
with automatic deduplication to avoid repeat alerts for the same event.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AlertRepository:
    """Thread-safe SQLite repository for managing security alerts."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(backend_dir, "cybershield_audit.db")

        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create security alerts table and indexes if they do not exist."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_alerts (
                        id TEXT PRIMARY KEY,
                        user_id TEXT,
                        scan_id TEXT,
                        event_key TEXT UNIQUE,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        category TEXT NOT NULL,
                        target TEXT NOT NULL,
                        risk_score INTEGER NOT NULL DEFAULT 0,
                        explanation TEXT NOT NULL,
                        recommended_actions_json TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'unread',
                        is_read INTEGER NOT NULL DEFAULT 0,
                        is_resolved INTEGER NOT NULL DEFAULT 0,
                        timestamp TEXT NOT NULL,
                        resolved_at TEXT,
                        metadata_json TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON security_alerts(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp DESC)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_scan_id ON security_alerts(scan_id)")
                conn.commit()

    def clear_all(self) -> None:
        """Clear all alerts (primarily used for test isolation)."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM security_alerts")
                conn.commit()

    def create_alert(
        self,
        title: str,
        severity: str,
        category: str,
        target: str,
        risk_score: int,
        explanation: str,
        recommended_actions: List[str],
        user_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        event_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create or return existing alert if deduplication key matches."""
        severity_norm = severity.lower()
        if severity_norm not in ("critical", "high", "medium", "low", "info"):
            severity_norm = "medium"

        category_norm = category.upper()
        if not event_key:
            event_key = f"{user_id or 'global'}:{scan_id or target}:{category_norm}:{severity_norm}"

        with self._lock:
            with self._get_connection() as conn:
                # Deduplication check by event_key or scan_id
                cursor = conn.execute(
                    "SELECT * FROM security_alerts WHERE event_key = ? OR (scan_id IS NOT NULL AND scan_id = ?)",
                    (event_key, scan_id if scan_id else "__none__"),
                )
                existing = cursor.fetchone()
                if existing:
                    return self._row_to_dict(existing)

                alert_id = f"alert-{uuid.uuid4().hex[:10]}"
                timestamp = datetime.now(timezone.utc).isoformat()
                actions_json = json.dumps(recommended_actions or [])
                metadata_json = json.dumps(metadata or {})

                conn.execute(
                    """
                    INSERT INTO security_alerts (
                        id, user_id, scan_id, event_key, title, severity, category, target,
                        risk_score, explanation, recommended_actions_json, status, is_read,
                        is_resolved, timestamp, resolved_at, metadata_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unread', 0, 0, ?, NULL, ?)
                    """,
                    (
                        alert_id,
                        user_id,
                        scan_id,
                        event_key,
                        title,
                        severity_norm,
                        category_norm,
                        target,
                        risk_score,
                        explanation,
                        actions_json,
                        timestamp,
                        metadata_json,
                    ),
                )
                conn.commit()

                cursor = conn.execute("SELECT * FROM security_alerts WHERE id = ?", (alert_id,))
                row = cursor.fetchone()
                return self._row_to_dict(row)

    def evaluate_and_create_scan_alert(
        self,
        scan_event: Dict[str, Any],
        user_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate a scan event and generate a security alert if the finding is
        Critical, High Risk, or Suspicious. Automatically deduplicates.
        """
        risk_score = scan_event.get("risk_score", 0)
        classification = str(scan_event.get("classification", "Safe")).strip()
        scan_type = str(scan_event.get("scan_type", "URL")).upper()
        target = str(scan_event.get("target", "Target"))
        scan_id = scan_event.get("id") or scan_event.get("scan_id")

        cls_lower = classification.lower()
        is_critical = risk_score >= 70 or cls_lower in ("critical", "malicious")
        is_high = risk_score >= 50 or cls_lower in ("high risk", "danger")
        is_suspicious = risk_score >= 35 or cls_lower in ("suspicious", "warning")

        if not (is_critical or is_high or is_suspicious):
            return None  # Safe finding, no alert required

        if is_critical:
            severity = "critical"
        elif is_high:
            severity = "high"
        else:
            severity = "medium"

        # Generate contextual title, explanation, and actionable recommendations
        title, default_explanation, recommendations = self._build_scan_alert_content(
            scan_type=scan_type,
            target=target,
            severity=severity,
            risk_score=risk_score,
        )

        explanation = scan_event.get("summary") or default_explanation

        return self.create_alert(
            title=title,
            severity=severity,
            category=scan_type,
            target=target,
            risk_score=risk_score,
            explanation=explanation,
            recommended_actions=recommendations,
            user_id=user_id,
            scan_id=scan_id,
            metadata={"source": "scanner_engine", "classification": classification},
        )

    def evaluate_and_create_community_alert(
        self,
        report_data: Dict[str, Any],
        user_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a community threat report and trigger an alert if confirmed/verified."""
        category = str(report_data.get("category", "threat")).upper()
        target = str(report_data.get("target", "Reported Item"))
        rep_count = report_data.get("report_count", 1)

        severity = "high" if rep_count >= 3 else "medium"
        title = f"Community Threat Intel Alert: {target}"
        explanation = (
            f"Multiple citizen reports have flagged '{target}' under category {category} "
            f"({rep_count} validated community reports). Caution is advised."
        )
        recommendations = [
            f"Do not interact with or respond to {target}.",
            "Add to device personal blocklist if applicable.",
            "Verify communication authenticity directly through official channels.",
        ]

        event_key = f"community:{target}:{category}:{severity}"

        return self.create_alert(
            title=title,
            severity=severity,
            category="COMMUNITY",
            target=target,
            risk_score=75 if severity == "high" else 45,
            explanation=explanation,
            recommended_actions=recommendations,
            user_id=user_id,
            event_key=event_key,
            metadata={"source": "community_intel", "report_count": rep_count},
        )

    def list_alerts(
        self,
        user_id: Optional[str] = None,
        severity: Optional[str] = None,
        is_read: Optional[bool] = None,
        is_resolved: Optional[bool] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List alerts with optional filtering."""
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params: List[Any] = []

        if user_id is not None:
            query += " AND (user_id = ? OR user_id IS NULL)"
            params.append(user_id)

        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())

        if is_read is not None:
            query += " AND is_read = ?"
            params.append(1 if is_read else 0)

        if is_resolved is not None:
            query += " AND is_resolved = ?"
            params.append(1 if is_resolved else 0)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(max(1, min(limit, 200)))

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                return [self._row_to_dict(row) for row in cursor.fetchall()]

    def get_alert(self, alert_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve a specific alert by ID."""
        query = "SELECT * FROM security_alerts WHERE id = ?"
        params: List[Any] = [alert_id]

        if user_id:
            query += " AND (user_id = ? OR user_id IS NULL)"
            params.append(user_id)

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                row = cursor.fetchone()
                return self._row_to_dict(row) if row else None

    def mark_as_read(self, alert_id: str, user_id: Optional[str] = None, is_read: bool = True) -> Optional[Dict[str, Any]]:
        """Update read status of an alert."""
        with self._lock:
            with self._get_connection() as conn:
                query = "UPDATE security_alerts SET is_read = ?"
                params: List[Any] = [1 if is_read else 0]

                if is_read:
                    query += ", status = CASE WHEN is_resolved = 1 THEN 'resolved' ELSE 'read' END"
                else:
                    query += ", status = CASE WHEN is_resolved = 1 THEN 'resolved' ELSE 'unread' END"

                query += " WHERE id = ?"
                params.append(alert_id)

                if user_id:
                    query += " AND (user_id = ? OR user_id IS NULL)"
                    params.append(user_id)

                conn.execute(query, params)
                conn.commit()

        return self.get_alert(alert_id, user_id)

    def mark_as_resolved(
        self,
        alert_id: str,
        user_id: Optional[str] = None,
        is_resolved: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Update resolved status of an alert."""
        resolved_at = datetime.now(timezone.utc).isoformat() if is_resolved else None
        status = "resolved" if is_resolved else "unread"

        with self._lock:
            with self._get_connection() as conn:
                query = """
                    UPDATE security_alerts
                    SET is_resolved = ?,
                        resolved_at = ?,
                        status = ?
                    WHERE id = ?
                """
                params: List[Any] = [1 if is_resolved else 0, resolved_at, status, alert_id]

                if user_id:
                    query += " AND (user_id = ? OR user_id IS NULL)"
                    params.append(user_id)

                conn.execute(query, params)
                conn.commit()

        return self.get_alert(alert_id, user_id)

    def get_alert_stats(self, user_id: Optional[str] = None) -> Dict[str, int]:
        """Return total, unread, critical, high, medium, low, and resolved counts."""
        query = "SELECT severity, is_read, is_resolved FROM security_alerts WHERE 1=1"
        params: List[Any] = []

        if user_id:
            query += " AND (user_id = ? OR user_id IS NULL)"
            params.append(user_id)

        stats = {
            "total": 0,
            "unread": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "resolved": 0,
        }

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                for row in cursor.fetchall():
                    stats["total"] += 1
                    if not row["is_read"]:
                        stats["unread"] += 1
                    if row["is_resolved"]:
                        stats["resolved"] += 1

                    sev = (row["severity"] or "").lower()
                    if sev in stats:
                        stats[sev] += 1

        return stats

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a SQLite row into a clean alert dictionary."""
        actions: List[str] = []
        try:
            actions = json.loads(row["recommended_actions_json"] or "[]")
        except Exception:
            pass

        meta: Dict[str, Any] = {}
        try:
            meta = json.loads(row["metadata_json"] or "{}")
        except Exception:
            pass

        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "scan_id": row["scan_id"],
            "event_key": row["event_key"],
            "title": row["title"],
            "severity": row["severity"],
            "category": row["category"],
            "target": row["target"],
            "risk_score": row["risk_score"],
            "explanation": row["explanation"],
            "recommended_actions": actions,
            "status": row["status"],
            "is_read": bool(row["is_read"]),
            "is_resolved": bool(row["is_resolved"]),
            "timestamp": row["timestamp"],
            "resolved_at": row["resolved_at"],
            "metadata": meta,
        }

    @staticmethod
    def _build_scan_alert_content(
        scan_type: str,
        target: str,
        severity: str,
        risk_score: int,
    ) -> tuple[str, str, List[str]]:
        """Construct descriptive titles, explanations, and actionable security recommendations."""
        sev_label = severity.capitalize()

        if scan_type == "URL":
            title = f"{sev_label} Risk Phishing URL: {target}"
            explanation = (
                f"URL scanner identified suspicious patterns, brand spoofing, or fraudulent domains "
                f"targeting {target} (Risk Score: {risk_score}/100)."
            )
            recommendations = [
                "Do not open, click, or redirect to this URL.",
                "Never submit usernames, passwords, or banking credentials.",
                "If received via SMS or email, block and report the sender address.",
            ]
        elif scan_type == "SMS":
            title = f"{sev_label} Threat Smishing Alert: {target}"
            explanation = (
                f"SMS analysis detected urgency coercion, deceptive KYC impersonation, or suspicious "
                f"telephony links (Risk Score: {risk_score}/100)."
            )
            recommendations = [
                "Do not respond or call any phone numbers listed in the message.",
                "Never share OTPs, PINs, or banking verification codes.",
                "Verify bank or carrier notices exclusively via verified official apps.",
            ]
        elif scan_type == "QR":
            title = f"{sev_label} Risk Malicious QR Code: {target}"
            explanation = (
                f"QR Code inspection flagged deceptive deep links, deceptive UPI payment intents, "
                f"or malicious redirection schemes (Risk Score: {risk_score}/100)."
            )
            recommendations = [
                "Do not authorize UPI payment requests or click destination links.",
                "Inspect the domain name before allowing browser navigation.",
                "Report suspicious physical QR stickers to location security.",
            ]
        elif scan_type == "APK":
            title = f"{sev_label} Malware/Trojan Risk in APK: {target}"
            explanation = (
                f"Static bytecode and manifest analysis discovered dangerous trojan capabilities or "
                f"stealth backdoor combinations (Risk Score: {risk_score}/100)."
            )
            recommendations = [
                "Do not install or launch this Android application package.",
                "If already installed, immediately uninstall and revoke device admin access.",
                "Only obtain mobile software from Google Play or trusted app stores.",
            ]
        elif scan_type == "PERMISSIONS":
            title = f"{sev_label} Excessive Permission Risk: {target}"
            explanation = (
                f"Permission analyzer detected dangerous permission combinations (e.g., SMS interception + "
                f"Accessibility or Background Camera) in {target} (Risk Score: {risk_score}/100)."
            )
            recommendations = [
                "Review Android app settings and revoke unnecessary background permissions.",
                "Disable SMS, Contacts, and Accessibility permissions if not strictly required.",
                "Consider replacing the app with a verified alternative.",
            ]
        elif scan_type == "EMAIL":
            title = f"{sev_label} Phishing Threat in Email: {target}"
            explanation = (
                f"Email scanner identified sender spoofing, urgency traps, or embedded malicious "
                f"attachments/links (Risk Score: {risk_score}/100)."
            )
            recommendations = [
                "Mark as spam/phishing in your email provider and delete.",
                "Do not download attachments or click inline hyperlinks.",
                "Contact sender via a known trusted channel to verify authenticity.",
            ]
        elif scan_type == "FILE":
            title = f"{sev_label} Dangerous File Finding: {target}"
            explanation = (
                f"File scanner identified suspicious file signatures, hidden macros, disguised scripts, "
                f"or archive deception (Risk Score: {risk_score}/100)."
            )
            recommendations = [
                "Do not open, execute, or extract this file.",
                "Quarantine or securely delete from local storage.",
                "Perform a full antivirus scan on your computer.",
            ]
        else:
            title = f"{sev_label} Security Finding: {target}"
            explanation = f"CyberShield detected an elevated threat level for {target} (Risk Score: {risk_score}/100)."
            recommendations = [
                "Exercise high caution with this digital artifact.",
                "Inspect related telemetry before continuing.",
                "Use the AI Security Assistant for in-depth remediation advice.",
            ]

        return title, explanation, recommendations


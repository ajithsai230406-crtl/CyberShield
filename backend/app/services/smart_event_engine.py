"""CyberShield Centralized Smart Alert & All-18-Module Security Event Engine.

Provides a unified, idempotent, fault-isolated processing pipeline for all 18 CyberShield modules:
Detection -> Analysis -> Risk Scoring -> Classification -> Event Storage ->
Smart Alert Evaluation -> Notification Decision -> History Update -> Unified Analytics.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.services.alert_service import AlertRepository
from app.services.communication_service import (
    classify_communication_risk,
    is_threat_flagged,
    redact_sensitive_communication,
)


ALL_18_MODULES: Dict[str, Dict[str, str]] = {
    "url_scanner": {"label": "URL Scanner", "default_source": "manual_scan", "default_category": "phishing_url"},
    "sms_scanner": {"label": "SMS Scanner", "default_source": "manual_scan", "default_category": "smishing"},
    "qr_scanner": {"label": "QR Scanner", "default_source": "manual_scan", "default_category": "qr_threat"},
    "screenshot_analyzer": {"label": "Screenshot Analyzer", "default_source": "manual_scan", "default_category": "screenshot_ocr"},
    "apk_analyzer": {"label": "APK Analyzer", "default_source": "manual_scan", "default_category": "apk_malware"},
    "file_scanner": {"label": "File Scanner", "default_source": "manual_scan", "default_category": "file_malware"},
    "permission_analyzer": {"label": "Permission Analyzer", "default_source": "device_audit", "default_category": "permission_risk"},
    "email_scanner": {"label": "Email Scanner", "default_source": "manual_scan", "default_category": "phishing_email"},
    "gmail_integration": {"label": "Gmail Integration", "default_source": "communication", "default_category": "gmail_message"},
    "call_screening": {"label": "Call Screening", "default_source": "communication", "default_category": "spam_call"},
    "notification_monitor": {"label": "Notification Monitor", "default_source": "communication", "default_category": "notification_threat"},
    "installed_app_audit": {"label": "Installed Application Audit", "default_source": "device_audit", "default_category": "installed_app_audit"},
    "community_threat_intel": {"label": "Community Threat Intelligence", "default_source": "community", "default_category": "community_report"},
    "ai_security_assistant": {"label": "AI Security Assistant", "default_source": "assistant", "default_category": "ai_advisory"},
    "dashboard_analytics": {"label": "Security Dashboard Analytics", "default_source": "system_event", "default_category": "analytics_telemetry"},
    "security_alerts": {"label": "Security Alerts", "default_source": "system_event", "default_category": "alert_lifecycle"},
    "audit_history": {"label": "Audit History", "default_source": "system_event", "default_category": "audit_record"},
    "realtime_protection": {"label": "Real-Time Protection", "default_source": "realtime_monitor", "default_category": "protection_status"},
}

SYSTEM_NOTIFY_CATEGORIES = {
    "service_interruption",
    "permission_revoked",
    "protection_activated",
    "daily_report",
}


class SmartSecurityEventEngine:
    """Centralized, thread-safe, user-isolated Smart Alert & Event Engine for all 18 modules."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        alert_repo: Optional[AlertRepository] = None,
    ):
        if db_path is None:
            backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_path = os.path.join(backend_dir, "cybershield_audit.db")
        self.db_path = db_path
        self.alert_repo = alert_repo or AlertRepository(db_path=db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        event_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        dedup_key TEXT NOT NULL,
                        module_name TEXT NOT NULL,
                        event_category TEXT NOT NULL,
                        source TEXT NOT NULL,
                        target_identifier TEXT NOT NULL,
                        risk_score INTEGER,
                        classification TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        findings_json TEXT NOT NULL DEFAULT '[]',
                        explanation TEXT NOT NULL DEFAULT '',
                        recommended_actions_json TEXT NOT NULL DEFAULT '[]',
                        detection_timestamp TEXT NOT NULL,
                        analysis_status TEXT NOT NULL DEFAULT 'analyzed',
                        notification_status TEXT NOT NULL DEFAULT 'suppressed_safe',
                        metadata_json TEXT NOT NULL DEFAULT '{}'
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_sec_events_user_dedup
                    ON security_events(user_id, dedup_key)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sec_events_user_ts
                    ON security_events(user_id, detection_timestamp DESC)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sec_events_user_module
                    ON security_events(user_id, module_name)
                    """
                )
                conn.commit()

    @staticmethod
    def normalize_module(module_name: str) -> str:
        key = (module_name or "realtime_protection").strip().lower().replace(" ", "_").replace("-", "_")
        aliases = {
            "url": "url_scanner",
            "sms": "sms_scanner",
            "qr": "qr_scanner",
            "screenshot": "screenshot_analyzer",
            "apk": "apk_analyzer",
            "file": "file_scanner",
            "permissions": "permission_analyzer",
            "permission": "permission_analyzer",
            "email": "email_scanner",
            "gmail": "gmail_integration",
            "call": "call_screening",
            "calls": "call_screening",
            "notification": "notification_monitor",
            "notifications": "notification_monitor",
            "apps": "installed_app_audit",
            "community": "community_threat_intel",
            "assistant": "ai_security_assistant",
            "analytics": "dashboard_analytics",
            "alerts": "security_alerts",
            "history": "audit_history",
            "protection": "realtime_protection",
        }
        key = aliases.get(key, key)
        return key if key in ALL_18_MODULES else "realtime_protection"

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        mod = row["module_name"]
        mod_info = ALL_18_MODULES.get(mod, {"label": mod.replace("_", " ").title()})
        return {
            "event_id": row["event_id"],
            "user_id": row["user_id"],
            "module_name": mod,
            "module_label": mod_info["label"],
            "event_category": row["event_category"],
            "source": row["source"],
            "target_identifier": row["target_identifier"],
            "risk_score": row["risk_score"],
            "classification": row["classification"],
            "severity": row["severity"],
            "findings": json.loads(row["findings_json"] or "[]"),
            "explanation": row["explanation"] or "",
            "recommended_actions": json.loads(row["recommended_actions_json"] or "[]"),
            "detection_timestamp": row["detection_timestamp"],
            "analysis_status": row["analysis_status"],
            "notification_status": row["notification_status"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
        }

    def process_event(
        self,
        *,
        user_id: str,
        module_name: str,
        target_identifier: str,
        risk_score: Optional[int] = 0,
        classification: Optional[str] = None,
        event_category: Optional[str] = None,
        source: Optional[str] = None,
        findings: Optional[List[str]] = None,
        explanation: str = "",
        recommended_actions: Optional[List[str]] = None,
        analysis_status: str = "analyzed",  # analyzed | failed | unverified | unavailable
        detection_timestamp: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        create_alert: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Execute the standardized pipeline for any of the 18 modules.
        Fault-isolated: never raises unhandled errors that would crash the calling module.
        Returns (event_dict, is_duplicate).
        """
        mod = self.normalize_module(module_name)
        mod_meta = ALL_18_MODULES[mod]
        mod_label = mod_meta["label"]
        cat = (event_category or mod_meta["default_category"]).strip().lower()
        src = (source or mod_meta["default_source"]).strip().lower()
        ts = detection_timestamp.strip() if detection_timestamp and detection_timestamp.strip() else datetime.now(timezone.utc).isoformat()

        # 1. Privacy redaction (never store raw OTPs, cards, CVVs, passwords, tokens)
        clean_target, target_redacted = redact_sensitive_communication(target_identifier or "N/A")
        clean_expl, expl_redacted = redact_sensitive_communication(explanation or "")
        clean_findings: List[str] = []
        any_redacted = target_redacted or expl_redacted
        for f in (findings or [])[:15]:
            cf, fr = redact_sensitive_communication(str(f))
            clean_findings.append(cf)
            any_redacted = any_redacted or fr

        clean_actions = [redact_sensitive_communication(str(a))[0] for a in (recommended_actions or [])[:6]]

        # 2. Strict status & classification normalization (NEVER mark failed/unavailable as Safe!)
        status_norm = (analysis_status or "analyzed").strip().lower()
        if status_norm not in ("analyzed", "failed", "unverified", "unavailable"):
            status_norm = "analyzed"

        effective_score: Optional[int]
        if status_norm in ("failed", "unavailable", "unverified"):
            effective_score = None if risk_score is None else max(0, min(100, int(risk_score)))
            if status_norm == "failed":
                effective_cls = "Failed"
                severity = "medium"
            elif status_norm == "unverified":
                effective_cls = "Unverified"
                severity = "low"
            else:
                effective_cls = "Unavailable"
                severity = "medium"
        else:
            effective_score = max(0, min(100, int(risk_score or 0)))
            effective_cls = classify_communication_risk(effective_score)
            # Respect explicit higher classification if detector flagged Critical/High Risk
            if classification:
                c_low = classification.strip().lower()
                if c_low == "critical" and effective_score >= 70:
                    effective_cls = "Critical"
                elif c_low in ("high risk", "malicious") and effective_score >= 55:
                    effective_cls = "High Risk"

            if effective_cls == "Critical":
                severity = "critical"
            elif effective_cls == "High Risk":
                severity = "high"
            elif effective_cls == "Suspicious":
                severity = "medium"
            elif effective_cls == "Low Risk":
                severity = "low"
            else:
                severity = "info"

        # 3. Smart Notification Decision (every notification identifies its originating module)
        if cat in SYSTEM_NOTIFY_CATEGORIES:
            if cat in ("service_interruption", "permission_revoked"):
                severity = "high"
                notif_status = "delivered_immediate"
            elif cat == "protection_activated":
                severity = "info"
                notif_status = "delivered_immediate"
            else:  # daily_report
                severity = "info"
                notif_status = "queued_preference"
        elif status_norm == "failed":
            notif_status = "queued_preference"
        elif severity in ("critical", "high"):
            notif_status = "delivered_immediate"
        elif severity == "medium":
            notif_status = "queued_preference"
        else:
            notif_status = "suppressed_safe"

        notif_title = f"[{mod_label}] {effective_cls}" + (
            f" ({effective_score}%)" if effective_score is not None and status_norm == "analyzed" else ""
        )
        notif_body = clean_expl[:180] if clean_expl else f"Security event from {mod_label} on {clean_target}."

        # 4. Idempotency / Deduplication key
        if idempotency_key and idempotency_key.strip():
            dedup_raw = f"{user_id}|{mod}|idemp:{idempotency_key.strip()}"
        else:
            minute_bucket = ts[:16] if len(ts) >= 16 else ts
            dedup_raw = f"{user_id}|{mod}|{cat}|{clean_target.lower()}|{effective_cls}|{status_norm}|{minute_bucket}"
        dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()

        merged_meta = dict(metadata or {})
        merged_meta["module_label"] = mod_label
        merged_meta["redacted"] = any_redacted
        merged_meta["notification_title"] = notif_title
        merged_meta["notification_body"] = notif_body
        merged_meta["lock_screen_safe_title"] = f"CyberShield Alert ({mod_label})"

        # 5. Store Event in SQLite (idempotent upsert)
        with self._lock:
            with self._get_connection() as conn:
                existing = conn.execute(
                    "SELECT * FROM security_events WHERE user_id = ? AND dedup_key = ?",
                    (user_id, dedup_key),
                ).fetchone()
                if existing is not None:
                    d = self._row_to_dict(existing)
                    d["is_duplicate"] = True
                    return d, True

                event_id = f"evt-{uuid.uuid4().hex[:16]}"
                conn.execute(
                    """
                    INSERT INTO security_events (
                        event_id, user_id, dedup_key, module_name, event_category,
                        source, target_identifier, risk_score, classification, severity,
                        findings_json, explanation, recommended_actions_json,
                        detection_timestamp, analysis_status, notification_status, metadata_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        user_id,
                        dedup_key,
                        mod,
                        cat,
                        src,
                        clean_target,
                        effective_score,
                        effective_cls,
                        severity,
                        json.dumps(clean_findings),
                        clean_expl,
                        json.dumps(clean_actions),
                        ts,
                        status_norm,
                        notif_status,
                        json.dumps(merged_meta),
                    ),
                )
                conn.commit()
                created_row = conn.execute(
                    "SELECT * FROM security_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()

        event_dict = self._row_to_dict(created_row)
        event_dict["is_duplicate"] = False

        # 6. Fault-isolated Smart Alert generation (only for meaningful threats or system interrupts)
        if create_alert and mod != "security_alerts":
            should_create_alert = (
                cat in ("service_interruption", "permission_revoked")
                or (status_norm == "analyzed" and effective_score is not None and is_threat_flagged(effective_score, effective_cls))
            )
            if should_create_alert:
                try:
                    self.alert_repo.create_alert(
                        title=notif_title,
                        severity=severity if severity in ("critical", "high", "medium", "low") else "medium",
                        category=cat.upper(),
                        target=clean_target,
                        risk_score=effective_score or 0,
                        explanation=clean_expl or notif_body,
                        recommended_actions=clean_actions or ["Review event details in CyberShield Unified History."],
                        user_id=user_id,
                        scan_id=event_id,
                        event_key=f"{user_id}:smart:{dedup_key[:24]}",
                        metadata={"module_name": mod, "module_label": mod_label, "event_id": event_id},
                    )
                except Exception:
                    # Fault isolation: alert repo error must never break the module event
                    pass

        return event_dict, False

    def safe_record(self, **kwargs: Any) -> Optional[Dict[str, Any]]:
        """Fault-isolated wrapper used inside existing endpoints so one module error never breaks another."""
        try:
            evt, _ = self.process_event(**kwargs)
            return evt
        except Exception:
            return None

    def update_notification_status(self, user_id: str, event_id: str, notification_status: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE security_events SET notification_status = ? WHERE event_id = ? AND user_id = ?",
                    (notification_status, event_id, user_id),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM security_events WHERE event_id = ? AND user_id = ?",
                    (event_id, user_id),
                ).fetchone()
                return self._row_to_dict(row) if row else None

    def list_events(
        self,
        *,
        user_id: str,
        module_name: Optional[str] = None,
        event_category: Optional[str] = None,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        classification: Optional[str] = None,
        min_risk: Optional[int] = None,
        max_risk: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        where = ["user_id = ?"]
        params: List[Any] = [user_id]

        if module_name and module_name.strip().lower() != "all":
            where.append("module_name = ?")
            params.append(self.normalize_module(module_name))

        if event_category and event_category.strip().lower() != "all":
            where.append("LOWER(event_category) = LOWER(?)")
            params.append(event_category.strip())

        if source and source.strip().lower() != "all":
            where.append("LOWER(source) = LOWER(?)")
            params.append(source.strip())

        if severity and severity.strip().lower() != "all":
            where.append("LOWER(severity) = LOWER(?)")
            params.append(severity.strip())

        if classification and classification.strip().lower() != "all":
            where.append("LOWER(classification) = LOWER(?)")
            params.append(classification.strip())

        if min_risk is not None:
            where.append("COALESCE(risk_score, -1) >= ?")
            params.append(int(min_risk))

        if max_risk is not None:
            where.append("COALESCE(risk_score, 101) <= ?")
            params.append(int(max_risk))

        if start_date and start_date.strip():
            where.append("detection_timestamp >= ?")
            params.append(start_date.strip())

        if end_date and end_date.strip():
            ev = end_date.strip()
            if len(ev) == 10:
                ev = f"{ev}T23:59:59.999999+00:00"
            where.append("detection_timestamp <= ?")
            params.append(ev)

        if search and search.strip():
            like = f"%{search.strip().lower()}%"
            where.append(
                "(LOWER(target_identifier) LIKE ? OR LOWER(module_name) LIKE ? OR "
                "LOWER(event_category) LIKE ? OR LOWER(explanation) LIKE ? OR LOWER(detection_timestamp) LIKE ?)"
            )
            params.extend([like, like, like, like, like])

        where_sql = " AND ".join(where)
        safe_limit = max(1, min(200, int(limit)))
        safe_offset = max(0, int(offset))

        with self._lock:
            with self._get_connection() as conn:
                total = conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM security_events WHERE {where_sql}",
                    params,
                ).fetchone()["cnt"]
                rows = conn.execute(
                    f"""
                    SELECT * FROM security_events
                    WHERE {where_sql}
                    ORDER BY detection_timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    [*params, safe_limit, safe_offset],
                ).fetchall()

        events = [self._row_to_dict(r) for r in rows]
        return {
            "total": int(total),
            "limit": safe_limit,
            "offset": safe_offset,
            "has_more": (safe_offset + len(events)) < int(total),
            "events": events,
        }

    def delete_event(self, user_id: str, event_id: str) -> bool:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "DELETE FROM security_events WHERE event_id = ? AND user_id = ?",
                    (event_id, user_id),
                )
                conn.commit()
                return cur.rowcount > 0

    def delete_events(self, user_id: str, older_than_days: Optional[int] = None) -> int:
        with self._lock:
            with self._get_connection() as conn:
                if older_than_days is not None and older_than_days > 0:
                    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
                    cur = conn.execute(
                        "DELETE FROM security_events WHERE user_id = ? AND detection_timestamp < ?",
                        (user_id, cutoff),
                    )
                else:
                    cur = conn.execute(
                        "DELETE FROM security_events WHERE user_id = ?",
                        (user_id,),
                    )
                conn.commit()
                return int(cur.rowcount)

    def get_unified_analytics(self, *, user_id: str, period: str = "daily") -> Dict[str, Any]:
        """
        Compute unified all-18-module analytics:
        - Strictly separates analyzed events from failed/unverified/unavailable events
        - Separates Threat Detection Rate from Device Security Posture Score
        - Module-wise threat distribution across all 18 modules
        - Daily, weekly, and monthly trends
        """
        now = datetime.now(timezone.utc)
        p = (period or "daily").strip().lower()
        if p not in ("daily", "weekly", "monthly"):
            p = "daily"

        with self._lock:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM security_events WHERE user_id = ? ORDER BY detection_timestamp DESC",
                    (user_id,),
                ).fetchall()

        events = [self._row_to_dict(r) for r in rows]

        total_events = len(events)
        total_analyzed = 0
        failed_events = 0
        unverified_events = 0
        unavailable_events = 0

        safe_events = 0
        low_risk_events = 0
        suspicious_events = 0
        high_risk_events = 0
        critical_events = 0

        notifications_delivered = 0

        module_dist: Dict[str, Dict[str, Any]] = {
            mod: {
                "module_name": mod,
                "module_label": info["label"],
                "total": 0,
                "analyzed": 0,
                "safe": 0,
                "threats": 0,
                "failed_or_unavailable": 0,
                "threat_percentage": None,
            }
            for mod, info in ALL_18_MODULES.items()
        }

        source_breakdown: Dict[str, int] = {
            "manual_scan": 0,
            "communication": 0,
            "device_audit": 0,
            "realtime_monitor": 0,
            "system_event": 0,
            "community": 0,
            "assistant": 0,
        }

        # Trend buckets
        trends_map: Dict[str, Dict[str, int]] = {}
        if p == "daily":
            for d in range(13, -1, -1):
                k = (now - timedelta(days=d)).strftime("%Y-%m-%d")
                trends_map[k] = {"total": 0, "analyzed": 0, "safe": 0, "threats": 0, "failed": 0}
        elif p == "weekly":
            for w in range(7, -1, -1):
                iso = (now - timedelta(weeks=w)).isocalendar()
                k = f"{iso.year}-W{iso.week:02d}"
                trends_map[k] = {"total": 0, "analyzed": 0, "safe": 0, "threats": 0, "failed": 0}
        else:
            for m in range(5, -1, -1):
                y, mo = now.year, now.month - m
                while mo <= 0:
                    mo += 12
                    y -= 1
                k = f"{y:04d}-{mo:02d}"
                trends_map[k] = {"total": 0, "analyzed": 0, "safe": 0, "threats": 0, "failed": 0}

        for ev in events:
            mod = ev["module_name"]
            status = (ev["analysis_status"] or "analyzed").lower()
            cls = (ev["classification"] or "").lower()
            score = ev["risk_score"]
            src = (ev["source"] or "manual_scan").lower()
            source_breakdown[src] = source_breakdown.get(src, 0) + 1

            if (ev["notification_status"] or "").startswith("delivered"):
                notifications_delivered += 1

            m_entry = module_dist[mod]
            m_entry["total"] += 1

            # Trend key
            ts_str = ev["detection_timestamp"] or ""
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if p == "daily":
                    t_key = dt.strftime("%Y-%m-%d")
                elif p == "weekly":
                    iso = dt.isocalendar()
                    t_key = f"{iso.year}-W{iso.week:02d}"
                else:
                    t_key = dt.strftime("%Y-%m")
            except Exception:
                t_key = ""

            if t_key in trends_map:
                trends_map[t_key]["total"] += 1

            if status != "analyzed":
                m_entry["failed_or_unavailable"] += 1
                if status == "failed":
                    failed_events += 1
                elif status == "unverified":
                    unverified_events += 1
                else:
                    unavailable_events += 1
                if t_key in trends_map:
                    trends_map[t_key]["failed"] += 1
                continue

            total_analyzed += 1
            m_entry["analyzed"] += 1
            if t_key in trends_map:
                trends_map[t_key]["analyzed"] += 1

            if cls == "critical":
                critical_events += 1
                m_entry["threats"] += 1
                if t_key in trends_map:
                    trends_map[t_key]["threats"] += 1
            elif cls == "high risk":
                high_risk_events += 1
                m_entry["threats"] += 1
                if t_key in trends_map:
                    trends_map[t_key]["threats"] += 1
            elif cls == "suspicious":
                suspicious_events += 1
                m_entry["threats"] += 1
                if t_key in trends_map:
                    trends_map[t_key]["threats"] += 1
            elif cls == "low risk":
                low_risk_events += 1
                m_entry["safe"] += 1
                if t_key in trends_map:
                    trends_map[t_key]["safe"] += 1
            else:
                safe_events += 1
                m_entry["safe"] += 1
                if t_key in trends_map:
                    trends_map[t_key]["safe"] += 1

        # Module threat percentages & active coverage
        active_modules_reporting = 0
        for m_entry in module_dist.values():
            if m_entry["total"] > 0:
                active_modules_reporting += 1
            if m_entry["analyzed"] > 0:
                m_entry["threat_percentage"] = round(
                    (m_entry["threats"] / m_entry["analyzed"]) * 100.0, 1
                )
            m_entry["total_events"] = m_entry["total"]
            m_entry["analyzed_events"] = m_entry["analyzed"]
            m_entry["threat_count"] = m_entry["threats"]
            m_entry["safe_count"] = m_entry["safe"]
            m_entry["threat_rate_percent"] = m_entry["threat_percentage"]

        threat_flagged_total = suspicious_events + high_risk_events + critical_events
        failed_or_unavail_total = failed_events + unverified_events + unavailable_events
        threat_detection_percentage = (
            round((threat_flagged_total / total_analyzed) * 100.0, 1)
            if total_analyzed > 0
            else None
        )
        monitoring_avail_pct = (
            round((total_analyzed / total_events) * 100.0, 1)
            if total_events > 0
            else 100.0
        )

        # Device Security Posture Score (distinct from Threat Detection Rate & individual risk score)
        # Starts at 100 baseline; deducts for unresolved critical/high threats & failed monitoring availability
        posture_deduction = min(75, critical_events * 15 + high_risk_events * 8 + suspicious_events * 3 + failed_events * 2)
        device_security_posture = max(0, 100 - posture_deduction) if total_analyzed > 0 else None
        posture_numeric = device_security_posture if device_security_posture is not None else (
            max(0, 100 - min(40, failed_or_unavail_total * 5))
        )
        posture_label = (
            "Strong" if posture_numeric >= 85
            else ("Moderate" if posture_numeric >= 65 else ("Elevated Risk" if posture_numeric >= 40 else "Critical Attention"))
        )

        trends_list = []
        for label, vals in trends_map.items():
            an = vals["analyzed"]
            pct = round((vals["threats"] / an) * 100.0, 1) if an > 0 else 0.0
            trends_list.append({
                "label": label,
                "total": vals["total"],
                "analyzed": an,
                "safe": vals["safe"],
                "threats": vals["threats"],
                "failed": vals["failed"],
                "failed_or_unavailable": vals["failed"],
                "threat_percentage": pct,
            })

        return {
            "period": p,
            "total_events": total_events,
            "total_analyzed": total_analyzed,
            "total_analyzed_events": total_analyzed,
            "safe_events": safe_events,
            "safe_count": safe_events + low_risk_events,
            "low_risk_events": low_risk_events,
            "suspicious_events": suspicious_events,
            "suspicious_count": suspicious_events,
            "high_risk_events": high_risk_events,
            "high_risk_count": high_risk_events,
            "critical_events": critical_events,
            "critical_count": critical_events,
            "threat_flagged_events": threat_flagged_total,
            "total_threats_detected": threat_flagged_total,
            "failed_events": failed_events,
            "unverified_events": unverified_events,
            "unavailable_events": unavailable_events,
            "failed_or_unavailable_events": failed_or_unavail_total,
            "threat_detection_percentage": threat_detection_percentage,
            "threat_detection_rate_percent": threat_detection_percentage or 0.0,
            "monitoring_coverage_percent": monitoring_avail_pct,
            "device_security_posture": device_security_posture,
            "device_security_posture_score": posture_numeric,
            "posture_label": posture_label,
            "active_modules_count": active_modules_reporting,
            "total_registered_modules": len(ALL_18_MODULES),
            "has_analyzed_data": total_analyzed > 0,
            "notifications_delivered": notifications_delivered,
            "monitoring_coverage": {
                "active_modules_reporting": active_modules_reporting,
                "total_integrated_modules": len(ALL_18_MODULES),
                "coverage_percentage": round((active_modules_reporting / len(ALL_18_MODULES)) * 100.0, 1),
            },
            "source_breakdown": source_breakdown,
            "module_distribution": list(module_dist.values()),
            "trends": trends_list,
            "trend_series": trends_list,
            "timestamp": now.isoformat(),
        }

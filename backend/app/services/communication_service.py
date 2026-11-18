"""CyberShield Communication History & Threat Intelligence Service.

Provides:
- User-isolated SQLite persistence for incoming SMS, notifications, calls, email, and WhatsApp notifications
- Configurable 0-100 risk percentage classification (Safe / Low Risk / Suspicious / High Risk / Critical)
- On-server sensitive data redaction (OTPs, credit cards, CVVs, passwords, auth tokens)
- Deduplication to prevent duplicate notification / rapid message inflation
- Real stored-record analytics (daily, weekly, monthly trends, SMS vs Call breakdown, threat rate)
- Retention policy cleanup and record deletion
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_RISK_THRESHOLDS: Dict[str, int] = {
    "safe_max": 20,
    "low_risk_max": 40,
    "suspicious_max": 60,
    "high_risk_max": 80,
}

# Privacy redaction patterns (never log or store raw secrets)
_CARD_RE = re.compile(r"\b(?:\d{4}[ -]?){3}\d{1,4}\b")
_OTP_RE = re.compile(
    r"(?i)\b(otp|code|pin|passcode|verification code|auth code|security code)\s*[:=\-#]?\s*(\d{4,8})\b"
)
_STANDALONE_OTP_RE = re.compile(r"(?i)\b(\d{4,6})\s+(?:is your|for your)\s+(?:otp|code|verification|login)\b")
_CVV_RE = re.compile(r"(?i)\bcvv\s*[:=\-]?\s*(\d{3,4})\b")
_PASSWORD_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|bearer)\s*[:=]\s*([^\s,;]+)")


def redact_sensitive_communication(text: Optional[str]) -> Tuple[str, bool]:
    """Redact OTPs, card numbers, CVVs, passwords, and auth tokens before storage or logging."""
    if not text:
        return "", False

    sanitized = text
    redacted = False

    if _CARD_RE.search(sanitized):
        sanitized = _CARD_RE.sub("[REDACTED_CARD]", sanitized)
        redacted = True

    if _OTP_RE.search(sanitized):
        sanitized = _OTP_RE.sub(r"\1: [REDACTED_OTP]", sanitized)
        redacted = True

    if _STANDALONE_OTP_RE.search(sanitized):
        sanitized = _STANDALONE_OTP_RE.sub("[REDACTED_OTP] is your verification code", sanitized)
        redacted = True

    if _CVV_RE.search(sanitized):
        sanitized = _CVV_RE.sub("cvv: [REDACTED]", sanitized)
        redacted = True

    if _PASSWORD_RE.search(sanitized):
        sanitized = _PASSWORD_RE.sub(r"\1=[REDACTED_SECRET]", sanitized)
        redacted = True

    return sanitized, redacted


def classify_communication_risk(
    score: int,
    thresholds: Optional[Dict[str, int]] = None,
) -> str:
    """Map a 0-100 risk score into the configured CyberShield communication risk tiers."""
    t = thresholds or DEFAULT_RISK_THRESHOLDS
    clamped = max(0, min(100, int(score)))
    if clamped <= t.get("safe_max", 20):
        return "Safe"
    if clamped <= t.get("low_risk_max", 40):
        return "Low Risk"
    if clamped <= t.get("suspicious_max", 60):
        return "Suspicious"
    if clamped <= t.get("high_risk_max", 80):
        return "High Risk"
    return "Critical"


def is_threat_flagged(score: int, classification: str) -> bool:
    """Return True if communication is classified as Suspicious, High Risk, or Critical."""
    cls = (classification or "").strip().lower()
    return score >= 41 or cls in ("suspicious", "high risk", "critical")


class CommunicationRepository:
    """Thread-safe, user-isolated SQLite store for communication history & threat analytics."""

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
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS communication_history (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        dedup_hash TEXT NOT NULL,
                        communication_type TEXT NOT NULL,
                        source_app TEXT NOT NULL,
                        sender_identifier TEXT NOT NULL,
                        caller_name TEXT,
                        message_preview TEXT NOT NULL DEFAULT '',
                        timestamp TEXT NOT NULL,
                        risk_score INTEGER NOT NULL DEFAULT 0,
                        classification TEXT NOT NULL,
                        threat_categories_json TEXT NOT NULL DEFAULT '[]',
                        findings_json TEXT NOT NULL DEFAULT '[]',
                        explanation TEXT NOT NULL DEFAULT '',
                        recommended_action TEXT NOT NULL DEFAULT '',
                        analysis_status TEXT NOT NULL DEFAULT 'analyzed',
                        is_known_contact INTEGER,
                        call_status TEXT,
                        spam_reputation TEXT,
                        metadata_json TEXT NOT NULL DEFAULT '{}'
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_comm_user_dedup
                    ON communication_history(user_id, dedup_hash)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_comm_user_ts
                    ON communication_history(user_id, timestamp DESC)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_comm_user_type
                    ON communication_history(user_id, communication_type)
                    """
                )
                conn.commit()

    @staticmethod
    def compute_dedup_hash(
        user_id: str,
        communication_type: str,
        source_app: str,
        sender_identifier: str,
        preview_or_key: str,
        timestamp_iso: str,
        external_id: Optional[str] = None,
    ) -> str:
        """Compute deterministic hash to prevent duplicate recording of rapid/repeated notifications."""
        if external_id and external_id.strip():
            raw = f"{user_id}|{communication_type.lower()}|ext:{external_id.strip()}"
        else:
            # Bucket to minute precision so re-posted identical notifications within the same minute deduplicate
            minute_bucket = timestamp_iso[:16] if len(timestamp_iso) >= 16 else timestamp_iso
            norm_preview = re.sub(r"\s+", " ", (preview_or_key or "").strip().lower())[:160]
            norm_sender = (sender_identifier or "").strip().lower()
            raw = f"{user_id}|{communication_type.lower()}|{source_app.strip().lower()}|{norm_sender}|{norm_preview}|{minute_bucket}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        is_known_raw = row["is_known_contact"]
        is_known = None if is_known_raw is None else bool(is_known_raw)
        return {
            "record_id": row["id"],
            "user_id": row["user_id"],
            "communication_type": row["communication_type"],
            "source_app": row["source_app"],
            "sender_identifier": row["sender_identifier"],
            "caller_name": row["caller_name"],
            "message_preview": row["message_preview"] or "",
            "timestamp": row["timestamp"],
            "risk_score": int(row["risk_score"]),
            "classification": row["classification"],
            "threat_categories": json.loads(row["threat_categories_json"] or "[]"),
            "findings": json.loads(row["findings_json"] or "[]"),
            "explanation": row["explanation"] or "",
            "recommended_action": row["recommended_action"] or "",
            "analysis_status": row["analysis_status"] or "analyzed",
            "is_known_contact": is_known,
            "call_status": row["call_status"],
            "spam_reputation": row["spam_reputation"],
            "metadata": json.loads(row["metadata_json"] or "{}"),
        }

    def upsert_record(
        self,
        *,
        user_id: str,
        communication_type: str,
        source_app: str,
        sender_identifier: str,
        message_preview: str,
        timestamp: Optional[str],
        risk_score: int,
        classification: str,
        threat_categories: List[str],
        findings: List[str],
        explanation: str,
        recommended_action: str,
        analysis_status: str = "analyzed",
        caller_name: Optional[str] = None,
        is_known_contact: Optional[bool] = None,
        call_status: Optional[str] = None,
        spam_reputation: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        external_id: Optional[str] = None,
        dedup_source_text: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], bool]:
        """Insert a communication record if not a duplicate. Returns (record, is_duplicate)."""
        ts = timestamp.strip() if timestamp and timestamp.strip() else datetime.now(timezone.utc).isoformat()
        dedup_hash = self.compute_dedup_hash(
            user_id=user_id,
            communication_type=communication_type,
            source_app=source_app,
            sender_identifier=sender_identifier,
            preview_or_key=dedup_source_text if dedup_source_text is not None else message_preview,
            timestamp_iso=ts,
            external_id=external_id,
        )

        with self._lock:
            with self._get_connection() as conn:
                existing = conn.execute(
                    "SELECT * FROM communication_history WHERE user_id = ? AND dedup_hash = ?",
                    (user_id, dedup_hash),
                ).fetchone()
                if existing is not None:
                    return self._row_to_dict(existing), True

                record_id = f"comm-{uuid.uuid4().hex[:16]}"
                known_int = None if is_known_contact is None else (1 if is_known_contact else 0)
                conn.execute(
                    """
                    INSERT INTO communication_history (
                        id, user_id, dedup_hash, communication_type, source_app,
                        sender_identifier, caller_name, message_preview, timestamp,
                        risk_score, classification, threat_categories_json, findings_json,
                        explanation, recommended_action, analysis_status,
                        is_known_contact, call_status, spam_reputation, metadata_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record_id,
                        user_id,
                        dedup_hash,
                        communication_type.lower(),
                        source_app,
                        sender_identifier,
                        caller_name,
                        message_preview,
                        ts,
                        int(max(0, min(100, risk_score))),
                        classification,
                        json.dumps(threat_categories),
                        json.dumps(findings),
                        explanation,
                        recommended_action,
                        analysis_status,
                        known_int,
                        call_status,
                        spam_reputation,
                        json.dumps(metadata or {}),
                    ),
                )
                conn.commit()
                created = conn.execute(
                    "SELECT * FROM communication_history WHERE id = ?",
                    (record_id,),
                ).fetchone()
                return self._row_to_dict(created), False

    def list_records(
        self,
        *,
        user_id: str,
        category: str = "all",  # all | messages | calls
        communication_type: Optional[str] = None,
        classification: Optional[str] = None,  # all | safe | low_risk | suspicious | high_risk | critical | unknown
        search: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query user-isolated communication history with filtering, search, and pagination."""
        where_clauses = ["user_id = ?"]
        params: List[Any] = [user_id]

        cat = (category or "all").strip().lower()
        if cat == "calls":
            where_clauses.append("communication_type = 'call'")
        elif cat == "messages":
            where_clauses.append("communication_type != 'call'")

        if communication_type and communication_type.strip().lower() != "all":
            where_clauses.append("LOWER(communication_type) = LOWER(?)")
            params.append(communication_type.strip())

        cls = (classification or "all").strip().lower()
        if cls and cls != "all":
            if cls == "unknown":
                where_clauses.append("(is_known_contact = 0 OR is_known_contact IS NULL)")
            elif cls in ("low_risk", "low risk"):
                where_clauses.append("LOWER(classification) = 'low risk'")
            elif cls in ("high_risk", "high risk"):
                where_clauses.append("LOWER(classification) = 'high risk'")
            else:
                where_clauses.append("LOWER(classification) = LOWER(?)")
                params.append(cls)

        if start_date and start_date.strip():
            where_clauses.append("timestamp >= ?")
            params.append(start_date.strip())

        if end_date and end_date.strip():
            end_val = end_date.strip()
            if len(end_val) == 10:  # YYYY-MM-DD -> include entire day
                end_val = f"{end_val}T23:59:59.999999+00:00"
            where_clauses.append("timestamp <= ?")
            params.append(end_val)

        if search and search.strip():
            like = f"%{search.strip().lower()}%"
            where_clauses.append(
                "("
                "LOWER(sender_identifier) LIKE ? OR "
                "LOWER(COALESCE(caller_name, '')) LIKE ? OR "
                "LOWER(source_app) LIKE ? OR "
                "LOWER(threat_categories_json) LIKE ? OR "
                "LOWER(timestamp) LIKE ? OR "
                "LOWER(message_preview) LIKE ?"
                ")"
            )
            params.extend([like, like, like, like, like, like])

        where_sql = " AND ".join(where_clauses)
        safe_limit = max(1, min(200, int(limit)))
        safe_offset = max(0, int(offset))

        with self._lock:
            with self._get_connection() as conn:
                total = conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM communication_history WHERE {where_sql}",
                    params,
                ).fetchone()["cnt"]

                rows = conn.execute(
                    f"""
                    SELECT * FROM communication_history
                    WHERE {where_sql}
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    [*params, safe_limit, safe_offset],
                ).fetchall()

        records = [self._row_to_dict(r) for r in rows]
        return {
            "total": int(total),
            "limit": safe_limit,
            "offset": safe_offset,
            "has_more": (safe_offset + len(records)) < int(total),
            "records": records,
        }

    def delete_record(self, user_id: str, record_id: str) -> bool:
        """Delete a single record strictly owned by user_id."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM communication_history WHERE id = ? AND user_id = ?",
                    (record_id, user_id),
                )
                conn.commit()
                return cursor.rowcount > 0

    def delete_records(self, user_id: str, older_than_days: Optional[int] = None) -> int:
        """Delete records for user_id (either older than N days for retention or all records)."""
        with self._lock:
            with self._get_connection() as conn:
                if older_than_days is not None and older_than_days > 0:
                    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
                    cursor = conn.execute(
                        "DELETE FROM communication_history WHERE user_id = ? AND timestamp < ?",
                        (user_id, cutoff),
                    )
                else:
                    cursor = conn.execute(
                        "DELETE FROM communication_history WHERE user_id = ?",
                        (user_id,),
                    )
                conn.commit()
                return int(cursor.rowcount)

    def get_analytics(
        self,
        *,
        user_id: str,
        period: str = "daily",  # daily | weekly | monthly
    ) -> Dict[str, Any]:
        """Compute accurate communication security analytics strictly from real stored records."""
        now = datetime.now(timezone.utc)
        period_norm = (period or "daily").strip().lower()
        if period_norm not in ("daily", "weekly", "monthly"):
            period_norm = "daily"

        if period_norm == "daily":
            lookback_days = 14
        elif period_norm == "weekly":
            lookback_days = 56  # 8 weeks
        else:
            lookback_days = 180  # 6 months

        cutoff_iso = (now - timedelta(days=lookback_days)).isoformat()

        with self._lock:
            with self._get_connection() as conn:
                all_rows = conn.execute(
                    "SELECT * FROM communication_history WHERE user_id = ? ORDER BY timestamp DESC",
                    (user_id,),
                ).fetchall()
                period_rows = conn.execute(
                    "SELECT * FROM communication_history WHERE user_id = ? AND timestamp >= ? ORDER BY timestamp DESC",
                    (user_id, cutoff_iso),
                ).fetchall()

        all_records = [self._row_to_dict(r) for r in all_rows]
        period_records = [self._row_to_dict(r) for r in period_rows]

        def compute_bucket_stats(items: List[Dict[str, Any]]) -> Dict[str, Any]:
            received = len(items)
            analyzed = 0
            unanalyzed = 0
            safe_c = 0
            low_c = 0
            susp_c = 0
            high_c = 0
            crit_c = 0
            unknown_callers = 0

            for it in items:
                status = (it.get("analysis_status") or "analyzed").lower()
                if status != "analyzed":
                    unanalyzed += 1
                    continue
                analyzed += 1
                cls = (it.get("classification") or "Safe").lower()
                if cls == "critical":
                    crit_c += 1
                elif cls == "high risk":
                    high_c += 1
                elif cls == "suspicious":
                    susp_c += 1
                elif cls == "low risk":
                    low_c += 1
                else:
                    safe_c += 1

                if it.get("communication_type") == "call" and it.get("is_known_contact") is False:
                    unknown_callers += 1

            threat_flagged = susp_c + high_c + crit_c
            threat_rate = round((threat_flagged / analyzed) * 100.0, 1) if analyzed > 0 else None

            return {
                "total_received": received,
                "total_analyzed": analyzed,
                "total_unanalyzed": unanalyzed,
                "safe_count": safe_c,
                "low_risk_count": low_c,
                "suspicious_count": susp_c,
                "high_risk_count": high_c,
                "critical_count": crit_c,
                "threat_flagged_count": threat_flagged,
                "threat_detection_rate": threat_rate,
                "has_analyzed_data": analyzed > 0,
                "unknown_callers_count": unknown_callers,
            }

        overall_stats = compute_bucket_stats(all_records)
        msg_records = [r for r in all_records if r["communication_type"] != "call"]
        call_records = [r for r in all_records if r["communication_type"] == "call"]
        sms_stats = compute_bucket_stats(msg_records)
        call_stats = compute_bucket_stats(call_records)

        # Trends grouped by requested period (daily / weekly / monthly)
        trends_map: Dict[str, Dict[str, int]] = {}
        if period_norm == "daily":
            for d in range(13, -1, -1):
                key = (now - timedelta(days=d)).strftime("%Y-%m-%d")
                trends_map[key] = {"total": 0, "analyzed": 0, "safe": 0, "threats": 0}
        elif period_norm == "weekly":
            for w in range(7, -1, -1):
                dt = now - timedelta(weeks=w)
                iso = dt.isocalendar()
                key = f"{iso.year}-W{iso.week:02d}"
                trends_map[key] = {"total": 0, "analyzed": 0, "safe": 0, "threats": 0}
        else:
            for m in range(5, -1, -1):
                # Approximate month rollback accurately
                year = now.year
                month = now.month - m
                while month <= 0:
                    month += 12
                    year -= 1
                key = f"{year:04d}-{month:02d}"
                trends_map[key] = {"total": 0, "analyzed": 0, "safe": 0, "threats": 0}

        cat_counter: Counter[str] = Counter()

        for rec in period_records:
            ts_str = rec.get("timestamp") or ""
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if period_norm == "daily":
                    key = dt.strftime("%Y-%m-%d")
                elif period_norm == "weekly":
                    iso = dt.isocalendar()
                    key = f"{iso.year}-W{iso.week:02d}"
                else:
                    key = dt.strftime("%Y-%m")
            except Exception:
                key = ts_str[:10] if len(ts_str) >= 10 else ""

            if key in trends_map:
                trends_map[key]["total"] += 1
                if (rec.get("analysis_status") or "analyzed").lower() == "analyzed":
                    trends_map[key]["analyzed"] += 1
                    if is_threat_flagged(rec["risk_score"], rec["classification"]):
                        trends_map[key]["threats"] += 1
                    else:
                        trends_map[key]["safe"] += 1

        for rec in all_records:
            for tag in rec.get("threat_categories") or []:
                if tag and str(tag).strip():
                    cat_counter[str(tag).strip()] += 1

        trend_points: List[Dict[str, Any]] = []
        for label, vals in trends_map.items():
            analyzed_n = vals["analyzed"]
            threat_pct = round((vals["threats"] / analyzed_n) * 100.0, 1) if analyzed_n > 0 else 0.0
            trend_points.append({
                "label": label,
                "total": vals["total"],
                "analyzed": analyzed_n,
                "safe": vals["safe"],
                "threats": vals["threats"],
                "threat_percentage": threat_pct,
            })

        def dist_for(items: List[Dict[str, Any]]) -> Dict[str, int]:
            st = compute_bucket_stats(items)
            return {
                "Safe": st["safe_count"],
                "Low Risk": st["low_risk_count"],
                "Suspicious": st["suspicious_count"],
                "High Risk": st["high_risk_count"],
                "Critical": st["critical_count"],
                "Unanalyzed": st["total_unanalyzed"],
            }

        top_categories = [
            {"category": cat, "count": cnt}
            for cat, cnt in cat_counter.most_common(8)
        ]

        return {
            "period": period_norm,
            "overall": overall_stats,
            "messages": sms_stats,
            "calls": call_stats,
            "trends": trend_points,
            "sms_threat_distribution": dist_for(msg_records),
            "call_threat_distribution": dist_for(call_records),
            "top_threat_categories": top_categories,
            "formula": "Threat Rate = (Threat-flagged analyzed communications / Total analyzed communications) × 100",
            "thresholds": DEFAULT_RISK_THRESHOLDS,
            "timestamp": now.isoformat(),
        }

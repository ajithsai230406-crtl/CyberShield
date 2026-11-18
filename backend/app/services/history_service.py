"""SQLite persistent audit history storage for CyberShield."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class HistoryRepository:
    """Thread-safe SQLite repository for managing scan audit events."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            env_db_path = os.getenv("CYBERSHIELD_DB_PATH", "").strip()
            env_data_dir = os.getenv("CYBERSHIELD_DATA_DIR", "").strip()
            if env_db_path:
                db_path = env_db_path
            elif env_data_dir:
                db_path = os.path.join(env_data_dir, "cybershield_audit.db")
            else:
                # Default to database file in backend root
                backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                db_path = os.path.join(backend_dir, "cybershield_audit.db")

        parent_dir = os.path.dirname(os.path.abspath(db_path))
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id TEXT PRIMARY KEY,
                        scan_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        risk_score INTEGER NOT NULL DEFAULT 0,
                        classification TEXT NOT NULL,
                        summary TEXT,
                        status_badge TEXT,
                        details_json TEXT,
                        timestamp TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scan_history_type ON scan_history(scan_type)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scan_history_classification ON scan_history(classification)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp DESC)"
                )
                conn.commit()

    def record_scan(
        self,
        scan_id: str,
        scan_type: str,
        target: str,
        risk_score: int,
        classification: str,
        summary: str,
        status_badge: str,
        timestamp: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Insert a scan record into SQLite."""
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()

        details_json = json.dumps(details or {})

        record = {
            "id": scan_id,
            "scan_id": scan_id,
            "scan_type": scan_type,
            "target": target,
            "risk_score": risk_score,
            "classification": classification,
            "summary": summary,
            "status_badge": status_badge,
            "timestamp": timestamp,
            "details": details or {},
        }

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scan_history
                    (id, scan_type, target, risk_score, classification, summary, status_badge, details_json, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        scan_type.upper(),
                        target,
                        risk_score,
                        classification,
                        summary,
                        status_badge,
                        details_json,
                        timestamp,
                    ),
                )
                conn.commit()

        return record

    def get_all(
        self,
        scan_type: Optional[str] = None,
        classification: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve scan records with optional filtering in descending order of timestamp."""
        query = "SELECT * FROM scan_history WHERE 1=1"
        params: List[Any] = []

        if scan_type and scan_type.strip().lower() != "all":
            query += " AND UPPER(scan_type) = UPPER(?)"
            params.append(scan_type.strip())

        if classification and classification.strip().lower() != "all":
            query += " AND LOWER(classification) = LOWER(?)"
            params.append(classification.strip())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

        records = []
        for row in rows:
            details = {}
            if row["details_json"]:
                try:
                    details = json.loads(row["details_json"])
                except Exception:
                    details = {}

            records.append(
                {
                    "id": row["id"],
                    "scan_id": row["id"],
                    "scan_type": row["scan_type"],
                    "target": row["target"],
                    "risk_score": row["risk_score"],
                    "classification": row["classification"],
                    "summary": row["summary"],
                    "status_badge": row["status_badge"],
                    "timestamp": row["timestamp"],
                    "details": details,
                }
            )
        return records

    def count(
        self,
        scan_type: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> int:
        """Count total matching records."""
        query = "SELECT COUNT(*) FROM scan_history WHERE 1=1"
        params: List[Any] = []

        if scan_type and scan_type.strip().lower() != "all":
            query += " AND UPPER(scan_type) = UPPER(?)"
            params.append(scan_type.strip())

        if classification and classification.strip().lower() != "all":
            query += " AND LOWER(classification) = LOWER(?)"
            params.append(classification.strip())

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                return cursor.fetchone()[0]

    def get_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve single scan by scan_id."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM scan_history WHERE id = ? OR LOWER(id) = LOWER(?)",
                    (scan_id, scan_id),
                )
                row = cursor.fetchone()

        if not row:
            return None

        details = {}
        if row["details_json"]:
            try:
                details = json.loads(row["details_json"])
            except Exception:
                details = {}

        return {
            "id": row["id"],
            "scan_id": row["id"],
            "scan_type": row["scan_type"],
            "target": row["target"],
            "risk_score": row["risk_score"],
            "classification": row["classification"],
            "summary": row["summary"],
            "status_badge": row["status_badge"],
            "timestamp": row["timestamp"],
            "details": details,
        }

    def delete_by_id(self, scan_id: str) -> bool:
        """Delete single scan by scan_id. Returns True if deleted, False if not found."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM scan_history WHERE id = ? OR LOWER(id) = LOWER(?)",
                    (scan_id, scan_id),
                )
                conn.commit()
                return cursor.rowcount > 0

    def clear(self) -> None:
        """Clear all records from database."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM scan_history")
                conn.commit()


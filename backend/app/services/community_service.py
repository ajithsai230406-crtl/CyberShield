"""CyberShield Community Threat Reporting and Reputation Engine.

Provides decentralized threat reporting, deduplication, rate limiting,
target normalization, privacy preservation, and heuristic community reputation scoring.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


SUPPORTED_CATEGORIES: Set[str] = {
    "phone",
    "sms",
    "url",
    "qr",
    "email",
    "app",
}

STATUS_PENDING = "PENDING"
STATUS_UNDER_REVIEW = "UNDER_REVIEW"
STATUS_VERIFIED_THREAT = "VERIFIED_THREAT"
STATUS_REJECTED = "REJECTED"

HASH_SALT = "CyberShield_Community_Report_Salt_2026_Secure"


class RateLimiter:
    """Thread-safe sliding-window rate limiter for report submissions."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, client_id: str) -> bool:
        """Check if client_id is within allowed threshold; records timestamp if allowed."""
        now = time.time()
        with self._lock:
            timestamps = self._requests.get(client_id, [])
            # Evict timestamps outside current window
            cutoff = now - self.window_seconds
            valid_timestamps = [t for t in timestamps if t > cutoff]
            if len(valid_timestamps) >= self.max_requests:
                self._requests[client_id] = valid_timestamps
                return False
            valid_timestamps.append(now)
            self._requests[client_id] = valid_timestamps
            return True

    def reset(self) -> None:
        """Reset rate limiter state (useful in tests)."""
        with self._lock:
            self._requests.clear()


def hash_reporter_id(uid: str) -> str:
    """
    Produce a non-reversible cryptographic hash of reporter UID to preserve privacy
    while enabling 1-vote-per-user deduplication.
    """
    salted = f"{uid}:{HASH_SALT}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()


def normalize_target(category: str, raw_target: str) -> Tuple[str, str]:
    """
    Validate and normalize report target according to its category.
    Returns (normalized_target, display_target).
    Raises ValueError on invalid or malformed target.
    """
    cat = category.strip().lower()
    if cat not in SUPPORTED_CATEGORIES:
        raise ValueError(
            f"Unsupported category '{category}'. Must be one of: {sorted(SUPPORTED_CATEGORIES)}"
        )

    raw = raw_target.strip()
    if not raw:
        raise ValueError(f"Report target for category '{cat}' cannot be empty.")

    if cat == "phone":
        # Remove parentheses, hyphens, spaces, dots
        cleaned = re.sub(r"[\s\-\(\)\.]", "", raw)
        has_plus = cleaned.startswith("+")
        digits = re.sub(r"\D", "", cleaned)
        if len(digits) < 7 or len(digits) > 15:
            raise ValueError(
                f"Invalid phone number format '{raw}'. Must contain between 7 and 15 digits."
            )
        normalized = f"+{digits}" if has_plus else digits
        display = f"+{digits}" if has_plus else digits
        return normalized, display

    elif cat == "url":
        clean_url = raw.lower()
        if clean_url.startswith(("javascript:", "data:", "file:", "vbscript:")):
            raise ValueError("Dangerous or unsupported URI scheme.")
        if not re.match(r"^https?://", clean_url):
            clean_url = f"https://{clean_url}"
        # Strip trailing slashes
        clean_url = clean_url.rstrip("/")
        # Validate domain/host structure
        host_match = re.search(r"^https?://([^/:\s]+)", clean_url)
        if not host_match or len(host_match.group(1)) < 3:
            raise ValueError(f"Invalid URL structure '{raw}'.")
        return clean_url, raw.strip()

    elif cat == "email":
        clean_email = raw.strip().lower()
        # Basic email check: something@domain.tld
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", clean_email):
            raise ValueError(f"Invalid email address '{raw}'.")
        return clean_email, clean_email

    elif cat == "app":
        clean_app = raw.strip().lower()
        # Android package name (e.g. com.example.app) or app identifier
        if len(clean_app) < 3 or len(clean_app) > 200:
            raise ValueError(f"Application package or identifier must be 3-200 characters.")
        return clean_app, raw.strip()

    elif cat in ("sms", "qr"):
        # Text/payload normalization: collapse excessive whitespace
        collapsed = re.sub(r"\s+", " ", raw)
        if len(collapsed) < 3:
            raise ValueError(f"Content for '{cat}' report must be at least 3 characters.")
        if len(collapsed) > 4000:
            raise ValueError(f"Content for '{cat}' report exceeds 4000 characters limit.")
        # Normalized key is lowercase truncated hash or excerpt
        normalized = collapsed.lower()
        return normalized, collapsed

    return raw.lower(), raw


class CommunityRepository:
    """
    SQLite-backed repository managing community threat reports and reputation aggregates.
    Thread-safe and ACID compliant.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            backend_dir = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            db_path = os.path.join(backend_dir, "cybershield_audit.db")

        self.db_path = db_path
        self._lock = threading.Lock()
        self.rate_limiter = RateLimiter(max_requests=10, window_seconds=600)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create community reports and indexes if they do not exist."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS community_reports (
                        id TEXT PRIMARY KEY,
                        category TEXT NOT NULL,
                        target TEXT NOT NULL,
                        target_display TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        tags_json TEXT,
                        reporter_hash TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        is_verified INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_comm_cat_target ON community_reports(category, target)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_comm_reporter ON community_reports(reporter_hash)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_comm_created ON community_reports(created_at DESC)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_comm_status ON community_reports(status)"
                )
                conn.commit()

    def check_rate_limit(self, user_uid: str) -> bool:
        """Check if user has exceeded submission rate limit."""
        return self.rate_limiter.is_allowed(user_uid)

    def clear_all(self) -> None:
        """Clear all community reports and reset rate limiters (intended for tests)."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM community_reports")
                conn.commit()
        self.rate_limiter.reset()

    def has_user_reported_recently(
        self,
        category: str,
        normalized_target: str,
        reporter_hash: str,
        window_seconds: int = 86400,
    ) -> bool:
        """Check if user has already reported this target within window_seconds (default 24h)."""
        now = datetime.now(timezone.utc).timestamp()
        cutoff_dt = datetime.fromtimestamp(now - window_seconds, tz=timezone.utc).isoformat()

        query = """
            SELECT id FROM community_reports
            WHERE category = ? AND target = ? AND reporter_hash = ? AND created_at >= ?
            LIMIT 1
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, (category, normalized_target, reporter_hash, cutoff_dt))
                return cursor.fetchone() is not None

    def submit_report(
        self,
        category: str,
        raw_target: str,
        title: str,
        description: str,
        tags: List[str],
        user_uid: str,
    ) -> Dict[str, Any]:
        """
        Submit a new community report after validation, normalization,
        rate limiting, and duplicate detection.
        """
        cat = category.strip().lower()
        normalized_tgt, display_tgt = normalize_target(cat, raw_target)

        # Rate limit check
        if not self.check_rate_limit(user_uid):
            raise PermissionError(
                "Rate limit exceeded: maximum 10 community reports per 10 minutes. Please try again later."
            )

        reporter_h = hash_reporter_id(user_uid)

        # Duplicate check within 24h
        if self.has_user_reported_recently(cat, normalized_tgt, reporter_h, window_seconds=86400):
            raise ValueError(
                "Duplicate report: You have already submitted a report for this target in the last 24 hours."
            )

        report_id = f"rep-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_tags = [t.strip().lower() for t in tags if t.strip()][:10]

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO community_reports
                    (id, category, target, target_display, title, description, tags_json, reporter_hash, status, is_verified, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        report_id,
                        cat,
                        normalized_tgt,
                        display_tgt,
                        title.strip()[:200],
                        (description or "").strip()[:2000],
                        json.dumps(clean_tags),
                        reporter_h,
                        STATUS_PENDING,
                        now_iso,
                        now_iso,
                    ),
                )
                conn.commit()

        # Compute instant reputation for returned report
        rep = self.get_reputation(cat, normalized_tgt)

        return {
            "id": report_id,
            "category": cat,
            "target": normalized_tgt,
            "target_display": display_tgt,
            "title": title.strip()[:200],
            "description": (description or "").strip()[:2000],
            "tags": clean_tags,
            "status": STATUS_PENDING,
            "is_verified": False,
            "created_at": now_iso,
            "reputation": rep,
        }

    def get_reports(
        self,
        category: Optional[str] = None,
        status: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent community reports with optional filtering, omitting private user identifiers."""
        query = "SELECT * FROM community_reports WHERE 1=1"
        params: List[Any] = []

        if category and category.strip().lower() != "all":
            query += " AND category = ?"
            params.append(category.strip().lower())

        if status and status.strip().lower() != "all":
            query += " AND UPPER(status) = UPPER(?)"
            params.append(status.strip())

        if search_query and search_query.strip():
            query += " AND (target LIKE ? OR title LIKE ? OR description LIKE ?)"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term])

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

        results = []
        for r in rows:
            tags = []
            if r["tags_json"]:
                try:
                    tags = json.loads(r["tags_json"])
                except Exception:
                    tags = []

            results.append(
                {
                    "id": r["id"],
                    "category": r["category"],
                    "target": r["target"],
                    "target_display": r["target_display"],
                    "title": r["title"],
                    "description": r["description"],
                    "tags": tags,
                    "status": r["status"],
                    "is_verified": bool(r["is_verified"]),
                    "created_at": r["created_at"],
                }
            )
        return results

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single report by ID with reputation details."""
        query = "SELECT * FROM community_reports WHERE id = ? LIMIT 1"
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query, (report_id,))
                row = cursor.fetchone()

        if not row:
            return None

        tags = []
        if row["tags_json"]:
            try:
                tags = json.loads(row["tags_json"])
            except Exception:
                tags = []

        rep = self.get_reputation(row["category"], row["target"])

        return {
            "id": row["id"],
            "category": row["category"],
            "target": row["target"],
            "target_display": row["target_display"],
            "title": row["title"],
            "description": row["description"],
            "tags": tags,
            "status": row["status"],
            "is_verified": bool(row["is_verified"]),
            "created_at": row["created_at"],
            "reputation": rep,
        }

    def get_reputation(self, category: str, normalized_target: str) -> Dict[str, Any]:
        """
        Calculate transparent reputation from community reports:
        - Deduplicates user votes (COUNT DISTINCT reporter_hash)
        - Distinguishes report count from verified threat status
        - Never automatically marks content as malicious without verified threat status
        - Caps unverified suspicion score at 75
        - Transparently presents confidence, evidence tags, and disclaimer
        """
        cat = category.strip().lower()

        query = """
            SELECT
                COUNT(id) as total_reports,
                COUNT(DISTINCT reporter_hash) as distinct_reporters,
                MAX(is_verified) as has_verified_threat,
                MAX(created_at) as last_reported_at
            FROM community_reports
            WHERE category = ? AND target = ? AND status != 'REJECTED'
        """

        tags_query = """
            SELECT tags_json FROM community_reports
            WHERE category = ? AND target = ? AND status != 'REJECTED'
        """

        with self._lock:
            with self._get_connection() as conn:
                row = conn.execute(query, (cat, normalized_target)).fetchone()
                tags_rows = conn.execute(tags_query, (cat, normalized_target)).fetchall()

        total_reports = row["total_reports"] if row else 0
        distinct_reporters = row["distinct_reporters"] if row else 0
        has_verified_threat = bool(row["has_verified_threat"]) if row and row["has_verified_threat"] else False
        last_reported_at = row["last_reported_at"] if row else None

        # Aggregate evidence tags
        tag_counter: Counter[str] = Counter()
        for tr in tags_rows:
            if tr["tags_json"]:
                try:
                    for t in json.loads(tr["tags_json"]):
                        tag_counter[t] += 1
                except Exception:
                    pass

        evidence_tags = [
            {"tag": tag, "count": count} for tag, count in tag_counter.most_common(5)
        ]

        # Scoring & Confidence Rules
        if distinct_reporters == 0:
            suspicion_score = 0
            classification = "Unreported / Unknown"
            confidence = "None"
            threat_status = "UNKNOWN"
        elif has_verified_threat:
            suspicion_score = 95
            classification = "Confirmed Threat"
            confidence = "High"
            threat_status = "VERIFIED_THREAT"
        else:
            threat_status = "UNVERIFIED_COMMUNITY_FLAGGED"
            if distinct_reporters == 1:
                suspicion_score = 25
                classification = "Single Community Report"
                confidence = "Low"
            elif 2 <= distinct_reporters <= 4:
                suspicion_score = 45
                classification = "Community Flagged"
                confidence = "Moderate"
            elif 5 <= distinct_reporters <= 9:
                suspicion_score = 65
                classification = "Elevated Community Suspicion"
                confidence = "Moderate"
            else:
                # 10 or more distinct reporters, but still unverified
                suspicion_score = 75
                classification = "High Community Suspicion (Unverified)"
                confidence = "High"

        return {
            "category": cat,
            "target": normalized_target,
            "total_reports": total_reports,
            "distinct_reporters": distinct_reporters,
            "suspicion_score": suspicion_score,
            "classification": classification,
            "confidence": confidence,
            "threat_status": threat_status,
            "is_verified_threat": has_verified_threat,
            "last_reported_at": last_reported_at,
            "evidence_tags": evidence_tags,
            "disclaimer": (
                "Community reports reflect individual user submissions and crowd consensus. "
                "Unverified reports indicate community suspicion and do not constitute confirmed malware intelligence."
            ),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate high-level community reporting metrics."""
        query_total = "SELECT COUNT(id) as total, COUNT(DISTINCT target) as targets, COUNT(DISTINCT reporter_hash) as reporters FROM community_reports"
        query_cats = "SELECT category, COUNT(id) as cnt FROM community_reports GROUP BY category"
        query_verified = "SELECT COUNT(id) FROM community_reports WHERE is_verified = 1"

        with self._lock:
            with self._get_connection() as conn:
                tot_row = conn.execute(query_total).fetchone()
                cat_rows = conn.execute(query_cats).fetchall()
                ver_count = conn.execute(query_verified).fetchone()[0]

        category_counts = {cat: 0 for cat in sorted(SUPPORTED_CATEGORIES)}
        for cr in cat_rows:
            category_counts[cr["category"]] = cr["cnt"]

        return {
            "total_reports": tot_row["total"] if tot_row else 0,
            "distinct_targets": tot_row["targets"] if tot_row else 0,
            "active_reporters": tot_row["reporters"] if tot_row else 0,
            "verified_threats": ver_count,
            "categories": category_counts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify_report(self, report_id: str, is_threat: bool, notes: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Admin/Analyst hook to mark a report as verified threat or rejected."""
        status = STATUS_VERIFIED_THREAT if is_threat else STATUS_REJECTED
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    UPDATE community_reports
                    SET status = ?, is_verified = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status, 1 if is_threat else 0, now_iso, report_id),
                )
                conn.commit()
                if cursor.rowcount == 0:
                    return None
        return self.get_report_by_id(report_id)

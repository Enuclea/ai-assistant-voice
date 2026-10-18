"""SQLite storage for call logs, SMS messages, 2FA/OTP extraction, VIP clients, and security audit trail."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from .security import normalize_phone

_OTP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:verification\s+code|security\s+code|code|pin|otp|passcode|verification)(?:\s+is)?[:\s-]*(\d{4,8})\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(\d{4,8})\s+is\s+your\b", re.IGNORECASE),
    re.compile(r"\bG-(\d{6})\b"),
)


def extract_otp_code(text: str) -> str:
    """Extract a 4-to-8 digit verification/2FA code from an SMS body if present."""
    if not text:
        return ""
    for pat in _OTP_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
    # Fallback: if the entire message is very short and contains a single 6-digit number
    if len(text.strip()) <= 48:
        m = re.search(r"\b(\d{6})\b", text)
        if m:
            return m.group(1)
    return ""


class VoiceStore:
    """SQLite persistence layer for call sessions, SMS/2FA, VIP routing, and security audits."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS call_logs (
                    call_id TEXT PRIMARY KEY,
                    direction TEXT NOT NULL,
                    remote_number TEXT NOT NULL,
                    remote_name TEXT NOT NULL DEFAULT '',
                    objective TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'ringing',
                    outcome TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT '',
                    transcript_json TEXT NOT NULL DEFAULT '[]',
                    dtmf_digits TEXT NOT NULL DEFAULT '',
                    started_at REAL NOT NULL,
                    ended_at REAL
                );

                CREATE TABLE IF NOT EXISTS sms_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    direction TEXT NOT NULL,
                    remote_number TEXT NOT NULL,
                    body TEXT NOT NULL,
                    otp_code TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'delivered',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS known_clients (
                    phone_number TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    company TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    auto_transfer INTEGER NOT NULL DEFAULT 1,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS security_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    actor TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                );
                """
            )

    def create_call(
        self,
        *,
        call_id: str,
        direction: str,
        remote_number: str,
        remote_name: str = "",
        objective: str = "",
        status: str = "ringing",
    ) -> dict[str, Any]:
        now = time.time()
        norm_num = normalize_phone(remote_number) or remote_number
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO call_logs
                (call_id, direction, remote_number, remote_name, objective, status, started_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (call_id, direction, norm_num, remote_name, objective, status, now),
            )
        return self.get_call(call_id) or {}

    def update_call(
        self,
        call_id: str,
        *,
        status: str | None = None,
        outcome: str | None = None,
        summary: str | None = None,
        dtmf_digits: str | None = None,
        ended_at: float | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_call(call_id)
        if not current:
            return None
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE call_logs
                SET status = ?,
                    outcome = ?,
                    summary = ?,
                    dtmf_digits = ?,
                    ended_at = ?
                WHERE call_id = ?
                """,
                (
                    status if status is not None else current["status"],
                    outcome if outcome is not None else current["outcome"],
                    summary if summary is not None else current["summary"],
                    dtmf_digits if dtmf_digits is not None else current["dtmf_digits"],
                    ended_at if ended_at is not None else current["ended_at"],
                    call_id,
                ),
            )
        return self.get_call(call_id)

    def append_call_transcript(self, call_id: str, role: str, text: str) -> None:
        current = self.get_call(call_id)
        if not current:
            return
        turns: list[dict[str, Any]] = list(current.get("transcript", []))
        turns.append({"role": role, "text": text, "ts": round(time.time(), 3)})
        with self._connect() as conn:
            conn.execute(
                "UPDATE call_logs SET transcript_json = ? WHERE call_id = ?",
                (json.dumps(turns, ensure_ascii=False), call_id),
            )

    def get_call(self, call_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM call_logs WHERE call_id = ?", (call_id,)
            ).fetchone()
        if not row:
            return None
        data = dict(row)
        raw_transcript = data.pop("transcript_json", "[]")
        try:
            data["transcript"] = json.loads(raw_transcript)
        except json.JSONDecodeError:
            data["transcript"] = []
        return data

    def list_calls(
        self, *, limit: int = 20, direction: str | None = None
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        with self._connect() as conn:
            if direction:
                rows = conn.execute(
                    "SELECT * FROM call_logs WHERE direction = ? ORDER BY started_at DESC LIMIT ?",
                    (direction, safe_limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM call_logs ORDER BY started_at DESC LIMIT ?",
                    (safe_limit,),
                ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw_transcript = item.pop("transcript_json", "[]")
            try:
                item["transcript"] = json.loads(raw_transcript)
            except json.JSONDecodeError:
                item["transcript"] = []
            results.append(item)
        return results

    def record_sms(
        self,
        *,
        direction: str,
        remote_number: str,
        body: str,
        status: str = "delivered",
    ) -> dict[str, Any]:
        now = time.time()
        norm_num = normalize_phone(remote_number) or remote_number
        otp = extract_otp_code(body) if direction == "inbound" else ""
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO sms_messages (direction, remote_number, body, otp_code, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (direction, norm_num, body, otp, status, now),
            )
            msg_id = cur.lastrowid
            row = conn.execute(
                "SELECT * FROM sms_messages WHERE id = ?", (msg_id,)
            ).fetchone()
        return dict(row) if row else {}

    def list_sms(
        self,
        *,
        limit: int = 20,
        remote_number: str | None = None,
        only_otp: bool = False,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 200))
        clauses: list[str] = []
        params: list[Any] = []
        if remote_number:
            clauses.append("remote_number = ?")
            params.append(normalize_phone(remote_number) or remote_number)
        if only_otp:
            clauses.append("otp_code != ''")
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(safe_limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM sms_messages {where_sql} ORDER BY created_at DESC LIMIT ?",
                tuple(params),
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_known_client(
        self,
        *,
        phone_number: str,
        name: str,
        company: str = "",
        notes: str = "",
        auto_transfer: bool = True,
    ) -> dict[str, Any]:
        norm_num = normalize_phone(phone_number)
        if not norm_num:
            raise ValueError(f"Invalid phone number: {phone_number!r}")
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO known_clients (phone_number, name, company, notes, auto_transfer, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(phone_number) DO UPDATE SET
                    name = excluded.name,
                    company = excluded.company,
                    notes = excluded.notes,
                    auto_transfer = excluded.auto_transfer,
                    updated_at = excluded.updated_at
                """,
                (norm_num, name.strip(), company.strip(), notes.strip(), 1 if auto_transfer else 0, now),
            )
            row = conn.execute(
                "SELECT * FROM known_clients WHERE phone_number = ?", (norm_num,)
            ).fetchone()
        return dict(row) if row else {}

    def get_known_client(self, phone_number: str) -> dict[str, Any] | None:
        norm_num = normalize_phone(phone_number)
        if not norm_num:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM known_clients WHERE phone_number = ?", (norm_num,)
            ).fetchone()
        return dict(row) if row else None

    def list_known_clients(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM known_clients ORDER BY name ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def log_security_event(
        self,
        *,
        event_type: str,
        severity: str = "info",
        actor: str = "",
        detail: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO security_audit_log (event_type, severity, actor, detail, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_type, severity, actor, detail[:1000], time.time()),
            )

    def list_security_events(self, *, limit: int = 50) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM security_audit_log ORDER BY created_at DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(r) for r in rows]

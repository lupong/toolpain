"""SQLite persistence for scans, events, and reports."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from control_plane.models import EventOut, Report, ScanSummary


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                  id TEXT PRIMARY KEY,
                  repo_url TEXT NOT NULL,
                  ref TEXT NOT NULL,
                  status TEXT NOT NULL,
                  account_mode TEXT NOT NULL,
                  token TEXT NOT NULL,
                  demo TEXT,
                  verdict TEXT,
                  findings_count INTEGER DEFAULT 0,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id TEXT NOT NULL,
                  stage TEXT NOT NULL,
                  level TEXT NOT NULL,
                  msg TEXT NOT NULL,
                  ts TEXT NOT NULL,
                  data TEXT NOT NULL,
                  FOREIGN KEY(scan_id) REFERENCES scans(id)
                );
                CREATE TABLE IF NOT EXISTS reports (
                  scan_id TEXT PRIMARY KEY,
                  body TEXT NOT NULL,
                  FOREIGN KEY(scan_id) REFERENCES scans(id)
                );
                CREATE TABLE IF NOT EXISTS api_tokens (
                  token_hash TEXT PRIMARY KEY,
                  label TEXT,
                  quota INTEGER NOT NULL,
                  created_at TEXT NOT NULL
                );
                """
            )
            cols = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
            if "owner_hash" not in cols:
                conn.execute("ALTER TABLE scans ADD COLUMN owner_hash TEXT")
            for name, decl in (
                ("error_code", "TEXT"),
                ("error_detail", "TEXT"),
                ("estimate_json", "TEXT"),
            ):
                if name not in cols:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {name} {decl}")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_calls (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id TEXT NOT NULL,
                  kind TEXT NOT NULL,
                  created_at TEXT NOT NULL
                )
                """
            )

    def create_scan(
        self,
        scan_id: str,
        repo_url: str,
        ref: str,
        token: str,
        account_mode: str,
        demo: str | None = None,
    ) -> ScanSummary:
        now = _utcnow().isoformat()
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scans
                (id, repo_url, ref, status, account_mode, token, demo, created_at, updated_at)
                VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?)
                """,
                (scan_id, repo_url, ref, account_mode, token, demo, now, now),
            )
        return self.get_scan(scan_id)  # type: ignore[return-value]

    def get_scan(self, scan_id: str) -> ScanSummary | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return ScanSummary(
            id=row["id"],
            repo_url=row["repo_url"],
            ref=row["ref"],
            status=row["status"],
            account_mode=row["account_mode"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            verdict=row["verdict"],
            findings_count=row["findings_count"] or 0,
            demo=row["demo"],
            error_code=row["error_code"] if "error_code" in row.keys() else None,
            error_detail=row["error_detail"] if "error_detail" in row.keys() else None,
        )

    def get_token(self, scan_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT token FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return None if not row else row["token"]

    def list_scans(self, limit: int = 50, owner_hash: str | None = None) -> list[ScanSummary]:
        sql = "SELECT * FROM scans"
        args: tuple[Any, ...] = (limit,)
        if owner_hash:
            sql += " WHERE owner_hash = ?"
            args = (owner_hash, limit)
        sql += " ORDER BY created_at DESC LIMIT ?"
        with self.connect() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [
            ScanSummary(
                id=r["id"],
                repo_url=r["repo_url"],
                ref=r["ref"],
                status=r["status"],
                account_mode=r["account_mode"],
                created_at=datetime.fromisoformat(r["created_at"]),
                updated_at=datetime.fromisoformat(r["updated_at"]),
                verdict=r["verdict"],
                findings_count=r["findings_count"] or 0,
                demo=r["demo"],
                error_code=r["error_code"] if "error_code" in r.keys() else None,
                error_detail=r["error_detail"] if "error_detail" in r.keys() else None,
            )
            for r in rows
        ]

    def update_scan(
        self,
        scan_id: str,
        *,
        status: str | None = None,
        verdict: str | None = None,
        findings_count: int | None = None,
        error_code: str | None = None,
        error_detail: str | None = None,
    ) -> None:
        fields: list[str] = ["updated_at = ?"]
        vals: list[Any] = [_utcnow().isoformat()]
        if status is not None:
            fields.append("status = ?")
            vals.append(status)
        if verdict is not None:
            fields.append("verdict = ?")
            vals.append(verdict)
        if findings_count is not None:
            fields.append("findings_count = ?")
            vals.append(findings_count)
        if error_code is not None:
            fields.append("error_code = ?")
            vals.append(error_code)
        if error_detail is not None:
            fields.append("error_detail = ?")
            vals.append(error_detail[:500])
        vals.append(scan_id)
        with self._lock, self.connect() as conn:
            conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE id = ?", vals)

    def add_event(
        self,
        scan_id: str,
        stage: str,
        level: str,
        msg: str,
        data: dict[str, Any] | None = None,
        ts: datetime | None = None,
    ) -> EventOut:
        when = (ts or _utcnow()).isoformat()
        payload = json.dumps(data or {})
        with self._lock, self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO events (scan_id, stage, level, msg, ts, data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, stage, level, msg, when, payload),
            )
            event_id = int(cur.lastrowid)
        return EventOut(
            id=event_id,
            scan_id=scan_id,
            stage=stage,
            level=level,  # type: ignore[arg-type]
            msg=msg,
            ts=datetime.fromisoformat(when),
            data=data or {},
        )

    def list_events(self, scan_id: str, after_id: int = 0) -> list[EventOut]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE scan_id = ? AND id > ?
                ORDER BY id ASC
                """,
                (scan_id, after_id),
            ).fetchall()
        return [
            EventOut(
                id=r["id"],
                scan_id=r["scan_id"],
                stage=r["stage"],
                level=r["level"],  # type: ignore[arg-type]
                msg=r["msg"],
                ts=datetime.fromisoformat(r["ts"]),
                data=json.loads(r["data"] or "{}"),
            )
            for r in rows
        ]

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def issue_api_token(self, token: str, label: str, quota: int) -> None:
        now = _utcnow().isoformat()
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO api_tokens (token_hash, label, quota, created_at) VALUES (?, ?, ?, ?)",
                (self.hash_token(token), label, quota, now),
            )

    def consume_quota(self, token: str) -> bool:
        digest = self.hash_token(token)
        with self._lock, self.connect() as conn:
            row = conn.execute(
                "SELECT quota FROM api_tokens WHERE token_hash = ?", (digest,)
            ).fetchone()
            if not row or int(row["quota"]) <= 0:
                return False
            conn.execute("UPDATE api_tokens SET quota = quota - 1 WHERE token_hash = ?", (digest,))
        return True

    def set_estimate(self, scan_id: str, estimate: dict[str, Any] | None) -> None:
        text = json.dumps(estimate) if estimate is not None else None
        with self._lock, self.connect() as conn:
            conn.execute("UPDATE scans SET estimate_json = ? WHERE id = ?", (text, scan_id))

    def get_estimate(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT estimate_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if not row or not row["estimate_json"]:
            return None
        loaded = json.loads(row["estimate_json"])
        return loaded if isinstance(loaded, dict) else None

    def scan_id_for_token(self, token: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM scans WHERE token = ? LIMIT 1", (token,)).fetchone()
        return None if not row else str(row["id"])

    def record_llm_call(self, scan_id: str, kind: str) -> None:
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT INTO llm_calls (scan_id, kind, created_at) VALUES (?, ?, ?)",
                (scan_id, kind, _utcnow().isoformat()),
            )

    def llm_call_counts(self, scan_id: str) -> dict[str, int]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT kind, COUNT(*) AS n FROM llm_calls WHERE scan_id = ? GROUP BY kind",
                (scan_id,),
            ).fetchall()
        return {str(r["kind"]): int(r["n"]) for r in rows}

    def set_owner(self, scan_id: str, owner_hash: str) -> None:
        with self._lock, self.connect() as conn:
            conn.execute("UPDATE scans SET owner_hash = ? WHERE id = ?", (owner_hash, scan_id))

    def owner_of(self, scan_id: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT owner_hash FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return row["owner_hash"]

    def save_report(self, scan_id: str, report: Report | dict[str, Any], reports_dir: Path) -> None:
        body = report.model_dump() if isinstance(report, Report) else report
        text = json.dumps(body, indent=2, default=str)
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports (scan_id, body) VALUES (?, ?)",
                (scan_id, text),
            )
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / f"{scan_id}.json").write_text(text)

    def get_report(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT body FROM reports WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return json.loads(row["body"])

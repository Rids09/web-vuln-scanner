import sqlite3
import json
import os
from datetime import datetime
from config import Config


def get_connection():
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL DEFAULT 'running',
            findings_json TEXT
        )
    """)
    conn.commit()
    conn.close()


def create_scan(target_url: str) -> int:
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO scans (target_url, started_at, status) VALUES (?, ?, ?)",
        (target_url, datetime.utcnow().isoformat(), "running")
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def complete_scan(scan_id: int, findings: list):
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET status = ?, finished_at = ?, findings_json = ? WHERE id = ?",
        ("completed", datetime.utcnow().isoformat(), json.dumps(findings), scan_id)
    )
    conn.commit()
    conn.close()


def fail_scan(scan_id: int, error: str):
    conn = get_connection()
    conn.execute(
        "UPDATE scans SET status = ?, finished_at = ?, findings_json = ? WHERE id = ?",
        ("failed", datetime.utcnow().isoformat(), json.dumps({"error": error}), scan_id)
    )
    conn.commit()
    conn.close()


def get_scan(scan_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    if result["findings_json"]:
        result["findings"] = json.loads(result["findings_json"])
    else:
        result["findings"] = []
    return result


def list_scans():
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, target_url, started_at, finished_at, status FROM scans ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


class DatabaseProxy:
    def init_db(self): return init_db()
    def create_scan(self, url): return create_scan(url)
    def complete_scan(self, id, findings): return complete_scan(id, findings)
    def fail_scan(self, id, err): return fail_scan(id, err)
    def get_scan(self, id): return get_scan(id)
    def list_scans(self): return list_scans()

db = DatabaseProxy()
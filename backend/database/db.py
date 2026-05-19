import sqlite3
import os
import json
from datetime import datetime

db_path = os.path.join(os.path.dirname(__file__), "osint.db")


def get_conn():
    return sqlite3.connect(db_path)


def create_tables():
    conn = get_conn()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL,
            email     TEXT NOT NULL,
            phone     TEXT,
            scanned_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Full scan reports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER,
            name            TEXT,
            email           TEXT,
            phone           TEXT,
            risk_score      TEXT,
            ai_summary      TEXT,
            digital_footprint TEXT,
            breach_summary  TEXT,
            risk_reasons    TEXT,
            recommendations TEXT,
            google_mentions TEXT,
            registered_sites TEXT,
            breach_data     TEXT,
            shodan_data     TEXT,
            hunter_data     TEXT,
            phone_data      TEXT,
            social_data     TEXT,
            scanned_at      TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Tables ready")


def insert_user(name, email, phone=None):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, phone) VALUES (?, ?, ?)",
        (name, email, phone)
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    print(f"[DB] User inserted: id={user_id}")
    return user_id


def insert_scan_report(user_id: int, report: dict):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_reports (
            user_id, name, email, phone,
            risk_score, ai_summary, digital_footprint, breach_summary,
            risk_reasons, recommendations, google_mentions,
            registered_sites, breach_data, shodan_data,
            hunter_data, phone_data, social_data
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        user_id,
        report.get("name"),
        report.get("email"),
        report.get("phone"),
        report.get("risk_score"),
        report.get("ai_summary"),
        report.get("digital_footprint"),
        report.get("breach_summary"),
        json.dumps(report.get("risk_reasons", [])),
        json.dumps(report.get("recommendations", [])),
        json.dumps(report.get("google_mentions", [])),
        json.dumps(report.get("registered_sites", [])),
        json.dumps(report.get("breach_data", {})),
        json.dumps(report.get("shodan_data", {})),
        json.dumps(report.get("hunter_data", {})),
        json.dumps(report.get("phone_data", {})),
        json.dumps(report.get("social_data", [])),
    ))
    conn.commit()
    conn.close()
    print("[DB] Scan report saved")


def get_all_scans():
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, email, risk_score, scanned_at
        FROM scan_reports
        ORDER BY scanned_at DESC
        LIMIT 50
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_scan_by_id(scan_id: int):
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_reports WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    # Parse JSON fields
    for field in ["risk_reasons","recommendations","google_mentions",
                  "registered_sites","breach_data","shodan_data",
                  "hunter_data","phone_data","social_data"]:
        try:
            data[field] = json.loads(data[field]) if data[field] else []
        except Exception:
            data[field] = []
    return data


def get_risk_trend(email: str):
    """Get risk score history for a specific email for the graph."""
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT risk_score, scanned_at
        FROM scan_reports
        WHERE email = ?
        ORDER BY scanned_at ASC
        LIMIT 20
    """, (email,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# Auto-create tables on import
create_tables()
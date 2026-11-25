"""SQLite storage for events and alerts."""
import os
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT, source TEXT, ip TEXT, username TEXT, status TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT, severity TEXT, ip TEXT, username TEXT,
    first_seen TEXT, last_seen TEXT, count INTEGER, details TEXT);
"""


def connect(path):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def reset_events(conn):
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM alerts")
    conn.commit()


def insert_events(conn, events):
    rows = [(e["ts"].isoformat(sep=" "), e["source"], e["ip"], e["username"],
             e["status"], e.get("raw", "")) for e in events]
    conn.executemany(
        "INSERT INTO events(ts,source,ip,username,status,raw) VALUES (?,?,?,?,?,?)", rows)
    conn.commit()
    return len(rows)


def load_events(conn):
    cur = conn.execute("SELECT ts,source,ip,username,status,raw FROM events ORDER BY ts")
    return [{"ts": datetime.fromisoformat(r[0]), "source": r[1], "ip": r[2],
             "username": r[3], "status": r[4], "raw": r[5]} for r in cur]


def save_alerts(conn, alerts):
    conn.execute("DELETE FROM alerts")
    conn.executemany(
        "INSERT INTO alerts(rule,severity,ip,username,first_seen,last_seen,count,details) "
        "VALUES (?,?,?,?,?,?,?,?)",
        [(a["rule"], a["severity"], a["ip"], a["username"],
          a["first_seen"].isoformat(sep=" "), a["last_seen"].isoformat(sep=" "),
          a["count"], a["details"]) for a in alerts])
    conn.commit()

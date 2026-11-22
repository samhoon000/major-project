"""SQLite storage shared by the collector and the private dashboard."""

import json
import os
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

RETENTION_SECONDS = 7 * 86400
MAX_ROWS_PER_APP = 50000
NONCE_LIMIT = 600
REPLAY_WINDOW = 120


class Replay(Exception):
    pass


class QuotaExceeded(Exception):
    pass


def database_path():
    return Path(os.getenv("HTTP_TELEMETRY_DB", "data/http-telemetry.sqlite3")).resolve()


@contextmanager
def connect(path):
    with closing(sqlite3.connect(path, timeout=2)) as db, db:
        db.row_factory = sqlite3.Row
        yield db


def initialize(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, app TEXT NOT NULL, request_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL, status INTEGER NOT NULL, auth TEXT NOT NULL,
                duration REAL NOT NULL, event TEXT NOT NULL, UNIQUE(app, request_id)
            );
            CREATE INDEX IF NOT EXISTS event_time ON events(app, timestamp, id);
            CREATE INDEX IF NOT EXISTS event_retention ON events(timestamp);
            CREATE TABLE IF NOT EXISTS nonces (
                app TEXT NOT NULL, nonce TEXT NOT NULL, expires INTEGER NOT NULL,
                PRIMARY KEY(app, nonce)
            );
            CREATE INDEX IF NOT EXISTS nonce_expiry ON nonces(expires);
            CREATE TABLE IF NOT EXISTS delivery (
                app TEXT PRIMARY KEY, seen INTEGER NOT NULL, health TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS observed_totals (app TEXT PRIMARY KEY, total INTEGER NOT NULL);
            INSERT OR IGNORE INTO observed_totals SELECT app,COUNT(*) FROM events GROUP BY app;
        """)


def prune(db, now):
    db.execute("DELETE FROM events WHERE timestamp < ?", ((now - RETENTION_SECONDS) * 1000,))
    db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
    db.execute("DELETE FROM delivery WHERE seen < ?", (now - RETENTION_SECONDS,))


def maintain(path, now):
    with connect(path) as db:
        prune(db, now)


def accept(path, app, nonce, signed_at, now, batch):
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM nonces WHERE expires < ?", (now,))
        if db.execute("SELECT 1 FROM nonces WHERE app=? AND nonce=?", (app, nonce)).fetchone():
            raise Replay
        if db.execute("SELECT COUNT(*) FROM nonces WHERE app=?", (app,)).fetchone()[0] >= NONCE_LIMIT:
            raise QuotaExceeded
        db.execute("INSERT INTO nonces VALUES (?, ?, ?)", (app, nonce, signed_at + REPLAY_WINDOW))
        inserted = db.executemany("""
            INSERT INTO events(app, request_id, timestamp, status, auth, duration, event)
            VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(app, request_id) DO NOTHING
        """, [(app, event.request_id, event.timestamp, event.status, event.auth,
               event.duration_ms, event.model_dump_json(exclude_none=True)) for event in batch.events]).rowcount
        if inserted:
            db.execute("""
                INSERT INTO observed_totals VALUES (?, ?) ON CONFLICT(app) DO UPDATE
                SET total=observed_totals.total+excluded.total
            """, (app, inserted))
            db.execute("""
                DELETE FROM events WHERE app=? AND id IN (
                    SELECT id FROM events WHERE app=? ORDER BY timestamp DESC, id DESC LIMIT -1 OFFSET ?
                )
            """, (app, app, MAX_ROWS_PER_APP))
        db.execute("""
            INSERT INTO delivery VALUES (?, ?, ?) ON CONFLICT(app) DO UPDATE
            SET seen=excluded.seen, health=excluded.health WHERE excluded.seen >= delivery.seen
        """, (app, now, batch.delivery.model_dump_json()))
        return inserted


def snapshot(path, now):
    if not path.is_file():
        return []
    applications = []
    with connect(path) as db:
        db.execute("BEGIN")
        minute = (now - 60) * 1000
        has_totals = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='observed_totals'"
        ).fetchone()
        for delivery in db.execute("SELECT * FROM delivery WHERE seen >= ? ORDER BY app LIMIT 32",
                                   (now - RETENTION_SECONDS,)):
            app = delivery["app"]
            events = db.execute("""
                SELECT event FROM events WHERE app=? AND timestamp>=?
                ORDER BY timestamp DESC, id DESC LIMIT 25
            """, (app, (now - RETENTION_SECONDS) * 1000)).fetchall()
            stats = db.execute("""
                SELECT status, COUNT(*) AS count, SUM(duration) AS duration,
                       SUM(timestamp>=?) AS recent,
                       SUM(auth IN ('denied', 'authorization_denied', 'rate_limited', 'origin_denied')) AS failures
                FROM events WHERE app=? AND timestamp>=? GROUP BY status ORDER BY status
            """, ((now - 10) * 1000, app, minute)).fetchall()
            if has_totals:
                total = db.execute("SELECT total FROM observed_totals WHERE app=?", (app,)).fetchone()
            else:
                # Older collector stores only have retained events until the collector migrates them.
                total = db.execute("SELECT COUNT(*) FROM events WHERE app=?", (app,)).fetchone()
            count = sum(row["count"] for row in stats)
            applications.append({
                "id": app, "requests_per_minute": count,
                "requests_per_second": sum(row["recent"] for row in stats) / 10,
                "total_observed": total[0] if total else 0,
                "statuses": {row["status"]: row["count"] for row in stats},
                "auth_failures": sum(row["failures"] for row in stats),
                "mean_latency_ms": round(sum(row["duration"] for row in stats) / count, 1) if count else None,
                "last_seen": delivery["seen"],
                "status": "receiving" if now - delivery["seen"] <= 45 else "stale",
                "delivery": json.loads(delivery["health"]),
                "events": [json.loads(row["event"]) for row in events],
            })
    return applications

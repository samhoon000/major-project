"""Read-only traffic series for the Northfield staging dashboard."""

import json
import os
import re

from .policy_wire import SUBJECT
from .rules import SHOWCASE_APP, SHOWCASE_COUNT, SHOWCASE_ROUTE, SHOWCASE_WINDOW
from .store import connect

WINDOW_SECONDS = 120


def snapshot(path, now):
    if not path.is_file():
        return None
    start = now - WINDOW_SECONDS
    with connect(path) as db:
        db.execute("BEGIN")
        ready = db.execute("""
            SELECT COUNT(*) FROM sqlite_master WHERE type='table'
              AND name IN ('events','http_alerts','http_policy_receipts','http_policy_audit')
        """).fetchone()[0]
        if ready != 4:
            return None
        alerts = db.execute("""
            SELECT id, rule, status, last_seen FROM http_alerts
            WHERE app=? AND (last_seen>=? OR status IN ('open','acknowledged'))
            ORDER BY status IN ('open','acknowledged') DESC, last_seen DESC LIMIT 40
        """, (SHOWCASE_APP, start * 1000)).fetchall()
        active_alerts = db.execute("""
            SELECT COUNT(*) FROM http_alerts WHERE app=? AND status IN ('open','acknowledged')
        """, (SHOWCASE_APP,)).fetchone()[0]
        rows = db.execute("""
            WITH flagged AS (
                SELECT DISTINCT json_extract(request.value,'$.request_id') AS request_id
                FROM http_alerts AS alert, json_each(alert.evidence,'$.requests') AS request
                WHERE alert.app=? AND alert.last_seen>=? AND alert.status!='false_positive'
            ), categorized AS (
                SELECT e.timestamp/1000 AS second, e.status,
                       CASE
                           WHEN receipt.outcome='blocked' AND e.status=403 THEN 'blocked'
                           WHEN receipt.outcome='rate_limited' AND e.status=429 THEN 'blocked'
                           WHEN flagged.request_id IS NOT NULL THEN 'suspicious'
                           WHEN e.status<400 THEN 'normal'
                           ELSE 'other'
                       END AS category
                FROM events e
                LEFT JOIN flagged ON flagged.request_id=e.request_id
                LEFT JOIN http_policy_receipts receipt
                  ON receipt.app=e.app AND receipt.request_id=e.request_id
                WHERE e.app=? AND e.timestamp>=? AND e.timestamp<?
            )
            SELECT second, category, COUNT(*) AS count, SUM(status=429) AS rate_limited
            FROM categorized GROUP BY second, category ORDER BY second
        """, (SHOWCASE_APP, start * 1000, SHOWCASE_APP, start * 1000, now * 1000)).fetchall()
        students = []
        for key in ("HTTP_SHOWCASE_SUBJECT", "HTTP_SHOWCASE_SECOND_SUBJECT"):
            subject = os.getenv(key, "")
            row = None
            if re.fullmatch(SUBJECT, subject):
                row = db.execute("""
                    SELECT event FROM events
                    WHERE app=? AND json_extract(event,'$.subject')=?
                      AND json_extract(event,'$.method')='POST' AND json_extract(event,'$.route')=?
                    ORDER BY timestamp DESC,id DESC LIMIT 1
                """, (SHOWCASE_APP, subject, SHOWCASE_ROUTE)).fetchone()
            students.append(json.loads(row[0]) if row else None)
        applied = db.execute("""
            SELECT audit.revision, MIN(receipt.timestamp) AS timestamp
            FROM http_policy_audit audit JOIN http_policy_receipts receipt
              ON receipt.app=audit.app AND json_extract(receipt.body,'$.revision')=audit.revision
            WHERE audit.app=? AND audit.operation='approve' AND receipt.outcome='applied'
              AND receipt.timestamp>=?
            GROUP BY audit.revision
        """, (SHOWCASE_APP, start)).fetchall()
    points = [dict.fromkeys(("normal", "suspicious", "blocked", "other", "rate_limited"), 0)
              for _ in range(WINDOW_SECONDS)]
    for row in rows:
        point = points[row["second"] - start]
        point[row["category"]] = row["count"]
        point["rate_limited"] += row["rate_limited"]
    return {
        "start": start, "end": now, "points": points, "students": students,
        "threshold": {"count": SHOWCASE_COUNT, "seconds": SHOWCASE_WINDOW, "route": SHOWCASE_ROUTE}
        if re.fullmatch(SUBJECT, os.getenv("HTTP_SHOWCASE_SUBJECT", "")) else None,
        "alerts": [dict(row) for row in alerts], "active_alerts": active_alerts,
        "applied": [dict(row) for row in applied],
    }

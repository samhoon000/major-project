"""Durable arrival-based HTTP detection, independent of collector and GATv2 processes."""

import json
import logging
import time
from uuid import uuid4

from .rules import DEFAULT_RULES, RULE_NAMES, configured_rules, match_signal
from .store import connect, database_path, initialize as initialize_telemetry

BATCH_SIZE = 16
EVIDENCE_LIMIT = 8
QUEUE_HISTORY_MS = 26 * 3600 * 1000
ALERT_HISTORY_MS = 30 * 86400 * 1000
ALERT_LIMIT_PER_APP = 2000
HEARTBEAT_MS = 2000
STALE_MS = 10000
SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = ("open", "acknowledged", "resolved", "false_positive")
ACTIVE = ("open", "acknowledged")
LOG = logging.getLogger(__name__)


def now_ms():
    return time.time_ns() // 1_000_000


def initialize(path):
    initialize_telemetry(path)
    with connect(path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS http_detection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app TEXT NOT NULL, request_id TEXT NOT NULL, arrived INTEGER NOT NULL,
                route TEXT NOT NULL, method TEXT NOT NULL, status INTEGER NOT NULL,
                auth TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(app, request_id)
            );
            CREATE INDEX IF NOT EXISTS http_detection_window ON http_detection_events(app, arrived, id);
            CREATE INDEX IF NOT EXISTS http_detection_route ON http_detection_events(app, route, arrived, id);
            CREATE INDEX IF NOT EXISTS http_detection_age ON http_detection_events(arrived, id);
            CREATE TABLE IF NOT EXISTS http_detection_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), cursor INTEGER NOT NULL DEFAULT 0,
                processed INTEGER NOT NULL DEFAULT 0, last_request_id TEXT, last_arrived INTEGER,
                last_processed INTEGER, heartbeat INTEGER, last_cleanup INTEGER,
                errors INTEGER NOT NULL DEFAULT 0, last_error TEXT
            );
            INSERT OR IGNORE INTO http_detection_state(singleton) VALUES (1);
            CREATE TABLE IF NOT EXISTS http_alerts (
                id TEXT PRIMARY KEY, app TEXT NOT NULL, rule TEXT NOT NULL, scope TEXT NOT NULL,
                severity TEXT NOT NULL, status TEXT NOT NULL, first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL, last_signal INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                evidence TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS http_alerts_scope ON http_alerts(app, rule, scope, last_signal DESC);
            CREATE INDEX IF NOT EXISTS http_alerts_recent ON http_alerts(last_seen DESC, id);
            CREATE INDEX IF NOT EXISTS http_alerts_app_recent ON http_alerts(app, last_seen DESC, id);
            CREATE TRIGGER IF NOT EXISTS enqueue_http_detection AFTER INSERT ON events BEGIN
                INSERT INTO http_detection_events(app, request_id, arrived, route, method, status, auth, payload)
                VALUES (
                    NEW.app, NEW.request_id,
                    MAX(CAST(strftime('%s','now') AS INTEGER) * 1000
                        + CAST(substr(strftime('%f','now'),4,3) AS INTEGER),
                        COALESCE((SELECT arrived FROM http_detection_events ORDER BY id DESC LIMIT 1), 0)),
                    json_extract(NEW.event, '$.route'), json_extract(NEW.event, '$.method'),
                    NEW.status, NEW.auth, NEW.event
                ) ON CONFLICT(app, request_id) DO NOTHING;
            END;
        """)


def candidate(db, event, rule, signal):
    lower = event["arrived"] - rule.window_seconds * 1000
    window = "app=? AND arrived>? AND arrived<=? AND id<=?"
    params = (event["app"], lower, event["arrived"], event["id"])
    attributed_production = (signal.subject and event["app"].endswith("-prod")
                             and rule.id in {"route_burst", "authorization_denials"})
    occurred = "CAST(json_extract(payload,'$.timestamp') AS INTEGER)"
    if attributed_production:
        timestamp = json.loads(event["payload"])["timestamp"]
        if not -5000 <= event["arrived"] - timestamp <= 15000 or event["auth"] == "rate_limited":
            return None
        window += f" AND {occurred}>? AND {occurred}<=? AND arrived-{occurred} BETWEEN -5000 AND 15000"
        window += " AND auth!='rate_limited'"
        params += (timestamp - rule.window_seconds * 1000, timestamp)
    matching = f"{window} AND {signal.condition}"
    match_params = (*params, *signal.parameters)
    span = f", MAX({occurred})-MIN({occurred}) AS occurrence_span" if attributed_production else ""
    counts = db.execute(
        f"SELECT COUNT(*) AS count, MIN(arrived) AS first{span} FROM http_detection_events WHERE {matching}",
        match_params,
    ).fetchone()
    observed = counts["count"]
    if observed < rule.threshold:
        return None

    comparison = {}
    if rule.id == "server_errors":
        total = db.execute(f"SELECT COUNT(*) FROM http_detection_events WHERE {window}", params).fetchone()[0]
        if total < rule.minimum_samples or observed * 100 < rule.ratio_percent * total:
            return None
        comparison = {"sample_size": total, "observed_percent": round(100 * observed / total, 1),
                      "minimum_samples": rule.minimum_samples, "ratio_threshold_percent": rule.ratio_percent}
    elif rule.id == "traffic_spike":
        baseline = db.execute("""
            SELECT COUNT(*) FROM http_detection_events WHERE app=? AND arrived>? AND arrived<=?
        """, (event["app"], lower - rule.baseline_seconds * 1000, lower)).fetchone()[0]
        if (baseline < rule.minimum_samples
                or observed * 100 * rule.baseline_seconds < rule.ratio_percent * baseline * rule.window_seconds):
            return None
        comparison = {
            "baseline_count": baseline, "baseline_seconds": rule.baseline_seconds,
            "minimum_samples": rule.minimum_samples, "ratio_threshold_percent": rule.ratio_percent,
            "baseline_window_average": round(baseline * rule.window_seconds / rule.baseline_seconds, 1),
        }

    supporting = db.execute(f"""
        SELECT payload, arrived FROM http_detection_events WHERE {matching}
        ORDER BY arrived DESC, id DESC LIMIT ?
    """, (*match_params, EVIDENCE_LIMIT)).fetchall()
    requests = [{**json.loads(row["payload"]), "received_at": row["arrived"]} for row in supporting]
    if attributed_production and rule.id == "route_burst" and not any(200 <= row["status"] < 300 for row in requests):
        successful = db.execute(f"""
            SELECT payload, arrived FROM http_detection_events WHERE {matching} AND status BETWEEN 200 AND 299
            ORDER BY arrived DESC, id DESC LIMIT 1
        """, match_params).fetchone()
        if successful:
            requests[-1] = {**json.loads(successful["payload"]), "received_at": successful["arrived"]}
    evidence = {
        "route": signal.route, "explanation": signal.explanation, "observed_count": observed,
        "threshold": rule.threshold, "window_seconds": rule.window_seconds,
        "quality": "verified_subject" if signal.subject else "aggregate_observation",
        "confidence": "high" if rule.id == "repeated_policy_rate_limits" else "medium" if signal.subject else "low",
        "subject": signal.subject, **comparison,
        "requests": requests,
    }
    if signal.subject:
        evidence["method"] = event["method"]
    if rule.id == "route_burst":
        evidence["requests_per_second"] = round(observed / rule.window_seconds, 2)
        evidence["threshold_per_second"] = round(rule.threshold / rule.window_seconds, 2)
        if attributed_production:
            evidence["occurrence_span_ms"] = counts["occurrence_span"]
    return counts["first"], json.dumps(evidence, separators=(",", ":"))


def record_signal(db, event, rule, signal):
    scope = signal.route or ""
    if signal.subject:
        scope = "|".join((scope, event["method"], signal.subject))
    arrived = event["arrived"]
    previous = db.execute("""
        SELECT id, status, last_signal FROM http_alerts WHERE app=? AND rule=? AND scope=?
        ORDER BY last_signal DESC, rowid DESC LIMIT 1
    """, (event["app"], rule.id, scope)).fetchone()
    ongoing = previous and arrived - previous["last_signal"] <= rule.cooldown_seconds * 1000
    result = candidate(db, event, rule, signal)
    if not result:
        return
    if ongoing and previous["status"] not in ACTIVE:
        # A disposition suppresses repeats while the same incident remains active.
        db.execute("UPDATE http_alerts SET last_signal=? WHERE id=?", (arrived, previous["id"]))
        return
    first, evidence = result
    if ongoing:
        db.execute("""
            UPDATE http_alerts SET last_seen=?, last_signal=?, updated_at=?, evidence=? WHERE id=?
        """, (arrived, arrived, now_ms(), evidence, previous["id"]))
        return
    db.execute("""
        INSERT INTO http_alerts VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
    """, (str(uuid4()), event["app"], rule.id, scope, rule.severity, first, arrived, arrived, now_ms(), evidence))
    db.execute("""
        DELETE FROM http_alerts WHERE app=? AND id IN (
            SELECT id FROM http_alerts WHERE app=? ORDER BY last_seen DESC, rowid DESC LIMIT -1 OFFSET ?
        )
    """, (event["app"], event["app"], ALERT_LIMIT_PER_APP))


def process(path, rules=DEFAULT_RULES, clock=now_ms):
    current = clock()
    with connect(path) as db:
        state = db.execute("SELECT * FROM http_detection_state").fetchone()
        if state["heartbeat"] is not None and current - state["heartbeat"] < HEARTBEAT_MS:
            if not db.execute("SELECT 1 FROM http_detection_events WHERE id>? LIMIT 1", (state["cursor"],)).fetchone():
                return 0
        db.execute("BEGIN IMMEDIATE")
        state = db.execute("SELECT * FROM http_detection_state").fetchone()
        events = db.execute("SELECT * FROM http_detection_events WHERE id>? ORDER BY id LIMIT ?",
                            (state["cursor"], BATCH_SIZE)).fetchall()
        for event in events:
            event = dict(event)
            observation = json.loads(event["payload"])
            event["subject"] = observation.get("subject")
            event["mitigation_applied"] = observation.get("mitigation_applied", False)
            for rule in rules:
                if rule.enabled and (signal := match_signal(rule, event)):
                    record_signal(db, event, rule, signal)
        if events:
            last = events[-1]
            db.execute("""
                UPDATE http_detection_state SET cursor=?, processed=processed+?, last_request_id=?,
                    last_arrived=?, last_processed=?
            """, (last["id"], len(events), last["request_id"], last["arrived"], current))
        db.execute("UPDATE http_detection_state SET heartbeat=?, last_error=NULL", (current,))
        if state["last_cleanup"] is None or current - state["last_cleanup"] >= HEARTBEAT_MS:
            cursor = events[-1]["id"] if events else state["cursor"]
            db.execute("""
                DELETE FROM http_detection_events WHERE id IN (
                    SELECT id FROM http_detection_events WHERE arrived<? AND id<=? LIMIT 512
                )
            """, (current - QUEUE_HISTORY_MS, cursor))
            db.execute("""
                DELETE FROM http_alerts WHERE id IN (SELECT id FROM http_alerts WHERE last_seen<? LIMIT 128)
            """, (current - ALERT_HISTORY_MS,))
            db.execute("UPDATE http_detection_state SET last_cleanup=?", (current,))
        return len(events)


def record_failure(path, error):
    with connect(path) as db:
        db.execute("""
            UPDATE http_detection_state SET heartbeat=?, errors=errors+1, last_error=?
        """, (now_ms(), type(error).__name__))


def environment(app):
    return {"prod": "production", "production": "production", "staging": "staging",
            "stage": "staging", "local": "local", "test": "test",
            "dev": "development"}.get(app.rsplit("-", 1)[-1], "unspecified")


def alert_snapshot(path, filters, current=None):
    current = now_ms() if current is None else current
    blank = {"mode": "alert_only", "health": {"status": "offline"}, "alerts": [],
             "overview": {"total": 0, "active": 0, "severity": {}, "rules": {}, "active_apps": []},
             "rules": RULE_NAMES, "applications": []}
    if not path.is_file():
        return blank
    with connect(path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='http_detection_state'").fetchone():
            return blank
        db.execute("BEGIN")
        state = db.execute("SELECT * FROM http_detection_state").fetchone()
        pending = db.execute("SELECT COUNT(*), MIN(arrived) FROM http_detection_events WHERE id>?",
                             (state["cursor"],)).fetchone()
        heartbeat = state["heartbeat"]
        status = "offline"
        if heartbeat is not None and 0 <= current - heartbeat <= STALE_MS:
            status = "degraded" if state["last_error"] else "running"
        blank["health"] = {
            "status": status, "processed": state["processed"], "pending": pending[0],
            "lag_ms": max(0, current - pending[1]) if pending[1] is not None else 0,
            "last_request_id": state["last_request_id"], "last_processed": state["last_processed"],
            "last_event_delay_ms": (max(0, state["last_processed"] - state["last_arrived"])
                                    if state["last_processed"] is not None else None),
            "errors": state["errors"], "last_error": state["last_error"],
        }
        summary = db.execute("SELECT COUNT(*), SUM(status IN ('open','acknowledged')) FROM http_alerts").fetchone()
        blank["overview"] = {
            "total": summary[0], "active": summary[1] or 0,
            "severity": dict(db.execute("SELECT severity, COUNT(*) FROM http_alerts GROUP BY severity").fetchall()),
            "rules": dict(db.execute("SELECT rule, COUNT(*) FROM http_alerts GROUP BY rule").fetchall()),
            "active_apps": [row[0] for row in db.execute("""
                SELECT DISTINCT app FROM http_alerts WHERE status IN ('open','acknowledged') ORDER BY app LIMIT 32
            """)],
        }
        blank["applications"] = [row[0] for row in db.execute("""
            SELECT app FROM http_alerts UNION SELECT app FROM delivery ORDER BY app LIMIT 64
        """)]
        columns = ("app", "severity", "rule", "status")
        criteria = [(column, filters[column]) for column in columns if filters.get(column)]
        where = " AND ".join(f"{column}=?" for column, _ in criteria) or "1=1"
        for row in db.execute(f"""
            SELECT id, app, rule, severity, status, first_seen, last_seen, evidence
            FROM http_alerts WHERE {where} ORDER BY last_seen DESC, id DESC LIMIT 40
        """, tuple(value for _, value in criteria)):
            alert = dict(row)
            alert["evidence"] = json.loads(alert["evidence"])
            alert["environment"] = environment(alert["app"])
            blank["alerts"].append(alert)
    return blank


def set_status(path, alert_id, status):
    if not path.is_file():
        return False
    allowed = {"acknowledged": ("open",), "resolved": ACTIVE, "false_positive": ACTIVE}
    sources = allowed[status]
    with connect(path) as db:
        placeholders = ",".join("?" for _ in sources)
        return db.execute(f"""
            UPDATE http_alerts SET status=?, updated_at=?
            WHERE id=? AND (status IN ({placeholders}) OR status=?)
        """, (status, now_ms(), alert_id, *sources, status)).rowcount == 1


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    path = database_path()
    rules = configured_rules()
    initialize(path)
    LOG.info("HTTP behavioral detection running in alert-only mode")
    try:
        while True:
            try:
                count = process(path, rules)
            except Exception as error:
                LOG.error("HTTP detection processing failed: %s", type(error).__name__)
                try:
                    record_failure(path, error)
                except Exception as health_error:
                    LOG.error("HTTP detection health write failed: %s", type(health_error).__name__)
                time.sleep(2)
            else:
                if count < BATCH_SIZE:
                    time.sleep(0.25)
    except KeyboardInterrupt:
        LOG.info("HTTP behavioral detection stopped")


if __name__ == "__main__":
    main()

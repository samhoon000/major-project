"""Persistent shadow evaluator for Stage 2 HTTP alerts."""

import argparse
import hashlib
import json
import logging
import time
from uuid import uuid4

from .detection import initialize as initialize_detection, now_ms
from .protection_policy import MAX_DURATION, PROTECTED_ROUTES, Policy, evaluate, load_policy
from .staging_policy import disable_channels
from .rules import SHOWCASE_RULE
from .store import connect, database_path

LOG = logging.getLogger(__name__)
BATCH = 12
HEARTBEAT_MS = 2000
RETENTION_MS = 30 * 86400_000


def initialize(path):
    initialize_detection(path)
    with connect(path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS http_protection_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                mode TEXT NOT NULL DEFAULT 'alert_only' CHECK(mode IN ('alert_only','shadow')),
                emergency INTEGER NOT NULL DEFAULT 0, since INTEGER NOT NULL DEFAULT 0,
                config TEXT, heartbeat INTEGER, processed INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_cleanup INTEGER
            );
            INSERT OR IGNORE INTO http_protection_state(singleton) VALUES (1);
            CREATE TABLE IF NOT EXISTS http_protection_queue (
                alert_id TEXT PRIMARY KEY, observed INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS http_protection_queue_order ON http_protection_queue(observed, alert_id);
            CREATE TABLE IF NOT EXISTS http_protection_audit (
                id INTEGER PRIMARY KEY, recorded INTEGER NOT NULL, source TEXT NOT NULL,
                operation TEXT NOT NULL, details TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS http_protection_decisions (
                id TEXT PRIMARY KEY, episode TEXT NOT NULL UNIQUE, app TEXT NOT NULL,
                rule TEXT NOT NULL, trigger_request_id TEXT, action TEXT NOT NULL,
                severity TEXT NOT NULL, route TEXT, reason TEXT NOT NULL, evidence TEXT NOT NULL,
                created INTEGER NOT NULL, expires INTEGER, revoked INTEGER,
                mode TEXT NOT NULL CHECK(mode='shadow'), enforced INTEGER NOT NULL CHECK(enforced=0)
            );
            CREATE INDEX IF NOT EXISTS http_protection_recent ON http_protection_decisions(created DESC);
            CREATE INDEX IF NOT EXISTS http_protection_cooldown
                ON http_protection_decisions(app, action, route, created DESC);
            CREATE TRIGGER IF NOT EXISTS http_protection_alert_insert AFTER INSERT ON http_alerts BEGIN
                INSERT INTO http_protection_queue VALUES (NEW.id, NEW.last_seen);
            END;
            CREATE TRIGGER IF NOT EXISTS http_protection_alert_update
            AFTER UPDATE OF last_seen, evidence ON http_alerts
            WHEN OLD.last_seen != NEW.last_seen OR OLD.evidence != NEW.evidence BEGIN
                INSERT INTO http_protection_queue VALUES (NEW.id, NEW.last_seen)
                ON CONFLICT(alert_id) DO UPDATE SET observed=excluded.observed;
            END;
        """)


def audit(db, source, operation, details, now):
    db.execute("INSERT INTO http_protection_audit(recorded, source, operation, details) VALUES (?, ?, ?, ?)",
               (now, source, operation, json.dumps(details, separators=(",", ":"))))


def sync_policy(db, policy, state, now):
    value = policy.model_dump_json()
    if value != state["config"]:
        previous = json.loads(state["config"]) if state["config"] else None
        db.execute("UPDATE http_protection_state SET config=?", (value,))
        audit(db, "worker", "policy_configured", {"before": previous, "after": policy.model_dump()}, now)


def change_mode(path, action, source, clock=now_ms):
    commands = {"alert-only": "alert_only", "shadow": "shadow", "emergency-disable": "alert_only",
                "reset-emergency": "alert_only"}
    if action not in commands or not path.is_file():
        return False
    now = clock()
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        state = db.execute("SELECT mode, emergency FROM http_protection_state").fetchone()
        if action == "shadow" and state["emergency"]:
            return False
        emergency = state["emergency"]
        if action == "emergency-disable":
            emergency = 1
            disable_channels(db, now // 1000, "emergency_disable")
            db.execute("""
                UPDATE http_protection_decisions SET revoked=?
                WHERE expires>? AND revoked IS NULL
            """, (now, now))
        elif action == "alert-only":
            disable_channels(db, now // 1000, "alert_only_disable", production_only=True)
        elif action == "reset-emergency":
            emergency = 0
        mode = commands[action]
        if mode != state["mode"] or emergency != state["emergency"]:
            db.execute("UPDATE http_protection_state SET mode=?, emergency=?, since=?", (mode, emergency, now))
            audit(db, source, action, {"previous_mode": state["mode"], "mode": mode,
                                      "emergency": bool(emergency)}, now)
    return True


def dismiss(path, decision_id, source, clock=now_ms):
    if not path.is_file():
        return False
    now = clock()
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        if (db.execute("SELECT 1 FROM sqlite_master WHERE name='http_policy_approvals'").fetchone()
                and db.execute("SELECT 1 FROM http_policy_approvals WHERE decision=?", (decision_id,)).fetchone()):
            return False
        result = db.execute("""
            UPDATE http_protection_decisions SET revoked=? WHERE id=? AND revoked IS NULL AND expires>?
        """, (now, decision_id, now))
        if not result.rowcount:
            return False
        audit(db, source, "proposal_dismissed", {"decision_id": decision_id}, now)
    return True


def alert_record(row):
    alert = dict(row)
    alert["evidence"] = json.loads(alert["evidence"])
    return alert


def record(db, trigger, proposal, policy, now):
    episode = hashlib.sha256(json.dumps([
        trigger["app"], proposal.action, proposal.route, proposal.subject, sorted(item["id"] for item in proposal.supporting),
    ], separators=(",", ":")).encode()).hexdigest()
    if proposal.duration_seconds:
        recent = db.execute("""
            SELECT 1 FROM http_protection_decisions
            WHERE app=? AND action=? AND route IS ? AND json_extract(evidence,'$.subject') IS ? AND expires+?>?
              AND (? != ? OR revoked IS NULL)
            LIMIT 1
        """, (trigger["app"], proposal.action, proposal.route, proposal.subject,
              policy.cooldown_seconds * 1000, now, trigger["rule"], SHOWCASE_RULE)).fetchone()
        if recent:
            return
    samples = trigger["evidence"]["requests"]
    rate = policy.proposed_requests_per_minute
    if proposal.subject:
        rate = min(120, rate)
    evidence = {
        "quality": "verified_subject" if proposal.subject else "aggregate_observation",
        "subject_available": proposal.subject is not None,
        "subject": proposal.subject,
        "method": "POST" if proposal.subject else None,
        "correlation_window_seconds": policy.window_seconds,
        "proposed_requests_per_minute": rate if proposal.action == "RATE_LIMIT" else None,
        "signals": [{
            "alert_id": alert["id"], "rule": alert["rule"], "severity": alert["severity"],
            "count": alert["evidence"]["observed_count"], "window_seconds": alert["evidence"]["window_seconds"],
            "observed_per_second": alert["evidence"].get("requests_per_second"),
            "threshold_per_second": alert["evidence"].get("threshold_per_second"),
            "route": alert["evidence"]["route"], "first_seen": alert["first_seen"], "last_seen": alert["last_seen"],
            "request_ids": [item["request_id"] for item in alert["evidence"]["requests"]],
        } for alert in proposal.supporting],
    }
    expires = now + min(proposal.duration_seconds, MAX_DURATION) * 1000 if proposal.duration_seconds else None
    db.execute("""
        INSERT INTO http_protection_decisions
        (id, episode, app, rule, trigger_request_id, action, severity, route, reason, evidence, created, expires,
         mode, enforced) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'shadow', 0)
        ON CONFLICT(episode) DO NOTHING
    """, (str(uuid4()), episode, trigger["app"], trigger["rule"], samples[0]["request_id"] if samples else None,
          proposal.action, proposal.severity, proposal.route, proposal.reason, json.dumps(evidence), now, expires))


def process(path, policy, clock=now_ms):
    now = clock()
    with connect(path) as db:
        state = db.execute("SELECT * FROM http_protection_state").fetchone()
        if state["heartbeat"] is not None and now - state["heartbeat"] < HEARTBEAT_MS:
            if not db.execute("SELECT 1 FROM http_protection_queue LIMIT 1").fetchone():
                return 0
        db.execute("BEGIN IMMEDIATE")
        now = clock()
        state = db.execute("SELECT * FROM http_protection_state").fetchone()
        sync_policy(db, policy, state, now)
        items = db.execute("""
            SELECT * FROM http_protection_queue WHERE observed<=? ORDER BY observed, alert_id LIMIT ?
        """, (now, BATCH)).fetchall()
        since = max(state["since"], now - policy.window_seconds * 1000)
        for item in items:
            if state["mode"] == "shadow" and not state["emergency"] and since <= item["observed"] <= now:
                alert = db.execute("""
                    SELECT * FROM http_alerts WHERE id=? AND status IN ('open','acknowledged')
                """, (item["alert_id"],)).fetchone()
                if alert:
                    related = db.execute("""
                        SELECT * FROM http_alerts WHERE app=? AND last_seen BETWEEN ? AND ?
                        AND status IN ('open','acknowledged') ORDER BY last_seen DESC, id LIMIT 64
                    """, (alert["app"], since, alert["last_seen"])).fetchall()
                    record(db, trigger := alert_record(alert),
                           evaluate(trigger, [alert_record(row) for row in related], policy), policy, now)
            db.execute("DELETE FROM http_protection_queue WHERE alert_id=?", (item["alert_id"],))
        db.execute("""
            UPDATE http_protection_state SET heartbeat=?, processed=processed+?, last_error=NULL
        """, (now, len(items)))
        if state["last_cleanup"] is None or now - state["last_cleanup"] >= 60000:
            db.execute("""
                DELETE FROM http_protection_decisions WHERE id IN (
                    SELECT id FROM http_protection_decisions WHERE created<? LIMIT 256
                )
            """, (now - RETENTION_MS,))
            db.execute("UPDATE http_protection_state SET last_cleanup=?", (now,))
        return len(items)


def snapshot(path, now=None):
    now = now_ms() if now is None else now
    view = {"mode": "alert_only", "emergency": False, "ready": False, "health": {"status": "offline"},
            "totals": {}, "decisions": [], "audit": [], "policy": Policy().model_dump(),
            "protected_routes": PROTECTED_ROUTES}
    if not path.is_file():
        return view
    with connect(path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='http_protection_state'").fetchone():
            return view
        db.execute("BEGIN")
        state = db.execute("SELECT * FROM http_protection_state").fetchone()
        age = now - state["heartbeat"] if state["heartbeat"] is not None else None
        status = "offline" if age is None or age < 0 or age > 10000 else (
            "degraded" if state["last_error"] else "running")
        view.update(mode=state["mode"], emergency=bool(state["emergency"]), ready=True, health={
            "status": status, "processed": state["processed"], "errors": state["errors"],
            "last_error": state["last_error"], "heartbeat": state["heartbeat"],
            "pending": db.execute("SELECT COUNT(*) FROM http_protection_queue").fetchone()[0],
        })
        if state["config"]:
            view["policy"] = json.loads(state["config"])
        totals = db.execute("""
            SELECT COUNT(*), SUM(action='BLOCK'), SUM(action='RATE_LIMIT'), SUM(enforced),
                   SUM(action='BLOCK' AND expires<=? AND revoked IS NULL)
            FROM http_protection_decisions
        """, (now,)).fetchone()
        view["totals"] = dict(zip(("decisions", "proposed_blocks", "proposed_limits", "enforced_blocks",
                                  "expired_block_proposals"), (value or 0 for value in totals)))
        approvals_exist = db.execute("SELECT 1 FROM sqlite_master WHERE name='http_policy_approvals'").fetchone()
        for row in db.execute("""
            SELECT id, app, rule, trigger_request_id, action, severity, route, reason, evidence,
                   created, expires, revoked, mode, enforced
            FROM http_protection_decisions ORDER BY created DESC, rowid DESC LIMIT 40
        """):
            decision = alert_record(row)
            decision["enforced"] = bool(decision["enforced"])
            approved = approvals_exist and db.execute("SELECT 1 FROM http_policy_approvals WHERE decision=?",
                                                       (decision["id"],)).fetchone()
            decision["status"] = ("dismissed" if decision["revoked"] is not None else
                                  "approved" if approved else
                                  "expired" if decision["expires"] is not None and decision["expires"] <= now else
                                  "proposed" if decision["expires"] is not None else "recorded")
            view["decisions"].append(decision)
        for row in db.execute("""
            SELECT recorded, source, operation, details FROM http_protection_audit ORDER BY id DESC LIMIT 20
        """):
            item = dict(row)
            detail = json.loads(item["details"])
            if item["operation"] == "policy_configured":
                before, after = detail["before"] or {}, detail["after"]
                detail = {"changed": sorted(key for key in after if after[key] != before.get(key))}
            view["audit"].append({**item, "details": detail})
    return view


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("alert-only", "shadow", "emergency-disable", "reset-emergency"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    path = database_path()
    initialize(path)
    if args.mode:
        if not change_mode(path, args.mode, "local CLI"):
            parser.error("Mode is unavailable. Reset the emergency latch before selecting Shadow.")
        return
    policy = load_policy()
    LOG.info("HTTP protection evaluator started; no enforcement point is connected")
    try:
        while True:
            try:
                if process(path, policy) < BATCH:
                    time.sleep(0.25)
            except Exception as error:
                LOG.error("HTTP protection evaluation failed: %s", type(error).__name__)
                try:
                    with connect(path) as db:
                        db.execute("UPDATE http_protection_state SET heartbeat=?, errors=errors+1, last_error=?",
                                   (now_ms(), type(error).__name__))
                except Exception:
                    LOG.error("HTTP protection health write failed")
                time.sleep(2)
    except KeyboardInterrupt:
        LOG.info("HTTP protection evaluator stopped")


if __name__ == "__main__":
    main()

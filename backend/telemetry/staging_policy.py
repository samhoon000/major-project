"""Operator approvals, signed staging snapshots, and authenticated receipts."""

import json
import time
from uuid import uuid4

from .policy_wire import MAX_LIFETIME, Rule, Snapshot, channel_environment
from .protection_policy import Policy, VERIFIED_QUALITY, attributed_proposal
from .rules import SHOWCASE_RULE
from .store import connect

SYNC_FRESH_SECONDS = 10


def initialize(path, channels, allow_production=False):
    with connect(path) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS http_policy_channels (
                app TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL,
                last_sync INTEGER, receiver_errors INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS http_policy_history (
                app TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(app,revision)
            );
            CREATE TABLE IF NOT EXISTS http_policy_nonce (
                app TEXT NOT NULL, nonce TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(app,nonce)
            );
            CREATE TABLE IF NOT EXISTS http_policy_approvals (decision TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS http_policy_production_opt_in (app TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS http_policy_receipts (
                app TEXT NOT NULL, id TEXT NOT NULL, request_id TEXT, timestamp INTEGER NOT NULL,
                outcome TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(app,id),
                UNIQUE(app,request_id)
            );
            CREATE INDEX IF NOT EXISTS http_policy_receipts_time ON http_policy_receipts(app,timestamp DESC);
            CREATE TABLE IF NOT EXISTS http_policy_recoveries (
                app TEXT NOT NULL, rule_id TEXT NOT NULL, timestamp INTEGER NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(app,rule_id)
            );
            CREATE INDEX IF NOT EXISTS http_policy_recoveries_time ON http_policy_recoveries(app,timestamp DESC);
            CREATE TABLE IF NOT EXISTS http_policy_audit (
                id INTEGER PRIMARY KEY, app TEXT NOT NULL, timestamp INTEGER NOT NULL,
                operation TEXT NOT NULL, revision INTEGER NOT NULL, target TEXT
            );
        """)
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM http_policy_production_opt_in")
        for app in channels:
            if current(db, app) is None:
                publish(db, app, 1, False, [], int(time.time()), "channel_created")
            if allow_production and channel_environment(app) == "production":
                db.execute("INSERT INTO http_policy_production_opt_in VALUES (?)", (app,))
        for row in db.execute("SELECT body FROM http_policy_channels WHERE app LIKE '%-prod'").fetchall():
            policy = Snapshot.model_validate_json(row[0])
            if policy.enabled and not production_allowed(db, policy.app):
                publish(db, policy.app, policy.revision + 1, False, [], int(time.time()), "production_opt_in_removed")


def production_allowed(db, app):
    return db.execute("SELECT 1 FROM http_policy_production_opt_in WHERE app=?", (app,)).fetchone() is not None


def current(db, app):
    row = db.execute("SELECT body FROM http_policy_channels WHERE app=?", (app,)).fetchone()
    return Snapshot.model_validate_json(row[0]) if row else None


def acknowledgment(db, policy):
    row = db.execute("""
        SELECT outcome FROM http_policy_receipts WHERE app=?
        AND json_extract(body,'$.revision')=? AND outcome IN ('applied','disabled')
        ORDER BY timestamp DESC,(outcome='disabled') DESC LIMIT 1
    """, (policy.app, policy.revision)).fetchone()
    return row[0] if row else "pending"


def receiver_ready(policy, now, last_sync):
    return last_sync is not None and 0 <= now - last_sync <= SYNC_FRESH_SECONDS and now < policy.expires


def publish(db, app, revision, enabled, rules, now, action, target=None):
    value = Snapshot(version=1, app=app, environment=channel_environment(app), id=str(uuid4()), revision=revision,
                     created=now, expires=now + MAX_LIFETIME, enabled=enabled,
                     rules=[rule for rule in rules if rule.expires > now])
    body = value.model_dump_json()
    db.execute("""
        INSERT INTO http_policy_channels(app,revision,body) VALUES (?,?,?)
        ON CONFLICT(app) DO UPDATE SET revision=excluded.revision, body=excluded.body
    """, (app, revision, body))
    db.execute("INSERT INTO http_policy_history VALUES (?,?,?)", (app, revision, body))
    db.execute("DELETE FROM http_policy_history WHERE app=? AND revision<?", (app, revision - 999))
    db.execute("""
        INSERT INTO http_policy_audit(app,timestamp,operation,revision,target) VALUES (?,?,?,?,?)
    """, (app, now, action, revision, target))
    return value


def command(path, app, action, target=None, clock=time.time):
    now = int(clock())
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        previous = current(db, app)
        if not previous:
            return None
        state = db.execute("SELECT emergency, mode, config FROM http_protection_state").fetchone()
        if action == "disable":
            return publish(db, app, previous.revision + 1, False, [], now, action)
        if not state or state["emergency"]:
            return None
        production = previous.environment == "production"
        if production and not production_allowed(db, app):
            return None
        if production and action in {"enable-production", "approve"}:
            last_sync = db.execute("SELECT last_sync FROM http_policy_channels WHERE app=?", (app,)).fetchone()[0]
            expected = "applied" if previous.enabled else "disabled"
            if not receiver_ready(previous, now, last_sync) or acknowledgment(db, previous) != expected:
                return None
        if action in {"enable", "enable-production"}:
            if previous.enabled or production != (action == "enable-production") or state["mode"] != "shadow":
                return None
            return publish(db, app, previous.revision + 1, True, [], now, action)
        if not previous.enabled:
            return None
        rules = [rule for rule in previous.rules if rule.expires > now]
        if action == "revoke":
            remaining = [rule for rule in rules if rule.id != target]
            if len(remaining) == len(rules):
                return None
            rules = remaining
        elif action == "approve":
            if state["mode"] != "shadow" or len(rules) >= 16:
                return None
            row = db.execute("""
                SELECT * FROM http_protection_decisions
                WHERE id=? AND app=? AND action IN ('BLOCK','RATE_LIMIT') AND revoked IS NULL AND expires>?
            """, (target, app, now * 1000 + 999)).fetchone()
            if not row:
                return None
            evidence = json.loads(row["evidence"])
            signal_rules = {signal["rule"] for signal in evidence["signals"]}
            if (evidence.get("quality") not in VERIFIED_QUALITY or not evidence.get("subject")
                    or evidence.get("method") != "POST"
                    or (signal_rules != {"route_burst", "authorization_denials"} and
                        not (not production and signal_rules == {SHOWCASE_RULE} and row["action"] == "RATE_LIMIT"))
                    or (production and row["action"] != "RATE_LIMIT")
                    or any(rule.subject == evidence["subject"] and rule.route == row["route"] for rule in rules)):
                return None
            # A disposition made after the shadow decision invalidates the approval evidence.
            alerts = []
            for signal in evidence["signals"]:
                alert = db.execute("SELECT * FROM http_alerts WHERE id=? AND app=?",
                                   (signal["alert_id"], app)).fetchone()
                if not alert or alert["status"] not in {"open", "acknowledged"}:
                    return None
                alerts.append({**dict(alert), "evidence": json.loads(alert["evidence"])})
            policy = Policy.model_validate_json(state["config"]) if state["config"] else Policy()
            rate = min(120, policy.proposed_requests_per_minute)
            if row["action"] == "RATE_LIMIT" and evidence.get("proposed_requests_per_minute") != rate:
                return None
            proposal = attributed_proposal(max(alerts, key=lambda alert: alert["last_seen"]), alerts, policy)
            if (not proposal or proposal.action != row["action"] or proposal.route != row["route"]
                    or proposal.subject != evidence["subject"]):
                return None
            inserted = db.execute("INSERT INTO http_policy_approvals VALUES (?) ON CONFLICT DO NOTHING",
                                  (target,)).rowcount
            if not inserted:
                return None
            rules.append(Rule(id=target, subject=evidence["subject"], method="POST", route=row["route"],
                              action="block" if row["action"] == "BLOCK" else "rate_limit",
                              requests_per_minute=rate,
                              expires=min(row["expires"] // 1000, now + MAX_LIFETIME)))
        elif action != "refresh":
            return None
        return publish(db, app, previous.revision + 1, True, rules, now, action, target)


def disable_channels(db, now, action, *, production_only=False):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='http_policy_channels'").fetchone():
        return
    for row in db.execute("SELECT body FROM http_policy_channels").fetchall():
        snapshot = Snapshot.model_validate_json(row[0])
        if snapshot.enabled and (not production_only or snapshot.environment == "production"):
            publish(db, snapshot.app, snapshot.revision + 1, False, [], now, action)


def exchange(path, request, now):
    with connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM http_policy_nonce WHERE expires<?", (now,))
        if db.execute("SELECT 1 FROM http_policy_nonce WHERE app=? AND nonce=?",
                      (request.app, request.nonce)).fetchone():
            return None, 409
        if db.execute("SELECT COUNT(*) FROM http_policy_nonce WHERE app=?", (request.app,)).fetchone()[0] >= 128:
            return None, 429
        db.execute("INSERT INTO http_policy_nonce VALUES (?,?,?)", (request.app, request.nonce, request.timestamp + 30))
        for receipt in request.receipts:
            row = db.execute("SELECT body FROM http_policy_history WHERE app=? AND revision=?",
                             (request.app, receipt.revision)).fetchone()
            if not row or not now - 3600 <= receipt.timestamp <= now + 30:
                continue
            issued = Snapshot.model_validate_json(row[0])
            if (receipt.policy_id != issued.id or not issued.created <= receipt.timestamp < issued.expires
                    or (receipt.outcome == "applied" and not issued.enabled)):
                continue
            if receipt.outcome in {"blocked", "rate_limited"}:
                rule = next((item for item in issued.rules if item.id == receipt.rule_id), None)
                expected = "blocked" if rule and rule.action == "block" else "rate_limited"
                if not rule or receipt.outcome != expected or receipt.timestamp >= rule.expires:
                    continue
            db.execute("""
                INSERT INTO http_policy_receipts VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING
            """, (request.app, receipt.id, receipt.request_id, receipt.timestamp, receipt.outcome,
                  receipt.model_dump_json()))
        db.execute("""
            DELETE FROM http_policy_receipts WHERE app=? AND id IN (
                SELECT id FROM http_policy_receipts WHERE app=? ORDER BY timestamp DESC,id DESC LIMIT -1 OFFSET 2000
            )
        """, (request.app, request.app))
        db.execute("UPDATE http_policy_channels SET last_sync=?, receiver_errors=? WHERE app=?",
                   (now, request.errors, request.app))
        policy = current(db, request.app)
        if policy and policy.expires <= now:
            # Renew only an empty snapshot. Polling never renews an approved rule.
            policy = publish(db, policy.app, policy.revision + 1, policy.enabled, [], now, "expired_refresh")
        for item in verified_recoveries(db, request.app, now):
            db.execute("INSERT INTO http_policy_recoveries VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
                       (request.app, item["rule_id"], item["timestamp"], json.dumps(item)))
        db.execute("DELETE FROM http_policy_recoveries WHERE app=? AND timestamp<?",
                   (request.app, (now - 30 * 86400) * 1000))
        return policy, 200


def verified_recoveries(db, app, now):
    """Correlate a real enforcement receipt and later successful, unrestricted telemetry."""
    actions = db.execute("""
        SELECT r.body AS receipt, h.body AS policy
        FROM http_policy_receipts r JOIN http_policy_history h
          ON h.app=r.app AND h.revision=json_extract(r.body,'$.revision')
        WHERE r.app=? AND r.timestamp>=? AND r.outcome IN ('rate_limited','blocked')
          AND NOT EXISTS (
            SELECT 1 FROM http_policy_recoveries saved
            WHERE saved.app=r.app AND saved.rule_id=json_extract(r.body,'$.rule_id')
          )
        GROUP BY json_extract(r.body,'$.rule_id') HAVING r.timestamp=MAX(r.timestamp)
        ORDER BY r.timestamp DESC LIMIT 20
    """, (app, now - 3600)).fetchall()
    recoveries = []
    for action in actions:
        enforcement = json.loads(action["receipt"])
        policy = Snapshot.model_validate_json(action["policy"])
        rule = next(item for item in policy.rules if item.id == enforcement["rule_id"])
        match = db.execute("""
            SELECT e.request_id, e.timestamp, e.status, h.body
            FROM events e JOIN http_policy_history h ON h.app=e.app
              AND h.revision=json_extract(e.event,'$.policy_revision')
            WHERE e.app=? AND e.timestamp>=? AND e.status BETWEEN 200 AND 299
              AND e.auth='authenticated' AND json_extract(e.event,'$.policy_unrestricted')=1
              AND json_extract(e.event,'$.subject')=? AND json_extract(e.event,'$.method')=?
              AND json_extract(e.event,'$.route')=? AND h.revision>=?
              AND EXISTS (
                SELECT 1 FROM http_policy_receipts receipt
                WHERE receipt.app=e.app AND json_extract(receipt.body,'$.revision')=h.revision
                  AND receipt.outcome IN ('applied','disabled') AND receipt.timestamp<=e.timestamp/1000
              )
              AND NOT EXISTS (
                SELECT 1 FROM json_each(h.body,'$.rules') AS active
                WHERE json_extract(active.value,'$.subject')=? AND json_extract(active.value,'$.method')=?
                  AND json_extract(active.value,'$.route')=? AND json_extract(active.value,'$.expires')*1000>e.timestamp
              )
            ORDER BY e.timestamp,e.id LIMIT 1
        """, (app, (enforcement["timestamp"] + 1) * 1000, rule.subject, rule.method, rule.route,
              enforcement["revision"], rule.subject, rule.method, rule.route)).fetchone()
        if match:
            recoveries.append({
                "rule_id": rule.id, "subject": rule.subject, "method": rule.method, "route": rule.route,
                "request_id": match["request_id"], "timestamp": match["timestamp"], "status": match["status"],
                "enforcement_request_id": enforcement["request_id"],
                "revision": json.loads(match["body"])["revision"],
            })
    return recoveries


def snapshot(path, now=None):
    state = {"channels": [], "pending": [], "audit": []}
    if not path.is_file():
        return state
    now = int(time.time()) if now is None else now
    with connect(path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='http_policy_channels'").fetchone():
            return state
        recovery_store = db.execute("SELECT 1 FROM sqlite_master WHERE name='http_policy_recoveries'").fetchone()
        for row in db.execute("SELECT * FROM http_policy_channels ORDER BY app LIMIT 16"):
            policy = Snapshot.model_validate_json(row["body"])
            receipts = [json.loads(receipt[0]) for receipt in db.execute("""
                SELECT body FROM http_policy_receipts WHERE app=? ORDER BY timestamp DESC,id DESC LIMIT 20
            """, (policy.app,))]
            ack = acknowledgment(db, policy)
            receiving = receiver_ready(policy, now, row["last_sync"])
            state["channels"].append({
                **policy.model_dump(), "last_sync": row["last_sync"], "receiver_errors": row["receiver_errors"],
                "can_enable": (policy.environment == "staging" or
                               (receiving and ack == "disabled" and production_allowed(db, policy.app))),
                "delivery": "receiving" if receiving else "stale",
                "acknowledgment": ack,
                "recoveries": [json.loads(recovery[0]) for recovery in db.execute("""
                    SELECT body FROM http_policy_recoveries WHERE app=? ORDER BY timestamp DESC LIMIT 20
                """, (policy.app,))] if recovery_store else [],
                "confirmed": dict(db.execute("""
                    SELECT outcome,COUNT(*) FROM http_policy_receipts WHERE app=?
                    AND outcome IN ('blocked','rate_limited') GROUP BY outcome
                """, (policy.app,)).fetchall()), "receipts": receipts,
            })
        state["pending"] = [dict(row) for row in db.execute("""
            SELECT id,app,action,route,expires,json_extract(evidence,'$.subject') AS subject
            FROM http_protection_decisions
            WHERE revoked IS NULL AND expires>? AND json_extract(evidence,'$.quality')
                IN ('verified_subject','verified_staging_subject')
            AND id NOT IN (SELECT decision FROM http_policy_approvals) ORDER BY created DESC LIMIT 20
        """, (now * 1000,))]
        state["audit"] = [dict(row) for row in db.execute("SELECT * FROM http_policy_audit ORDER BY id DESC LIMIT 20")]
    return state

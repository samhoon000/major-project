"""Operator-driven checks for the disposable Northfield showcase."""

import asyncio
import json
import os
import re
import time

import httpx
from fastapi import HTTPException

from . import staging_policy
from .policy_wire import SUBJECT
from .rules import SHOWCASE_APP, SHOWCASE_COUNT, SHOWCASE_ROUTE, SHOWCASE_RULE, SHOWCASE_WINDOW
from .store import connect, database_path

ORIGIN = "http://127.0.0.1:8011"
lock = asyncio.Lock()
started = False
armed_revision = None
blocked_revision = None
blocking_checked = False
recovery_checked = False
ready_after = 0.0


def config():
    subject = os.getenv("HTTP_SHOWCASE_SUBJECT", "")
    course = os.getenv("HTTP_SHOWCASE_COURSE", "")
    if not re.fullmatch(SUBJECT, subject) or not re.fullmatch(r"[1-9][0-9]{0,8}", course):
        return None
    try:
        sessions = json.loads(os.getenv("HTTP_SHOWCASE_SESSIONS", ""))
    except ValueError:
        return None
    if (not isinstance(sessions, list) or len(sessions) != 2
            or any(not isinstance(pair, list) or len(pair) != 2 or
                   any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{20,4096}", value)
                       for value in pair) for pair in sessions)
            or sessions[0][0] == sessions[1][0]):
        return None
    return subject, course, sessions


def policy_state(subject, *, reset=False):
    with connect(database_path()) as db:
        if reset:
            db.execute("BEGIN IMMEDIATE")
        now = int(time.time())
        policy = staging_policy.current(db, SHOWCASE_APP)
        sync = db.execute("SELECT last_sync FROM http_policy_channels WHERE app=?", (SHOWCASE_APP,)).fetchone()
        if not policy or not sync or not staging_policy.receiver_ready(policy, now, sync[0]):
            raise HTTPException(409, "Northfield has not recently synchronized the current policy.")
        expected = "applied" if policy.enabled else "disabled"
        if staging_policy.acknowledgment(db, policy) != expected:
            raise HTTPException(409, "Wait for Northfield to acknowledge the current revision.")
        active_rules = [rule for rule in policy.rules
                        if rule.subject == subject and rule.route == SHOWCASE_ROUTE and rule.expires > now]
        showcase_active = any(db.execute("""
            SELECT 1 FROM http_protection_decisions WHERE id=? AND app=? AND rule=? AND revoked IS NULL
        """, (rule.id, SHOWCASE_APP, SHOWCASE_RULE)).fetchone() for rule in active_rules)
        if reset:
            if active_rules:
                raise HTTPException(409, "Revoke the showcase policy and wait for acknowledgment before resetting.")
            db.execute("""
                UPDATE http_protection_decisions SET revoked=?
                WHERE app=? AND rule=? AND route=? AND json_extract(evidence,'$.subject')=? AND revoked IS NULL
            """, (now * 1000, SHOWCASE_APP, SHOWCASE_RULE, SHOWCASE_ROUTE, subject))
            db.execute("""
                UPDATE http_alerts SET status='resolved',updated_at=?
                WHERE app=? AND rule=? AND scope=? AND status IN ('open','acknowledged')
            """, (now * 1000, SHOWCASE_APP, SHOWCASE_RULE, f"{SHOWCASE_ROUTE}|POST|{subject}"))
        return policy, bool(active_rules), showcase_active


async def course_request(client, course, session, student):
    cookie, csrf = session
    response = await client.post(f"{ORIGIN}/api/courses/{course}/access",
                                 headers={"X-CSRF-Token": csrf, "Cookie": f"portal={cookie}"})
    if response.status_code in (401, 403):
        raise HTTPException(409, "The disposable student session is unavailable. Restart the showcase.")
    return {"student": student, "status": response.status_code, "request_id": response.headers.get("x-request-id")}


async def action(name, settings):
    global started, armed_revision, blocked_revision, blocking_checked, recovery_checked, ready_after
    subject, course, sessions = settings
    if lock.locked():
        raise HTTPException(409, "A showcase check is already running.")
    async with lock:
        if name == "reset":
            await asyncio.to_thread(policy_state, subject, reset=True)
            started = blocking_checked = recovery_checked = False
            armed_revision = blocked_revision = None
            ready_after = time.monotonic() + SHOWCASE_WINDOW + 1
            return {"requests": [], "message": "Reset complete. Wait nine seconds before generating requests."}
        policy, active, showcase_active = await asyncio.to_thread(policy_state, subject)
        if name == "generate":
            if started or active or not policy.enabled or time.monotonic() < ready_after:
                raise HTTPException(409, "Enable the staging channel, wait for acknowledgment, and reset between runs.")
            started = True
            sequence = (1,) * SHOWCASE_COUNT
        elif name == "prepare":
            if not started or not showcase_active or armed_revision is not None:
                raise HTTPException(409, "Approve the proposal and wait for acknowledgment before using the allowance.")
            armed_revision = policy.revision
            sequence = (1,)
        elif name == "blocking":
            if not showcase_active or armed_revision != policy.revision or blocking_checked:
                raise HTTPException(409, "Use the first allowance under the active revision before checking blocking.")
            # Reserve this check before dispatch so failed or overlapping clicks cannot add requests.
            blocking_checked = True
            sequence = (1, 2)
        elif name == "recovery":
            if active or blocked_revision is None or policy.revision <= blocked_revision or recovery_checked:
                raise HTTPException(409, "Wait for acknowledgment of the revocation before checking recovery.")
            recovery_checked = True
            sequence = (1,)
        else:
            raise HTTPException(404)
        try:
            async with asyncio.timeout(8), httpx.AsyncClient(
                timeout=2, trust_env=False, follow_redirects=False,
                limits=httpx.Limits(max_connections=1),
            ) as client:
                results = []
                for student in sequence:
                    result = await course_request(client, course, sessions[student - 1], student)
                    results.append(result)
                    if name in {"generate", "prepare"} and result["status"] != 204:
                        break
        except (TimeoutError, httpx.HTTPError):
            raise HTTPException(503, "The localhost course request failed or timed out.") from None
        expected = {"generate": [204] * SHOWCASE_COUNT, "prepare": [204], "blocking": [429, 204],
                    "recovery": [204]}[name]
        matched = [result["status"] for result in results] == expected
        if name == "blocking" and matched:
            blocked_revision = policy.revision
        return {"requests": results, "matched": matched, "revision": policy.revision}

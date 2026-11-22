"""Authenticated application telemetry and local operator controls."""

import asyncio
import re
import sqlite3
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from backend.security.demo_access import boundary, demo_security, is_remote_operator_console

from . import northfield_monitor, protection, showcase, staging_policy
from .policy_wire import APP as POLICY_APP
from .detection import RULE_NAMES, SEVERITIES, STATUSES, alert_snapshot, set_status
from .schemas import APP_PATTERN, UUID_PATTERN
from .rules import SHOWCASE_APP
from .store import database_path, snapshot

router = APIRouter()
VIEWERS = 8
INTERVAL = 2
_viewers = 0


def is_local(connection):
    context = boundary(connection)
    return context.local and demo_security.can_view(connection)


def can_stream(ws):
    if is_remote_operator_console(ws):
        return demo_security.can_view(ws)
    return (is_local(ws) and demo_security.session(ws) is not None
            and ws.headers.get("origin") == boundary(ws).origin)


def filters_for(connection):
    params = connection.query_params
    app = params.get("app", "")
    allowed = {"severity": SEVERITIES, "rule": RULE_NAMES, "status": STATUSES}
    filters = {name: params.get(name) for name, options in allowed.items() if params.get(name) in options}
    if re.fullmatch(APP_PATTERN, app):
        filters["app"] = app
    return filters


@router.get("/dashboard/applications", response_class=HTMLResponse)
async def applications_page(request: Request):
    remote_view = is_remote_operator_console(request) and demo_security.can_view(request)
    if not (is_local(request) or remote_view):
        raise HTTPException(404)
    from backend.security_ui import security_panel

    folder = Path(__file__).parent
    page = (folder / "dashboard.html").read_text(encoding="utf-8")
    if remote_view:
        page = page.replace("<!-- operator session -->",
                            "<p>Remote monitoring is read-only. Policy changes use the local console.</p>")
        page = page.replace("<body>", '<body class="remote-monitor">', 1)
    legacy = request.query_params.get("view") == "legacy"
    app = request.query_params.get("app")
    if not legacy and (app == SHOWCASE_APP or not app):
        page = page.replace("<!-- northfield monitor -->", (folder / "northfield_monitor.html").read_text(encoding="utf-8"))
        page = page.replace("/* northfield monitor */", (folder / "northfield_monitor.js").read_text(encoding="utf-8"))
    elif legacy and showcase.config():
        page = page.replace('id="showcase-defense"', 'id="showcase-defense" data-enabled="true"')
    if not legacy:
        from backend.console import wrap_existing
        page = wrap_existing(request, "applications", page)
    else:
        page = page.replace("<!-- overview link -->", '<a href="/dashboard">Sentinel Overview</a>')
    return HTMLResponse(page.replace("<!-- operator session -->", security_panel() if legacy else ""),
                        headers={"Cache-Control": "no-store", "Content-Security-Policy": "frame-ancestors 'self'"})


def require_operator(request):
    if not is_local(request):
        raise HTTPException(404)
    if demo_security.session(request) is None:
        raise HTTPException(401, "Operator sign-in required")
    if request.headers.get("x-admin-token"):
        raise HTTPException(403, "Use the operator session")
    demo_security.require_control(request, local_only=True, dashboard=True)


@router.post("/api/telemetry/showcase/{action}")
async def showcase_action(request: Request, action: str):
    require_operator(request)
    settings = showcase.config()
    if not settings or action not in {"generate", "prepare", "blocking", "recovery", "reset"}:
        raise HTTPException(404)
    try:
        return await showcase.action(action, settings)
    except sqlite3.OperationalError:
        raise HTTPException(503, "Showcase policy storage unavailable") from None


@router.post("/api/telemetry/alerts/{alert_id}/{action}")
async def change_alert(request: Request, alert_id: str, action: str):
    require_operator(request)
    actions = {"acknowledge": "acknowledged", "resolve": "resolved", "false-positive": "false_positive"}
    if action not in actions or not re.fullmatch(UUID_PATTERN, alert_id):
        raise HTTPException(404)
    try:
        changed = await asyncio.to_thread(set_status, database_path(), alert_id, actions[action])
    except sqlite3.OperationalError:
        raise HTTPException(503, "Detection storage unavailable") from None
    if not changed:
        raise HTTPException(409, "Alert is unavailable or already closed")
    return {"status": actions[action]}


@router.post("/api/telemetry/protection/mode/{action}")
async def protection_mode(request: Request, action: str):
    require_operator(request)
    if action not in {"alert-only", "shadow", "emergency-disable", "reset-emergency"}:
        raise HTTPException(404)
    try:
        changed = await asyncio.to_thread(protection.change_mode, database_path(), action, "operator")
    except sqlite3.OperationalError:
        raise HTTPException(503, "Protection storage unavailable") from None
    if not changed:
        raise HTTPException(409, "Mode unavailable. Check the emergency switch.")
    return {"status": "updated"}


@router.post("/api/telemetry/protection/decisions/{decision_id}/dismiss")
async def dismiss_proposal(request: Request, decision_id: str):
    require_operator(request)
    if not re.fullmatch(UUID_PATTERN, decision_id):
        raise HTTPException(404)
    try:
        changed = await asyncio.to_thread(protection.dismiss, database_path(), decision_id, "operator")
    except sqlite3.OperationalError:
        raise HTTPException(503, "Protection storage unavailable") from None
    if not changed:
        raise HTTPException(409, "Proposal is expired, dismissed, or unavailable")
    return {"status": "dismissed"}


@router.post("/api/telemetry/staging-policy/{app_id}/{action}")
@router.post("/api/telemetry/staging-policy/{app_id}/{action}/{target}")
async def staging_command(request: Request, app_id: str, action: str, target: str | None = None):
    require_operator(request)
    if (not re.fullmatch(POLICY_APP, app_id)
            or action not in {"enable", "enable-production", "disable", "approve", "revoke", "refresh"}
            or (action in {"approve", "revoke"}) != bool(target)
            or (target and not re.fullmatch(UUID_PATTERN, target))):
        raise HTTPException(404)
    try:
        updated = await asyncio.to_thread(staging_policy.command, database_path(), app_id, action, target)
    except sqlite3.OperationalError:
        raise HTTPException(503, "Policy storage unavailable") from None
    if not updated:
        raise HTTPException(409, "Policy action is unavailable or evidence is no longer eligible")
    return {"revision": updated.revision}


@router.websocket("/ws/monitored-applications")
async def applications_stream(ws: WebSocket):
    global _viewers
    if not can_stream(ws) or _viewers >= VIEWERS:
        await ws.close(code=1008)
        return
    _viewers += 1
    try:
        await ws.accept()
        filters = filters_for(ws)
        northfield = ws.query_params.get("view") == "northfield"
        while can_stream(ws):
            try:
                now = int(time.time())
                apps = await asyncio.to_thread(snapshot, database_path(), now)
                message = {"type": "snapshot", "applications": apps}
            except sqlite3.OperationalError:
                message = {"type": "unavailable"}
            if message["type"] == "snapshot":
                try:
                    message["detection"] = await asyncio.to_thread(alert_snapshot, database_path(), filters)
                except sqlite3.OperationalError:
                    message["detection"] = {"health": {"status": "unavailable"}, "alerts": []}
                try:
                    message["protection"] = await asyncio.to_thread(protection.snapshot, database_path())
                except sqlite3.OperationalError:
                    message["protection"] = {"health": {"status": "unavailable"}}
                try:
                    message["staging"] = await asyncio.to_thread(staging_policy.snapshot, database_path())
                except sqlite3.OperationalError:
                    message["staging"] = {"channels": [], "pending": [], "audit": [], "unavailable": True}
                if northfield:
                    try:
                        traffic = await asyncio.to_thread(northfield_monitor.snapshot, database_path(), now)
                    except sqlite3.OperationalError:
                        traffic = None
                    message["northfield"] = traffic
                    if traffic:
                        for app in apps:
                            if app["id"] == SHOWCASE_APP:
                                app["student_observations"] = traffic["students"]
                                break
            async with asyncio.timeout(2):
                await ws.send_json(message)
            try:
                async with asyncio.timeout(INTERVAL):
                    await ws.receive_text()
            except TimeoutError:
                continue
            # This is a send-only subscription; client messages end the session.
            await ws.close(code=1008)
            return
        await ws.close(code=1008)
    except (WebSocketDisconnect, TimeoutError, OSError):
        pass
    finally:
        _viewers -= 1

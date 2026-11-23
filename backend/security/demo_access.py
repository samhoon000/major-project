"""Authentication and exposure boundary for the existing remote demonstration.

Run Uvicorn with --no-proxy-headers: this module must see the actual socket peer.
Cloudflare headers only describe a visitor when that peer is a configured proxy.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from html import escape
from urllib.parse import urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from starlette.requests import HTTPConnection
from starlette.responses import HTMLResponse, JSONResponse, Response, RedirectResponse
from starlette.middleware.cors import CORSMiddleware

COOKIE = "sentinel_admin"
SESSION_SECONDS = 1800
router = APIRouter()
OPERATOR_PAGES = frozenset({
    "/dashboard", "/dashboard/applications", "/attack-lab", "/dashboard/network",
    "/dashboard/chat", "/dashboard/chat-security", "/dashboard/settings",
})


def remote_enabled():
    return (not browser_verification_enabled()
            and os.getenv("HTTP_FLOOD_REMOTE_ENABLED", "false").lower() in ("1", "true", "yes"))


def dashboard_remote_enabled():
    return (operator_console_enabled() or remote_enabled()
            or os.getenv("DASHBOARD_REMOTE_ENABLED", "false").lower() in ("1", "true", "yes"))


def operator_console_enabled():
    return (os.getenv("SENTINEL_REMOTE_CONSOLE", "false").lower() in ("1", "true", "yes")
            or os.getenv("DASHBOARD_REMOTE_ENABLED", "false").lower() in ("1", "true", "yes"))


def browser_verification_enabled():
    return os.getenv("HTTP_POLICY_REMOTE_VERIFY_ENABLED", "false").lower() in ("1", "true", "yes")


def is_remote_operator_console(connection):
    return operator_console_enabled() and boundary(connection).tunnel


def public_origin():
    raw = os.getenv("CLOUDFLARE_PUBLIC_HOSTNAME", "").strip()
    # Quick hosts are learned from our existing cloudflared manager, never
    # from request headers, query parameters, or an arbitrary trycloudflare site.
    from backend.network.tunnel import tunnel_manager
    if tunnel_manager.mode == "quick":
        raw = tunnel_manager.public_hostname or ""
    elif not raw:
        raw = tunnel_manager.public_hostname or ""
    if not raw:
        return None
    try:
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443)
                or parsed.username or parsed.password or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or "*" in parsed.hostname):
            return None
        return "https://" + parsed.hostname.lower()
    except ValueError:
        return None


class DemoCORSMiddleware(CORSMiddleware):
    def is_allowed_origin(self, origin):
        return bool(public_origin() and origin == public_origin()) or super().is_allowed_origin(origin)


def _ip(value):
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def _origin(value):
    try:
        p = urlsplit(value)
        if not p.hostname or p.username or p.password or p.path not in ("", "/") or p.query or p.fragment:
            return None
        port = p.port
        host = "["+p.hostname+"]" if ":" in p.hostname else p.hostname.lower()
        suffix = "" if port is None or (p.scheme,port) in (("https",443),("http",80)) else f":{port}"
        return f"{p.scheme}://{host}{suffix}"
    except (ValueError, TypeError):
        return None


@dataclass(frozen=True)
class Boundary:
    local: bool
    tunnel: bool
    source: str
    origin: str | None


def boundary(connection: HTTPConnection):
    peer = _ip(connection.client.host if connection.client else None)
    trusted = {_ip("127.0.0.1"), _ip("::1")}
    trusted.update(filter(None, (_ip(x.strip()) for x in os.getenv("TRUSTED_PROXIES", "").split(","))))
    headers = connection.headers
    host_origin = _origin("https://" + headers.get("host", ""))
    local_host = _ip(urlsplit(host_origin).hostname) if host_origin else None
    local_name = urlsplit(host_origin).hostname if host_origin else ""
    forwarded = any(headers.get(key) for key in
                    ("cf-connecting-ip", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded"))
    local = bool(peer and peer.is_loopback and not forwarded and
                 (local_name == "localhost" or local_host and local_host.is_loopback))
    visitor = _ip(headers.get("cf-connecting-ip"))
    expected = public_origin()
    tunnel = bool(peer in trusted and visitor and expected and host_origin == expected
                  and headers.get("x-forwarded-proto", "").lower() == "https")
    scheme = "https" if connection.scope.get("scheme") in ("https", "wss") else "http"
    return Boundary(local, tunnel, str(visitor if tunnel else peer or "unknown"),
                    expected if tunnel else _origin(scheme+"://"+headers.get("host", "")))


class DemoSecurity:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.sessions = OrderedDict()
        self.failures = OrderedDict()
        self.global_failures = deque(maxlen=120)
        self.lock = threading.RLock()

    def _fingerprint(self):
        return hashlib.sha256(os.getenv("ADMIN_TOKEN", "").encode()).hexdigest()

    def check_token(self, connection, candidate):
        source = boundary(connection).source
        now = self.clock()
        with self.lock:
            while self.global_failures and now-self.global_failures[0] >= 60:
                self.global_failures.popleft()
            recent = self.failures.get(source, deque(maxlen=8))
            while recent and now-recent[0] >= 60:
                recent.popleft()
            if len(recent) >= 8 or len(self.global_failures) >= 120:
                raise HTTPException(429, "Too many authentication attempts; retry in 60 seconds",
                                    headers={"Retry-After":"60"})
            expected = os.getenv("ADMIN_TOKEN", "")
            valid = bool(expected and isinstance(candidate,str) and len(candidate) <= 256
                         and secrets.compare_digest(expected.encode(), candidate.encode()))
            if not valid:
                recent.append(now)
                self.failures[source] = recent
                self.failures.move_to_end(source)
                while len(self.failures) > 1024:
                    self.failures.popitem(last=False)
                self.global_failures.append(now)
                raise HTTPException(403, "Administrator authentication failed")
            self.failures.pop(source, None)

    def session(self, connection):
        value = connection.cookies.get(COOKIE, "")
        if not value or len(value) > 128:
            return None
        key = hashlib.sha256(value.encode()).hexdigest()
        with self.lock:
            record = self.sessions.get(key)
            if not record:
                return None
            if record["expires"] <= self.clock() or record["fingerprint"] != self._fingerprint():
                self.sessions.pop(key, None)
                return None
            context = boundary(connection)
            if not context.local and not (context.tunnel and dashboard_remote_enabled() and record["remote"]):
                return None
            return record

    def check_origin(self, connection, required=False):
        context = boundary(connection)
        origin = connection.headers.get("origin")
        if not origin and not required:
            return
        if not origin or _origin(origin) != context.origin:
            raise HTTPException(403, "Same-origin request required")

    def require_control(self, connection, local_only=False, *, dashboard=False):
        context = boundary(connection)
        allow_remote = dashboard_remote_enabled() if dashboard else remote_enabled()
        if not context.local and not (not local_only and context.tunnel and allow_remote):
            raise HTTPException(403, "Use localhost or the explicitly enabled HTTPS tunnel")
        self.check_origin(connection, required=not context.local)
        header = connection.headers.get("x-admin-token")
        if header:
            if is_remote_operator_console(connection):
                raise HTTPException(403, "Use the operator session")
            self.check_token(connection, header)
            return
        session = self.session(connection)
        if not session:
            raise HTTPException(403, "Administrator authentication required")
        self.check_origin(connection, required=True)
        csrf = connection.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(csrf.encode(), session["csrf"].encode()):
            raise HTTPException(403, "CSRF validation failed")

    def can_view(self, connection):
        context = boundary(connection)
        if context.local:
            origin = connection.headers.get("origin")
            if not origin:
                return True
            normalized = _origin(origin)
            name = urlsplit(normalized).hostname if normalized else None
            address = _ip(name)
            return bool(normalized and normalized.startswith(("http://","https://")) and
                        (name == "localhost" or address and address.is_loopback))
        if not (context.tunnel and dashboard_remote_enabled()):
            return False
        origin = connection.headers.get("origin")
        if connection.scope["type"] == "websocket" and not origin:
            return False
        if origin and _origin(origin) != context.origin:
            return False
        return self.session(connection) is not None

    def login(self, connection, token):
        context = boundary(connection)
        if not context.local and not (context.tunnel and dashboard_remote_enabled()):
            raise HTTPException(403, "Remote administration is not enabled for this HTTPS tunnel")
        if is_remote_operator_console(connection) and not 16 <= len(os.getenv("ADMIN_TOKEN", "")) <= 256:
            raise HTTPException(503, "Remote operator sign-in requires a configured administrator token")
        self.check_origin(connection, required=True)
        self.check_token(connection, token)
        value = secrets.token_urlsafe(32)
        record = dict(csrf=secrets.token_urlsafe(32), expires=self.clock()+SESSION_SECONDS,
                      remote=not context.local, fingerprint=self._fingerprint())
        with self.lock:
            for key in list(self.sessions):
                if self.sessions[key]["expires"] <= self.clock():
                    self.sessions.pop(key)
            previous = connection.cookies.get(COOKIE)
            if previous:
                self.sessions.pop(hashlib.sha256(previous.encode()).hexdigest(), None)
            self.sessions[hashlib.sha256(value.encode()).hexdigest()] = record
            while len(self.sessions) > 128:
                self.sessions.popitem(last=False)
        response = JSONResponse({"authenticated":True,"expires_in":SESSION_SECONDS},
                                headers={"X-CSRF-Token":record["csrf"],"Cache-Control":"no-store"})
        response.set_cookie(COOKIE, value, max_age=SESSION_SECONDS, httponly=True,
                            secure=not context.local or connection.scope.get("scheme")=="https",
                            samesite="strict", path="/")
        return response


demo_security = DemoSecurity()


@router.post("/api/auth/login")
async def login(request: Request):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 4096:
            raise HTTPException(413, "Authentication request too large")
    try:
        payload = json.loads(body)
        token = payload.get("token") if isinstance(payload,dict) else None
    except (ValueError, UnicodeError):
        token = None
    return demo_security.login(request, token)


@router.get("/api/auth/session")
async def session_state(request: Request):
    record = demo_security.session(request)
    response = JSONResponse(dict(authenticated=bool(record), local=boundary(request).local,
        remote_console=is_remote_operator_console(request),
        remote_enabled=dashboard_remote_enabled(), expires_in=max(0,int(record["expires"]-demo_security.clock())) if record else 0),
        headers={"Cache-Control":"no-store"})
    if record:
        response.headers["X-CSRF-Token"] = record["csrf"]
    return response


@router.post("/api/auth/logout")
async def logout(request: Request):
    demo_security.require_control(request, dashboard=True)
    value = request.cookies.get(COOKIE, "")
    with demo_security.lock:
        demo_security.sessions.pop(hashlib.sha256(value.encode()).hexdigest(),None)
    response = JSONResponse({"authenticated":False},headers={"Cache-Control":"no-store"})
    response.delete_cookie(COOKIE,path="/",httponly=True,samesite="strict",secure=not boundary(request).local)
    return response


@router.get("/api/auth/ui.js")
async def auth_script():
    from pathlib import Path
    return Response((Path(__file__).resolve().parent.parent / "static" / "demo_auth.js").read_text(encoding="utf-8"),
                    media_type="text/javascript")


@router.get("/operator/sign-in", include_in_schema=False)
async def operator_sign_in(request: Request):
    from backend.security_ui import security_panel

    target = request.query_params.get("next", "/dashboard")
    if target.partition("?")[0] not in OPERATOR_PAGES:
        target = "/dashboard"
    if demo_security.session(request):
        return RedirectResponse(target, status_code=303, headers={"Cache-Control": "no-store"})
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel operator sign-in</title></head><body>
<main id="operator-sign-in" data-next="{escape(target, quote=True)}">
<h1>Sentinel operator sign-in</h1><p>Sign in to access the Sentinel dashboard.</p>
{security_panel()}<p><a href="/chat">Open Secure Chat</a></p></main>
<script>
function continueToConsole() {{
  if (window.SentinelAuth.authenticated) {{
    location.replace(document.getElementById('operator-sign-in').dataset.next);
  }}
}}
window.addEventListener('sentinel-auth-changed', continueToConsole);
window.SentinelAuth.ready.then(continueToConsole);
</script></body></html>"""
    return HTMLResponse(html, headers={"Cache-Control": "no-store", "Content-Security-Policy": "frame-ancestors 'none'"})


class DemoExposure:
    """Remote route allowlist and authenticated telemetry; local APIs stay compatible."""
    CONSOLE = {"/dashboard/network", "/dashboard/settings", "/dashboard/chat", "/dashboard/chat-security"}
    PUBLIC = CONSOLE | {"/attack-lab", "/dashboard", "/chat", "/api/auth/login", "/api/auth/session",
              "/api/auth/logout", "/api/auth/ui.js", "/api/attack-lab/http-flood/ui.js"}
    READ = {"/api/chat/state", "/api/network/state", "/api/attack-lab/status",
            "/api/attack-lab/http-flood/state", "/api/attack-lab/http-flood-target",
            "/api/network/quarantine", "/api/tunnel/state", "/api/tunnel/qr.svg"}
    CONTROL = {"/api/attack-lab/http-flood/"+x for x in ("start","stop","reset","unblock","monitor","authorize")}
    CHAT_AND_DASHBOARD = CONSOLE | {"/", "/chat", "/dashboard", "/dashboard/applications",
                          "/api/auth/login", "/api/auth/session",
                          "/api/auth/logout", "/api/auth/ui.js", "/api/chat/state", "/api/network/state",
                          "/api/tunnel/state", "/api/tunnel/qr.svg"}
    OPERATOR_PUBLIC = {"/", "/chat", "/operator/sign-in", "/api/auth/login",
                       "/api/auth/session", "/api/auth/logout", "/api/auth/ui.js",
                       "/api/tunnel/state", "/api/tunnel/qr.svg"}
    OPERATOR_READ = {"/api/network/state", "/api/chat/state", "/api/attack-lab/status",
                     "/api/attack-lab/http-flood/state", "/api/attack-lab/http-flood-target",
                     "/api/network/quarantine", "/api/attack-lab/verification",
                     "/api/attack-lab/verification/traffic"}
    BROWSER_VERIFICATION = {"/api/attack-lab/http-verification/" + command
                            for command in ("start", "request", "stop", "reset")}

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope,receive,send)
            return
        upstream_send = send
        connection = HTTPConnection(scope)
        remote_console = is_remote_operator_console(connection)
        async def private_send(message):
            if message["type"] == "http.response.start" and (remote_console or scope.get("path", "").startswith("/api/")):
                headers = [(key,value) for key,value in message.get("headers", []) if key.lower() != b"cache-control"]
                message = {**message,"headers":headers+[(b"cache-control",b"no-store")]}
            await upstream_send(message)
        send = private_send
        path = scope.get("path", "")
        if boundary(connection).local:
            await self.app(scope,receive,send)
            return
        if path.startswith("/api/admin/unblock/") and scope["method"] == "POST":
            await self.app(scope, receive, send)
            return
        response = None
        dashboard_only = dashboard_remote_enabled() and not remote_enabled()
        if remote_console and path in OPERATOR_PAGES:
            if not demo_security.can_view(connection):
                target = path + ("?" + connection.url.query if connection.url.query else "")
                response = RedirectResponse("/operator/sign-in?" + urlencode({"next": target}), status_code=303)
            elif connection.query_params.get("view") == "legacy":
                response = RedirectResponse(path, status_code=307)
        elif remote_console and path == "/":
            response = RedirectResponse("/dashboard", status_code=307)
        elif remote_console and path in self.BROWSER_VERIFICATION:
            if scope["method"] != "POST" or not browser_verification_enabled():
                response = JSONResponse({"detail": "Not found"}, status_code=404)
        elif remote_console and path not in self.OPERATOR_PUBLIC | self.OPERATOR_READ | (self.CONTROL if remote_enabled() else set()):
            response = JSONResponse({"detail": "Not found"}, status_code=404)
        elif not remote_console and dashboard_only and path not in self.CHAT_AND_DASHBOARD:
            response = JSONResponse({"detail": "Not found"}, status_code=404)
        elif path == "/":
            response = RedirectResponse("/chat" if dashboard_only else "/attack-lab", status_code=307)
        elif path in ("/api/tunnel/state", "/api/tunnel/qr.svg") and not demo_security.can_view(connection):
            # Public chat joining metadata contains no LAN IP, runtime state or logs.
            origin = public_origin()
            if not origin:
                response = JSONResponse({"detail":"Public hostname is not configured"},status_code=503)
            elif path.endswith(".svg"):
                from backend.network.qr_generator import generate_qr_svg
                response = Response(generate_qr_svg(origin+"/chat"),media_type="image/svg+xml")
            else:
                response = JSONResponse(dict(public_url=origin,active_joining_url=origin+"/chat",
                    local_ip=None,local_url=None,status="public_route",joining_mode="public_https",
                    readiness_note="Public hostname configured; reachability must be verified separately"))
        elif path in self.READ and not demo_security.can_view(connection):
            response = JSONResponse({"detail":"Authenticate to view sensitive telemetry"},status_code=401)
        elif not remote_console and path not in self.PUBLIC | self.READ | self.CONTROL:
            response = JSONResponse({"detail":"Not found"},status_code=404)
        if response:
            await response(scope,receive,send)
        else:
            await self.app(scope,receive,send)

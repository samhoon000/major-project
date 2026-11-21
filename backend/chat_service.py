"""Small in-memory WebSocket chat and security event service."""

from __future__ import annotations

import asyncio
import logging
import re
import time
import os
import uuid
from collections import defaultdict, deque
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi import HTTPException
from backend.security.blocking import blocking_manager
from backend.security.live_behavior_analyzer import BehaviorAnalyzer, BehaviorConfig
from backend.security.message_analyzer import message_analyzer
from backend.security.url_analyzer import url_analyzer
from backend.security.threat_engine import threat_engine
import ipaddress
from backend.security.demo_access import boundary, demo_security, public_origin

router = APIRouter()
logger = logging.getLogger(__name__)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl"}
SUSPICIOUS_WORDS = {"verify", "login", "account", "password", "urgent", "suspended", "payment"}
MAX_MESSAGE_LENGTH = 2000

DEFAULT_TRUSTED_PROXIES = {
    ipaddress.ip_address("127.0.0.1"),
    ipaddress.ip_address("::1"),
}


def get_trusted_proxies() -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Returns the set of explicitly trusted reverse proxy IP addresses."""
    proxies = set(DEFAULT_TRUSTED_PROXIES)
    extra = os.getenv("TRUSTED_PROXIES", "").strip()
    if extra:
        for item in extra.split(","):
            val = item.strip()
            if val:
                try:
                    proxies.add(ipaddress.ip_address(val))
                except ValueError:
                    logger.warning("[SECURITY] Invalid IP in TRUSTED_PROXIES: %s", val)
    return proxies


def resolve_client_ip(
    peer_host: str | None,
    headers: Any,
    trusted_proxies: set[ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None,
) -> str:
    """Resolves the real client IP address, only honoring forwarded headers from trusted proxies.

    Prevents IP spoofing: if the immediate connection does not originate from an explicitly
    trusted proxy (e.g. cloudflared loopback 127.0.0.1 / ::1), all forwarded headers
    (CF-Connecting-IP, X-Forwarded-For) are ignored and the immediate peer host is used.
    Validates IP address syntax using Python's ipaddress module.
    """
    if not peer_host:
        return "unknown"

    raw_peer = peer_host.strip()
    try:
        peer_addr = ipaddress.ip_address(raw_peer)
    except ValueError:
        return raw_peer

    trusted = trusted_proxies if trusted_proxies is not None else get_trusted_proxies()

    # Direct connection from untrusted source (e.g. direct LAN client):
    # Forwarded headers MUST NOT be trusted.
    if peer_addr not in trusted:
        return str(peer_addr)

    # From trusted proxy: check CF-Connecting-IP first, then X-Forwarded-For
    cf_ip = None
    xff = None
    if hasattr(headers, "get"):
        cf_ip = headers.get("cf-connecting-ip") or headers.get("CF-Connecting-IP")
        xff = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")

    if cf_ip and str(cf_ip).strip():
        cand = str(cf_ip).strip()
        try:
            return str(ipaddress.ip_address(cand))
        except ValueError:
            logger.warning("[SECURITY] Invalid IP syntax in CF-Connecting-IP: %s", cand)

    if xff and str(xff).strip():
        parts = [p.strip() for p in str(xff).split(",") if p.strip()]
        if parts:
            try:
                return str(ipaddress.ip_address(parts[0]))
            except ValueError:
                logger.warning("[SECURITY] Invalid IP syntax in X-Forwarded-For: %s", parts[0])

    return str(peer_addr)


def is_origin_allowed(origin: str | None, request_host: str | None = None) -> bool:
    """Validates the Origin header before accepting a WebSocket connection.

    Protects against Cross-Site WebSocket Hijacking (CSWSH).
    Permits localhost, local LAN hostnames, configured Cloudflare custom domains,
    and active Cloudflare tunnels (including trycloudflare.com subdomains).
    Rejects untrusted third-party origins before ws.accept().

    Policy for missing Origin headers:
    All compliant web browsers automatically attach an Origin header on WebSocket handshakes.
    Non-browser tools (e.g. test clients, CLI monitoring) omit the header.
    Missing Origin is allowed for non-browser programmatic clients by default,
    or can be strictly enforced by setting ALLOW_MISSING_ORIGIN=false.
    """
    if origin is None or not str(origin).strip():
        allow_missing = os.getenv("ALLOW_MISSING_ORIGIN", "true").lower() in ("true", "1", "yes")
        return allow_missing

    origin_str = str(origin).strip()
    try:
        parsed = urlparse(origin_str)
    except Exception:
        return False

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False

    req_hostname = None
    if request_host:
        clean_req = str(request_host).strip().lower()
        for prefix in ("https://", "http://"):
            if clean_req.startswith(prefix):
                clean_req = clean_req[len(prefix):]
        req_hostname = clean_req.rstrip("/").split(":")[0].strip() or None

    # 1. Localhost and loopback
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True

    # 2. Configured Cloudflare public hostname (from env var)
    raw_public = os.getenv("CLOUDFLARE_PUBLIC_HOSTNAME", "").strip().lower()
    for prefix in ("https://", "http://"):
        if raw_public.startswith(prefix):
            raw_public = raw_public[len(prefix):]
    raw_public = raw_public.rstrip("/").split(":")[0].strip()
    if raw_public and hostname == raw_public:
        return True

    # 3. Dynamic tunnel manager public hostname
    try:
        from backend.network.tunnel import tunnel_manager
        tm_host = getattr(tunnel_manager, "public_hostname", None)
        if tm_host and isinstance(tm_host, str):
            tm_clean = tm_host.strip().lower()
            for prefix in ("https://", "http://"):
                if tm_clean.startswith(prefix):
                    tm_clean = tm_clean[len(prefix):]
            tm_clean = tm_clean.rstrip("/").split(":")[0].strip()
            if tm_clean and hostname == tm_clean:
                return True
    except Exception:
        pass

    # 4. Cloudflare Quick Tunnels (*.trycloudflare.com)
    if hostname == "trycloudflare.com" or hostname.endswith(".trycloudflare.com"):
        if req_hostname:
            if hostname == req_hostname or req_hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                return True
            return False
        return True

    # 5. Strict same-origin match against request host
    if req_hostname and hostname == req_hostname:
        return True

    # 6. Active server LAN IP
    try:
        from backend.network.tunnel import get_lan_ipv4
        lan_ip = get_lan_ipv4()
        if lan_ip and hostname == lan_ip.lower():
            return True
    except Exception:
        pass

    # 7. Any private LAN IPv4 (RFC 1918)
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private:
            return True
    except ValueError:
        pass

    # 8. Explicit ALLOWED_ORIGINS list
    extra_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
    if extra_origins:
        for item in extra_origins.split(","):
            clean_item = item.strip().lower()
            if not clean_item:
                continue
            if clean_item.startswith("http://") or clean_item.startswith("https://"):
                try:
                    p = urlparse(clean_item)
                    if p.hostname and hostname == p.hostname.lower():
                        return True
                except Exception:
                    pass
            elif hostname == clean_item:
                return True

    return False


class ChatState:
    def __init__(self) -> None:
        self.clients: dict[str, WebSocket] = {}
        self.client_ips: dict[str, str] = {}
        self.client_endpoints: dict[str, tuple[str, int, str, int, str]] = {}
        self.blocked: set[str] = set()
        self.block_reasons: dict[str, str] = {}
        self.recent: deque[dict[str, Any]] = deque(maxlen=200)
        self.events: deque[dict[str, Any]] = deque(maxlen=500)
        self.sent: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self.lock = asyncio.Lock()

    @staticmethod
    def _flow_matches_endpoint(flow: dict[str, Any], endpoint: tuple[str, int, str, int, str] | None) -> bool:
        if not endpoint or str(flow.get("protocol", "")).upper() != "TCP":
            return False
        client_ip, client_port, server_ip, server_port, session_id = endpoint
        packet_session = flow.get("chat_session_id")
        if packet_session is not None and packet_session != session_id:
            return False
        source = (flow.get("source_ip"), flow.get("source_port"))
        destination = (flow.get("destination_ip"), flow.get("destination_port"))
        client = (client_ip, client_port)
        server = (server_ip, server_port)
        return (source == client and destination == server) or (source == server and destination == client)

    def flow_matches_client(self, flow: dict[str, Any], username: str) -> bool:
        return self._flow_matches_endpoint(flow, self.client_endpoints.get(username))

    def resolve_flow_session(self, flow: dict[str, Any]) -> tuple[str, str] | None:
        matches = [(username, endpoint[4]) for username, endpoint in self.client_endpoints.copy().items()
                   if self._flow_matches_endpoint(flow, endpoint)]
        return matches[0] if len(matches) == 1 else None

    async def event(self, kind: str, data: dict[str, Any]) -> None:
        item = {"type": kind, "timestamp": time.time(), **data}
        self.events.append(item)
        await self.broadcast_dashboard(item)

    async def broadcast_dashboard(self, item: dict[str, Any]) -> None:
        for ws in tuple(dashboard_clients):
            try:
                if not demo_security.can_view(ws):
                    await ws.close(code=1008)
                    dashboard_clients.discard(ws)
                    continue
                await ws.send_json(item)
            except Exception:
                dashboard_clients.discard(ws)

    def dashboard_roster(self) -> dict[str, Any]:
        blocked_client_ips = {name: record["ip"] for name in self.blocked
                              if (record := blocking_manager.get_block_info(name)) and record["ip"]}
        return {"users": sorted(self.clients), "blocked": sorted(self.blocked),
                "client_ips": dict(self.client_ips), "block_reasons": dict(self.block_reasons),
                "blocked_client_ips": blocked_client_ips}

    def blocked_username(self, username: str) -> str | None:
        key = username.casefold()
        return next((name for name in self.blocked if name.casefold() == key), None)

    def chat_block_message(self, username: str, client_ip: str | None) -> str | None:
        if blocking_manager.is_ip_blocked(client_ip):
            return "Your IP address has been blocked. You cannot join Sentinel AI Chat from this address."
        if self.blocked_username(username) is not None or blocking_manager.is_user_blocked(username):
            return "This username has been blocked from Sentinel AI Chat."
        return None

    async def roster(self) -> None:
        payload = {"type": "users", "users": sorted(self.clients), "blocked": sorted(self.blocked)}
        for ws in list(self.clients.values()):
            try:
                await ws.send_json(payload)
            except Exception:
                pass
        await self.broadcast_dashboard({"type": "users", **self.dashboard_roster()})


state = ChatState()
dashboard_clients: set[WebSocket] = set()
behavior_analyzer = BehaviorAnalyzer(BehaviorConfig(
    warning_messages_30s=int(os.getenv("BULK_WARNING_THRESHOLD", "12")),
    block_messages_30s=int(os.getenv("BULK_BLOCK_THRESHOLD", "24")),
))


def inspect_message(text: str) -> dict[str, Any]:
    urls = URL_RE.findall(text)
    url_findings = []
    for raw in urls:
        parsed = urlparse(raw.rstrip(".,!?);]"))
        host = (parsed.hostname or "").lower()
        indicators = []
        if parsed.scheme != "https":
            indicators.append("unencrypted HTTP")
        if host in SHORTENERS:
            indicators.append("URL shortener")
        if any(word in (host + parsed.path).lower() for word in SUSPICIOUS_WORDS):
            indicators.append("credential or urgency wording")
        try:
            import ipaddress
            ipaddress.ip_address(host)
            indicators.append("IP address used as host")
        except ValueError:
            pass
        url_findings.append({"url": raw, "host": host, "indicators": indicators, "risk": min(1.0, len(indicators) * 0.32)})

    letters = [char for char in text if char.isalpha()]
    uppercase_ratio = (sum(char.isupper() for char in letters) / len(letters)) if letters else 0.0
    content_risk = min(1.0, (0.25 if uppercase_ratio > 0.65 else 0) + (0.2 if "!!!" in text else 0) + (0.15 if any(w in text.lower() for w in SUSPICIOUS_WORDS) else 0))
    suspicious_url = any(item["risk"] >= 0.6 for item in url_findings)
    return {"urls": url_findings, "content_risk": round(content_risk, 3), "url_risk": max((item["risk"] for item in url_findings), default=0.0), "suspicious_url": suspicious_url}


def behavior_risk(sender: str, recipient: str, text: str) -> tuple[float, dict[str, Any]]:
    details = behavior_analyzer.record(sender, recipient, text)
    threshold = behavior_analyzer.config.block_messages_30s
    risk = min(1.0, details["messages_last_30_seconds"] / max(1, threshold))
    return risk, details


CHAT_HTML = r"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Secure Chat</title><style>
body{font:16px system-ui;margin:0;background:#f2f5f8;color:#17212b}.shell{max-width:760px;margin:5vh auto;padding:20px;background:white;border:1px solid #dbe3ea;border-radius:14px}h1{margin:0 0 16px}input,button{font:inherit;padding:10px;border:1px solid #cbd5df;border-radius:8px}button{background:#126b65;color:white;border:0;cursor:pointer}.row{display:flex;gap:8px;margin:8px 0}.row input{flex:1}#feed{height:50vh;overflow:auto;border:1px solid #e1e7ed;border-radius:10px;padding:10px}.msg{padding:8px 4px;border-bottom:1px solid #eef1f4}.warn{color:#a23c15}.muted{color:#667582;font-size:.9em}</style></head><body><main class="shell"><h1>Local Secure Chat</h1><p class="muted">Messages are sent through this server and inspected before delivery.</p><div class="row"><input id="name" placeholder="Username"><button id="join">Join</button></div><div id="status" class="muted">Not connected</div><div id="feed"></div><div class="row"><input id="to" placeholder="Recipient username"><input id="message" placeholder="Message"><button id="send">Send</button></div><script>
let ws;const $=id=>document.getElementById(id);function line(text,cls=''){const d=document.createElement('div');d.className='msg '+cls;d.textContent=text;$('feed').append(d);$('feed').scrollTop=$('feed').scrollHeight}function connect(){const name=$('name').value.trim();if(!/^[a-zA-Z0-9_-]{2,24}$/.test(name)){ $('status').textContent='Use 2–24 letters, numbers, _ or -.';return}ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/chat/${encodeURIComponent(name)}`);ws.onopen=()=>{$('status').textContent=`Connected as ${name}`};ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.type==='message')line(`${x.sender} → ${x.recipient}: ${x.text}${x.security?.urls?.length?' [URL inspected]':''}`,x.security?.suspicious_url?'warn':'');else if(x.type==='warning')line(x.message,'warn');else if(x.type==='blocked'){$('status').textContent='This account is blocked.';line(x.message,'warn');ws.close()}else if(x.type==='users')$('status').textContent=`Online: ${x.users.join(', ')||'no one'}${x.blocked.includes(name)?' · blocked':''}`};ws.onclose=()=>{if($('status').textContent!=='This account is blocked.')$('status').textContent='Disconnected'}}$('join').onclick=connect;$('send').onclick=()=>{if(ws?.readyState===WebSocket.OPEN)ws.send(JSON.stringify({recipient:$('to').value.trim(),text:$('message').value}));$('message').value=''};$('message').onkeydown=e=>{if(e.key==='Enter')$('send').click()};
</script></main></body></html>"""


DASHBOARD_HTML = r"""<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Events</title><style>body{font:15px system-ui;margin:28px auto;max-width:1000px;padding:0 18px;background:#f2f5f8;color:#17212b}h1{margin-bottom:5px}.muted{color:#667582}#events{display:grid;gap:8px;margin-top:18px}.event{background:white;border:1px solid #dbe3ea;border-radius:10px;padding:12px}.alert{border-color:#e8a27f}.cards{display:flex;gap:10px;flex-wrap:wrap}.card{background:white;padding:12px 18px;border:1px solid #dbe3ea;border-radius:10px}</style></head><body><h1>Live Security Dashboard</h1><p class="muted">Live chat/security events. Network capture and GATv2 events appear only when connected to those real services.</p><div class="cards"><div class="card">Connected users: <b id="users">0</b></div><div class="card">Messages observed: <b id="messages">0</b></div><div class="card">Threat events: <b id="threats">0</b></div><div class="card">Blocked users: <b id="blocked">0</b></div></div><div id="events"></div><script>
const events=document.getElementById('events');let messages=0,threats=0;const ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/dashboard`);ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.type==='snapshot'){document.getElementById('users').textContent=x.users.length;document.getElementById('blocked').textContent=x.blocked.length;for(const item of x.events)show(item);return}if(x.type==='users'){document.getElementById('users').textContent=x.users.length;document.getElementById('blocked').textContent=x.blocked.length;return}show(x)};function show(x){if(x.type==='message')messages++;if(['threat','blocked','message_blocked'].includes(x.type))threats++;document.getElementById('messages').textContent=messages;document.getElementById('threats').textContent=threats;const d=document.createElement('div');d.className='event '+(['threat','blocked','message_blocked'].includes(x.type)?'alert':'');d.textContent=`${new Date(x.timestamp*1000).toLocaleTimeString()} · ${x.type} · ${x.sender||x.username||''} ${x.recipient?'→ '+x.recipient:''} ${x.message||x.text||''} ${x.security?.suspicious_url?'· suspicious URL':''} ${x.behavior?.messages_last_second>4?'· rapid messages':''}`;events.prepend(d);while(events.children.length>100)events.lastChild.remove()}
</script></body></html>"""


DASHBOARD_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#050706"><title>Security Admin // Live Network</title><style>
:root{color-scheme:dark;--bg:#050706;--panel:#0a100c;--panel2:#0d1510;--line:#23342a;--green:#7cff8a;--cyan:#54e6ff;--amber:#ffc857;--red:#ff3b4e;--text:#d7e8d9;--muted:#7b9880;--mono:"Cascadia Code","SFMono-Regular",Consolas,"Liberation Mono",monospace}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:13px var(--mono);background-image:linear-gradient(rgba(124,255,138,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(124,255,138,.025) 1px,transparent 1px);background-size:32px 32px}body:after{content:"";position:fixed;inset:0;pointer-events:none;z-index:5;background:repeating-linear-gradient(0deg,rgba(0,0,0,.08),rgba(0,0,0,.08) 1px,transparent 1px,transparent 3px);opacity:.32}.shell{max-width:1500px;margin:auto;padding:22px 24px 44px;position:relative;z-index:1}.top{display:flex;justify-content:space-between;align-items:center;gap:20px;border-bottom:1px solid var(--line);padding-bottom:16px}.brand{display:flex;align-items:center;gap:14px}.sigil{width:35px;height:35px;border:1px solid var(--green);display:grid;place-items:center;color:var(--green);text-shadow:0 0 9px #7cff8a66;font-size:18px}.eyebrow,.section-tag{color:var(--muted);font-size:10px;letter-spacing:.16em;text-transform:uppercase}.title{font-size:17px;letter-spacing:.07em;margin:2px 0}.subtitle{font-size:10px;color:var(--muted)}.top-right{display:flex;align-items:center;gap:18px}.live{color:var(--green);letter-spacing:.1em;font-size:11px}.live:before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;background:currentColor;margin-right:8px;box-shadow:0 0 9px currentColor;animation:blink 1.3s steps(2,start) infinite}.live.warn{color:var(--red)}.live.wait{color:var(--amber)}@keyframes blink{to{visibility:hidden}}a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}.nav{display:flex;gap:16px;font-size:10px}.banner{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:16px 0 12px;padding:14px 16px;background:#09120c;border:1px solid #285034;border-left:3px solid var(--green)}.banner.attack{background:#160b0e;border-color:#67232c;border-left-color:var(--red);box-shadow:inset 0 0 24px #ff3b4e0c}.banner.wait{border-color:#5b4a23;border-left-color:var(--amber)}.banner-main{display:flex;align-items:center;gap:12px}.banner-icon{color:var(--green);font-size:15px}.attack .banner-icon{color:var(--red)}.wait .banner-icon{color:var(--amber)}.banner-title{font-size:13px;letter-spacing:.12em}.banner-copy{color:var(--muted);font-size:11px;margin-top:4px}.banner-meta{font-size:10px;color:var(--muted);text-align:right}.grid{display:grid;gap:12px}.stats{grid-template-columns:repeat(6,minmax(0,1fr));margin:12px 0}.panel,.stat{background:linear-gradient(135deg,rgba(124,255,138,.018),transparent 42%),var(--panel);border:1px solid var(--line);position:relative}.panel{padding:14px;min-width:0}.panel:before,.stat:before{content:"";position:absolute;left:-1px;top:-1px;width:24px;border-top:1px solid var(--green);opacity:.6}.stat{padding:12px 14px;min-width:0}.stat-label{font-size:9px;color:var(--muted);letter-spacing:.12em;text-transform:uppercase}.stat-value{font-size:23px;color:var(--green);margin-top:7px;text-shadow:0 0 12px #7cff8a21;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.stat-value.cyan{color:var(--cyan)}.stat-value.amber{color:var(--amber)}.stat-note{font-size:9px;color:var(--muted);margin-top:4px}.main-grid{grid-template-columns:minmax(0,1.8fr) minmax(300px,1fr);align-items:stretch}.lower-grid{grid-template-columns:minmax(0,1.2fr) minmax(280px,.8fr)}.panel-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;border-bottom:1px solid var(--line);padding-bottom:10px;margin-bottom:12px}.panel-title{margin:0;font-size:12px;letter-spacing:.1em;font-weight:500}.panel-kicker{color:var(--muted);font-size:9px;margin-top:4px}.tag{border:1px solid var(--line);padding:4px 7px;color:var(--muted);font-size:9px;white-space:nowrap}.tag.ok{border-color:#31563a;color:var(--green)}.tag.bad{border-color:#67232c;color:var(--red)}.chart-wrap{height:260px;position:relative}.chart-wrap svg{width:100%;height:100%;display:block}.chart-foot{display:flex;justify-content:space-between;color:var(--muted);font-size:9px;margin-top:3px}.legend{display:flex;gap:14px;color:var(--muted);font-size:9px}.key{display:inline-block;width:12px;height:2px;background:var(--cyan);vertical-align:middle;margin-right:5px}.key.red{background:var(--red)}.readout{border-top:1px solid var(--line);padding-top:11px;margin-top:9px;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px 14px}.readout-item .label{color:var(--muted);font-size:9px;letter-spacing:.1em}.readout-item .value{color:var(--text);font-size:11px;margin-top:4px;overflow-wrap:anywhere}.prob-track{height:8px;background:#18231b;border:1px solid #25372a;position:relative;margin:12px 0 5px}.prob-fill{height:100%;width:0;background:var(--green);box-shadow:0 0 8px #7cff8a55;transition:width .25s}.prob-fill.attack{background:var(--red);box-shadow:0 0 8px #ff3b4e55}.prob-marker{position:absolute;top:-4px;height:14px;width:1px;background:var(--amber)}.prob-scale{display:flex;justify-content:space-between;color:var(--muted);font-size:9px}.prob-caption{display:flex;justify-content:space-between;margin-top:8px}.prob-caption strong{font-size:19px;color:var(--green);font-weight:400}.prob-caption strong.attack{color:var(--red)}.incident{border-top:1px solid var(--line);margin-top:13px;padding-top:11px}.incident-label{color:var(--red);font-size:9px;letter-spacing:.12em}.incident-title{margin:6px 0 10px;font-size:13px}.small{font-size:10px;color:var(--muted);line-height:1.65}.incident-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px 14px}.incident-grid .value{color:var(--text);font-size:10px;display:block;margin-top:3px;overflow-wrap:anywhere}.incident-empty{color:var(--muted);font-size:11px;line-height:1.6;padding:12px 0}.timeline{max-height:300px;overflow:auto}.timeline-row{display:grid;grid-template-columns:66px 12px 1fr;gap:7px;padding:8px 0;border-bottom:1px solid #18251c;font-size:10px}.timeline-time{color:var(--muted)}.timeline-dot{color:var(--red)}.timeline-row .desc{color:var(--text)}.timeline-row .sub{color:var(--muted);margin-top:3px;overflow-wrap:anywhere}.terminal{height:300px;overflow:auto;background:#060a07;padding:4px 10px}.term-row{padding:7px 0;border-bottom:1px solid #142019;display:grid;grid-template-columns:74px 80px 1fr;gap:8px;font-size:10px;line-height:1.5}.term-time{color:var(--muted)}.term-type{color:var(--cyan)}.term-type.attack{color:var(--red)}.term-text{color:#b5cbb8;overflow-wrap:anywhere}.topology{height:280px}.topology svg{width:100%;height:100%;display:block}.topology-empty{color:var(--muted);font-size:10px;padding:20px 0}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:10px;min-width:700px}th,td{text-align:left;padding:8px;border-bottom:1px solid #1b2920;white-space:nowrap}th{font-weight:400;color:var(--muted);font-size:9px;letter-spacing:.08em}td{color:#c5d8c8}.pill{color:var(--green)}.pill.attack{color:var(--red)}.pill.pending{color:var(--amber)}input,button{font:inherit;background:#080d09;color:var(--text);border:1px solid var(--line);padding:7px}button{cursor:pointer;color:var(--cyan)}button:hover{border-color:var(--cyan)}.user-table{min-width:740px}.user-actions{display:flex;gap:6px;align-items:center}.user-head{display:flex;justify-content:space-between;align-items:center}.token{max-width:180px}.footer{border-top:1px solid var(--line);margin-top:15px;padding-top:10px;color:var(--muted);font-size:9px;display:flex;justify-content:space-between;gap:14px}@media(max-width:1000px){.stats{grid-template-columns:repeat(3,minmax(0,1fr))}.main-grid{grid-template-columns:1fr}.lower-grid{grid-template-columns:1fr}}@media(max-width:600px){.shell{padding:14px 11px 30px}.top{align-items:flex-start}.top-right{align-items:flex-end;flex-direction:column;gap:9px}.nav{gap:10px}.title{font-size:14px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.banner{align-items:flex-start;flex-direction:column}.banner-meta{text-align:left}.chart-wrap{height:220px}.incident-grid{grid-template-columns:1fr 1fr}.footer{flex-direction:column}}
</style></head><body><main class="shell">
<header class="top"><div class="brand"><div class="sigil">⌁</div><div><div class="eyebrow">SENTINEL // NETWORK DEFENSE</div><h1 class="title">SECURITY ADMIN CONSOLE</h1><div class="subtitle">LIVE TELEMETRY / GATv2 INFERENCE / FLOW MONITOR</div></div></div><div class="top-right"><span class="live wait" id="liveIndicator">CONNECTING</span><nav class="nav"><a href="/attack-lab">ATTACK LAB</a><a href="/chat">SECURE CHAT</a></nav></div></header>
<section class="banner wait" id="warningBanner"><div class="banner-main"><span class="banner-icon" id="bannerIcon">◌</span><div><div class="banner-title" id="bannerTitle">INITIALIZING LIVE STATE</div><div class="banner-copy" id="bannerCopy">Waiting for network capture and model status.</div></div></div><div class="banner-meta" id="bannerMeta">LAST UPDATE: —</div></section>
<div class="grid stats"><div class="stat"><div class="stat-label">Packets / Sec</div><div class="stat-value cyan" id="pps">—</div><div class="stat-note">LIVE CAPTURE WINDOW</div></div><div class="stat"><div class="stat-label">Bytes / Sec</div><div class="stat-value cyan" id="bps">—</div><div class="stat-note">LIVE CAPTURE WINDOW</div></div><div class="stat"><div class="stat-label">Active Flows</div><div class="stat-value" id="active">—</div><div class="stat-note">OBSERVED BY FLOW TRACKER</div></div><div class="stat"><div class="stat-label">GATv2 Analyses</div><div class="stat-value" id="analyses">—</div><div class="stat-note">COMPLETED INFERENCES</div></div><div class="stat"><div class="stat-label">Anomalies</div><div class="stat-value" id="anomalies">—</div><div class="stat-note">GATv2 CHAT FLOW ANOMALIES</div></div><div class="stat"><div class="stat-label">Online Users</div><div class="stat-value" id="users">—</div><div class="stat-note">SECURE CHAT</div></div></div>
<div class="grid main-grid"><section class="panel"><div class="panel-head"><div><h2 class="panel-title">LIVE NETWORK ACTIVITY</h2><div class="panel-kicker">PACKETS PER SECOND // ROLLING 60 SECOND WINDOW</div></div><div class="legend"><span><i class="key"></i>CAPTURED TRAFFIC</span><span><i class="key red"></i>GATv2 CHAT FLOW ANOMALY</span></div></div><div class="chart-wrap"><svg id="activityGraph" viewBox="0 0 900 260" role="img" aria-label="Captured packet rate over the last 60 seconds"></svg></div><div class="chart-foot"><span>TIME →</span><span id="chartRange">LAST 60 SECONDS</span></div></section>
<section class="panel"><div class="panel-head"><div><h2 class="panel-title">GATv2 // MODEL INFERENCE</h2><div class="panel-kicker">EXISTING MODEL OUTPUT / SAVED CLASSIFICATION THRESHOLD</div></div><span class="tag" id="modelTag">MODEL —</span></div><div class="readout-item"><div class="label">LATEST PREDICTION</div><div class="value" id="latest">WAITING FOR ANALYSIS</div></div><div class="prob-track"><div class="prob-fill" id="probFill"></div><div class="prob-marker" id="probMarker"></div></div><div class="prob-scale"><span>0.00</span><span id="thresholdLabel">THRESHOLD —</span><span>1.00</span></div><div class="prob-caption"><span class="small">ANOMALY PROBABILITY</span><strong id="probability">—</strong></div><div class="incident" id="incidentPanel"><div class="incident-label">LATEST GATv2 CHAT FLOW ANOMALY</div><div class="incident-empty">No current GATv2 chat-flow alert.</div></div></section></div>
<div class="grid lower-grid" style="margin-top:12px"><section class="panel"><div class="panel-head"><div><h2 class="panel-title">OBSERVED NETWORK TOPOLOGY</h2><div class="panel-kicker">ENDPOINTS FROM REAL CAPTURED FLOWS</div></div><span class="tag" id="topologyCount">0 OBSERVED HOSTS</span></div><div class="topology" id="topology"></div></section><section class="panel"><div class="panel-head"><div><h2 class="panel-title">ATTACK HISTORY // TIMELINE</h2><div class="panel-kicker">CHAT MODERATION AND MATCHED GATv2 ALERTS</div></div><span class="tag" id="threats">0 EVENTS</span></div><div class="timeline" id="attackHistory"></div></section></div>
<div class="grid lower-grid" style="margin-top:12px"><section class="panel"><div class="panel-head"><div><h2 class="panel-title">SECURITY EVENTS // LIVE TERMINAL</h2><div class="panel-kicker">WEBSOCKET EVENT STREAM + API SNAPSHOT</div></div><span class="tag" id="eventCount">0 EVENTS</span></div><div class="terminal" id="events" aria-live="polite"></div></section><section class="panel"><div class="panel-head"><div><h2 class="panel-title">FLOW TELEMETRY</h2><div class="panel-kicker">LATEST CAPTURED FLOWS / NO SYNTHETIC HOSTS</div></div></div><div class="small" id="captureStatus">Waiting for API state.</div><div class="readout" style="margin-top:10px"><div class="readout-item"><div class="label">NEW FLOWS / 60 SEC</div><div class="value" id="newFlows">0</div></div><div class="readout-item"><div class="label">CURRENT CHAT BLOCKS</div><div class="value" id="blocked">0</div></div><div class="readout-item"><div class="label">MESSAGES / SEC</div><div class="value" id="mps">0</div></div><div class="readout-item"><div class="label">CHAT SECURITY EVENTS</div><div class="value" id="eventCount2">0</div></div></div></section></div>
<section class="panel" style="margin-top:12px"><div class="user-head"><div class="panel-head" style="border:0;margin:0;padding:0"><div><h2 class="panel-title">USER SECURITY</h2><div class="panel-kicker">CONNECTED CHAT USERS</div></div></div><div class="user-actions"><button id="refreshButton" type="button">REFRESH</button></div></div><div class="table-wrap" style="margin-top:12px"><table class="user-table"><thead><tr><th>USERNAME</th><th>CLIENT IP</th><th>STATUS</th><th>MESSAGES</th><th>MSG/SEC</th><th>RISK</th></tr></thead><tbody id="userRows"></tbody></table></div>
<details id="blockedUsers" hidden style="margin-top:12px"><summary>Manage blocked accounts</summary><div class="table-wrap"><table><thead><tr><th>USERNAME</th><th>BLOCKED IP</th><th>REASON</th><th>ACTION</th></tr></thead><tbody id="blockedUserRows"></tbody></table></div></details></section>
<section class="panel" style="margin-top:12px"><div class="panel-head"><div><h2 class="panel-title">LIVE NETWORK FLOWS</h2><div class="panel-kicker">CAPTURED FLOW TRACKER RECORDS AND GATv2 RESULTS</div></div><span class="tag" id="flowCount">0 FLOWS</span></div><div class="table-wrap"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>PACKETS</th><th>BYTES</th><th>GATv2</th><th>PROBABILITY</th></tr></thead><tbody id="flows"></tbody></table></div></section>
<section class="panel" style="margin-top:12px"><div class="panel-head"><div><h2 class="panel-title">ACCESS &amp; CONNECTIVITY // CLOUDFLARE TUNNEL &amp; LOCAL LAN</h2><div class="panel-kicker">MULTI-DEVICE JOINING URLS &amp; REAL-TIME QR CODE</div></div><span class="tag" id="tunnelStatusTag">TUNNEL —</span></div><div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap;padding:6px 0"><div style="background:#fff;padding:8px;border-radius:8px;display:inline-block;line-height:0" id="dashboardQrWrap"><img id="dashboardQrImg" src="/api/tunnel/qr.svg" width="120" height="120" alt="Join QR Code" style="display:block"></div><div style="flex:1;min-width:240px;display:grid;gap:8px"><div class="readout-item"><div class="label">ACTIVE JOINING URL (<span id="joiningModeLabel">LOCAL LAN</span>)</div><div class="value" style="font-size:13px;font-weight:600;color:var(--green)" id="activeJoiningUrl">—</div></div><div style="display:flex;gap:16px;flex-wrap:wrap"><div class="readout-item"><div class="label">PUBLIC CLOUDFLARE URL</div><div class="value" id="publicTunnelUrl">—</div></div><div class="readout-item"><div class="label">LOCAL WI-FI (LAN) URL</div><div class="value" id="localLanUrl">—</div></div></div><div class="small" id="tunnelDetailNote" style="color:var(--muted)">Checking tunnel status...</div></div></div></section>
<footer class="footer"><span id="interfaceInfo">CAPTURE INTERFACE: UNKNOWN</span><span>ATTACK CLASSIFICATION IS PROVIDED BY THE EXISTING GATv2 PIPELINE.</span><span id="updatedAt">UPDATED: —</span></footer></main>
<script>
const $=id=>document.getElementById(id);const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let events=[],networkState=null,chatState=null,samples=[],socket=null,dashboardRefreshBusy=false;const sampleLimit=31;function eventKey(x){return [x.timestamp,x.type,x.flow_id,x.message_id,x.username,x.source_ip].join('|')}function mergeEvents(incoming){const map=new Map(events.map(x=>[eventKey(x),x]));(incoming||[]).forEach(x=>{if(x&&x.type)map.set(eventKey(x),x)});events=Array.from(map.values()).sort((a,b)=>(a.timestamp||0)-(b.timestamp||0)).slice(-500)}function attackEvents(){return events.filter(x=>x.type==='gatv2_analysis'&&(x.gatv2_prediction==='ATTACK'||x.prediction==='ATTACK'))}function timeText(ts){return ts?new Date(ts*1000).toLocaleTimeString(): '—'}function formatRate(value){return Number(value||0).toLocaleString(undefined,{maximumFractionDigits:1})}function formatBytes(value){const n=Number(value||0);if(n<1024)return n.toFixed(0)+' B/s';if(n<1048576)return (n/1024).toFixed(1)+' KB/s';return (n/1048576).toFixed(2)+' MB/s'}function privateIp(ip){if(!ip)return false;if(ip==='::1'||ip.indexOf('fc')===0||ip.indexOf('fd')===0)return true;const m=ip.match(/^(\d{1,3})\.(\d{1,3})\./);if(!m)return false;const a=Number(m[1]),b=Number(m[2]);return a===10||a===127||(a===192&&b===168)||(a===172&&b>=16&&b<=31)}function getFlow(id){if(!networkState)return null;return (networkState.completed_flows||[]).find(f=>f.flow_id===id)||null}
function drawGraph(){const svg=$('activityGraph');const w=900,h=260,left=48,right=15,top=12,bottom=24,pw=w-left-right,ph=h-top-bottom,now=Date.now()/1000,cut=now-60;const points=samples.filter(p=>p.t>=cut);const max=Math.max(1,...points.map(p=>p.v));const ceil=Math.max(5,Math.ceil(max/5)*5);let out='';for(let i=0;i<=4;i++){const val=ceil*(4-i)/4,y=top+ph*i/4;out+='<line x1="'+left+'" y1="'+y+'" x2="'+(w-right)+'" y2="'+y+'" stroke="#1d2c22" stroke-width="1"/><text x="'+(left-8)+'" y="'+(y+3)+'" fill="#728d77" font-size="9" text-anchor="end">'+Math.round(val)+'</text>'}for(let i=0;i<=6;i++){const x=left+pw*i/6;out+='<line x1="'+x+'" y1="'+top+'" x2="'+x+'" y2="'+(top+ph)+'" stroke="#142019" stroke-width="1"/><text x="'+x+'" y="'+(h-5)+'" fill="#728d77" font-size="8" text-anchor="middle">'+(i===6?'NOW':Math.round((i-6)*10)+'s')+'</text>'}if(points.length){const coords=points.map(p=>({x:left+Math.max(0,Math.min(60,p.t-cut))/60*pw,y:top+ph-(Math.min(ceil,p.v)/ceil)*ph}));const line=coords.map(p=>p.x.toFixed(1)+','+p.y.toFixed(1)).join(' ');out+='<polyline points="'+line+'" fill="none" stroke="#54e6ff" stroke-width="2" vector-effect="non-scaling-stroke"/>';const first=coords[0],last=coords[coords.length-1];out+='<polygon points="'+first.x+','+(top+ph)+' '+line+' '+last.x+','+(top+ph)+'" fill="#54e6ff" opacity=".06"/>'}const attacks=attackEvents().filter(x=>chatState?.users?.includes(x.username)&&!chatState.blocked?.includes(x.username)&&x.timestamp>=cut&&x.timestamp<=now);attacks.forEach(a=>{const x=left+(a.timestamp-cut)/60*pw;out+='<line x1="'+x+'" y1="'+top+'" x2="'+x+'" y2="'+(top+ph)+'" stroke="#ff3b4e" stroke-width="1" stroke-dasharray="4 4" opacity=".9"><title>GATv2 CHAT FLOW ANOMALY · '+esc(timeText(a.timestamp))+' · '+esc(a.source_ip||'source unavailable')+'</title></line><path d="M '+(x-5)+' '+(top+ph+1)+' L '+(x+5)+' '+(top+ph+1)+' L '+x+' '+(top+ph-7)+' Z" fill="#ff3b4e"><title>GATv2 CHAT FLOW ANOMALY · '+esc(timeText(a.timestamp))+'</title></path>'});svg.innerHTML=out}
function currentAnalysis(n) {
  const analysis = n.latest_analysis;
  if (analysis?.gatv2_prediction === 'BENIGN') return analysis;
  return analysis && chatState?.users?.includes(analysis.username) &&
    !chatState.blocked?.includes(analysis.username) ? analysis : null;
}
function renderIncident(n){
  const analysis = currentAnalysis(n);
  const prediction = analysis?.gatv2_prediction;
  const probability = analysis?.gatv2_anomaly_probability;
  const threshold = analysis?.gatv2_threshold ?? n.gatv2_threshold;
  const flagged = prediction === 'ATTACK';
  const percentage = probability == null ? '—' : (probability * 100).toFixed(2) + '%';
  $('latest').textContent = flagged ? 'ANOMALY FLAGGED' : prediction || 'WAITING FOR ANALYSIS';
  $('latest').className = 'value' + (flagged ? ' pill attack' : '');
  $('probability').textContent = percentage;
  $('probability').className = flagged ? 'attack' : '';
  $('probFill').style.width = probability == null ? '0%' : percentage;
  $('probFill').className = 'prob-fill' + (flagged ? ' attack' : '');
  $('probMarker').style.display = threshold == null ? 'none' : 'block';
  $('probMarker').style.left = (Number(threshold || 0) * 100) + '%';
  $('thresholdLabel').textContent = threshold == null ? 'THRESHOLD —' : 'THRESHOLD ' + Number(threshold).toFixed(2);
  const available = n.gatv2 === 'available';
  $('modelTag').textContent = available ? 'MODEL ONLINE' : 'MODEL OFFLINE';
  $('modelTag').className = 'tag ' + (available ? 'ok' : 'bad');
  $('incidentPanel').innerHTML = flagged
    ? '<div class="incident-label">GATv2 CHAT FLOW ANOMALY</div><div class="incident-title">' + esc(analysis.username) +
      '</div><div class="small">' + esc(analysis.source_ip) + ':' + esc(analysis.source_port) +
      ' → ' + esc(analysis.destination_ip) + ':' + esc(analysis.destination_port) + ' · ' + percentage + '</div>'
    : '<div class="incident-empty">No current GATv2 chat-flow alert. Earlier results appear in the timeline.</div>';
}
function renderBanner(n){
  const banner = $('warningBanner');
  const indicator = $('liveIndicator');
  const blocked = new Set(chatState?.blocked || []);
  const online = (chatState?.users || []).some(username => !blocked.has(username));
  const analysis = currentAnalysis(n);
  const prediction = chatState?.users?.includes(analysis?.username) ? analysis.gatv2_prediction : null;
  let state = 'wait';
  let title = 'WAITING FOR CHAT USERS';
  let detail = 'Network activity remains visible. Chat alerts require a joined chat user.';
  let status = 'IDLE';
  if (online && !n.direct_chat_sessions) {
    title = 'CHAT MODERATION ACTIVE';
    detail = 'Relayed chat uses message and behavior checks. GATv2 alerts require a matching direct chat flow.';
    status = 'CHAT ACTIVE';
  } else if (online && prediction === 'ATTACK') {
    state = 'attack';
    title = 'GATv2 FLAGGED A CHAT FLOW';
    detail = 'The model flagged a captured flow attributed to a connected chat user.';
    status = 'ANOMALY FLAGGED';
  } else if (online && (n.capture !== 'running' || n.gatv2 !== 'available')) {
    title = 'CHAT PACKET ANALYSIS UNAVAILABLE';
    detail = n.capture_error || n.gatv2_error || 'Waiting for capture and model status.';
    status = 'CHECK STATUS';
  } else if (online && !prediction) {
    title = 'WAITING FOR DIRECT CHAT FLOW ANALYSIS';
    detail = 'Chat moderation is active. GATv2 reports a result after a matching flow is captured and analyzed.';
    status = 'CHAT ACTIVE';
  } else if (online) {
    state = '';
    title = 'LATEST CHAT FLOW CLASSIFIED BENIGN';
    detail = 'Earlier alerts and chat moderation actions appear in the timeline.';
    status = 'LIVE / MONITORING';
  }
  banner.className = 'banner' + (state ? ' ' + state : '');
  $('bannerIcon').textContent = state === 'attack' ? '⚠' : state ? '◌' : '●';
  $('bannerTitle').textContent = title;
  $('bannerCopy').textContent = detail;
  $('bannerMeta').textContent = 'LAST UPDATE: ' + new Date().toLocaleTimeString();
  indicator.className = 'live' + (state === 'attack' ? ' warn' : state ? ' wait' : '');
  indicator.textContent = status;
}
function renderTimeline(){
  const kinds = {
    gatv2_analysis: 'GATv2 CHAT FLOW ANOMALY',
    blocked: 'CHAT USER BLOCKED',
    message_blocked: 'CHAT MESSAGE BLOCKED',
  };
  const incidents = events.filter(event =>
    event.type === 'blocked' || event.type === 'message_blocked' ||
    (event.type === 'gatv2_analysis' && event.username &&
      (event.gatv2_prediction === 'ATTACK' || event.prediction === 'ATTACK'))
  ).reverse();
  $('threats').textContent = incidents.length + ' EVENTS';
  $('attackHistory').innerHTML = incidents.slice(0, 60).map(event => {
    const user = event.username || event.sender || '';
    const detail = event.type === 'gatv2_analysis'
      ? (Number(event.anomaly_probability) * 100).toFixed(2) + '% model score'
      : event.reason || event.threat?.reason || '';
    return '<div class="timeline-row"><div class="timeline-time">' + esc(timeText(event.timestamp)) +
      '</div><div class="timeline-dot">▲</div><div><div class="desc">' + kinds[event.type] +
      '</div><div class="sub">' + esc(user) + (detail ? ' · ' + esc(detail) : '') + '</div></div></div>';
  }).join('') || '<div class="incident-empty">No chat security events recorded.</div>';
}
function renderTerminal(){const recent=events.slice().reverse().slice(0,100);$('events').innerHTML=recent.map(x=>{const bad=(x.type==='gatv2_analysis'&&(x.gatv2_prediction==='ATTACK'||x.prediction==='ATTACK'));const detail=x.reason||x.gatv2_prediction||x.prediction||x.action||x.username||x.source_ip||'';const endpoints=x.source_ip?(x.source_ip+(x.source_port!=null?':'+x.source_port:'')+' → '+(x.destination_ip||'')+(x.destination_port!=null?':'+x.destination_port:'')):'';return '<div class="term-row"><span class="term-time">'+esc(timeText(x.timestamp))+'</span><span class="term-type'+(bad?' attack':'')+'">'+esc(x.type||'EVENT').toUpperCase()+'</span><span class="term-text">'+esc(endpoints||detail)+(endpoints&&detail?' · '+esc(detail):'')+'</span></div>'}).join('');$('eventCount').textContent=events.length+' EVENTS';$('eventCount2').textContent=events.length+' observed'}
function renderTopology(n){const flows=[...(n.active_flows||[]),...(n.completed_flows||[])].slice(-32),hosts=Array.from(new Set(flows.flatMap(f=>[f.source_ip,f.destination_ip]).filter(Boolean)));$('topologyCount').textContent=hosts.length+' OBSERVED HOSTS';if(!hosts.length){$('topology').innerHTML='<div class="topology-empty">No captured flow endpoints observed yet.</div>';return}const w=640,h=280,cx=w/2,cy=h/2,rad=Math.min(100,Math.max(42,hosts.length*9)),pos={};hosts.forEach((ip,i)=>{const angle=-Math.PI/2+2*Math.PI*i/hosts.length;pos[ip]={x:cx+Math.cos(angle)*rad,y:cy+Math.sin(angle)*rad}});let s='<svg viewBox="0 0 '+w+' '+h+'" role="img" aria-label="Observed network flow endpoints">';flows.forEach(f=>{if(!pos[f.source_ip]||!pos[f.destination_ip])return;const attacked=f.gatv2_prediction==='ATTACK'&&chatState?.users?.includes(f.username);const col=attacked?'#ff3b4e':'#54e6ff';s+='<line x1="'+pos[f.source_ip].x+'" y1="'+pos[f.source_ip].y+'" x2="'+pos[f.destination_ip].x+'" y2="'+pos[f.destination_ip].y+'" stroke="'+col+'" stroke-width="1" opacity=".52"><title>'+esc(f.source_ip)+' → '+esc(f.destination_ip)+' · '+esc(f.protocol||'')+' · '+esc(f.gatv2_prediction||f.gatv2_status||'pending')+'</title></line>'});hosts.forEach(ip=>{const p=pos[ip];s+='<circle cx="'+p.x+'" cy="'+p.y+'" r="18" fill="#0b150e" stroke="#7cff8a" stroke-width="1"/><text x="'+p.x+'" y="'+(p.y+3)+'" fill="#d7e8d9" text-anchor="middle" font-size="8">HOST '+(hosts.indexOf(ip)+1)+'</text><text x="'+p.x+'" y="'+(p.y+31)+'" fill="#8ba791" text-anchor="middle" font-size="9">'+esc(ip)+'</text>'});s+='</svg>';$('topology').innerHTML=s}
function renderFlows(n){const flows=[...(n.active_flows||[]),...(n.completed_flows||[])].slice(-100).reverse();$('flowCount').textContent=flows.length+' FLOWS';$('flows').innerHTML=flows.map(f=>{const pred=f.gatv2_prediction||f.gatv2_status||'PENDING',prob=f.gatv2_anomaly_probability;return '<tr><td>'+esc(timeText(f.last_seen||f.timestamp))+'</td><td>'+esc(f.source_ip||'')+':'+esc(f.source_port==null?'':f.source_port)+'</td><td>'+esc(f.destination_ip||'')+':'+esc(f.destination_port==null?'':f.destination_port)+'</td><td>'+esc(f.protocol||'')+'</td><td>'+esc(f.total_packets==null?'—':f.total_packets)+'</td><td>'+esc(f.total_bytes==null?'—':f.total_bytes)+'</td><td class="pill'+(pred==='ATTACK'?' attack':pred==='pending'?' pending':'')+'">'+esc(pred)+'</td><td>'+((prob==null||Number.isNaN(Number(prob)))?'—':(Number(prob)*100).toFixed(2)+'%')+'</td></tr>'}).join('')||'<tr><td colspan="8" class="small">No flows captured yet.</td></tr>'}
let rosterVersion = 0;
function renderUsers(c) {
  const blocked = new Set(c.blocked || []);
  const users = (c.users || []).filter(username => !blocked.has(username));
  $('users').textContent = users.length;
  $('blocked').textContent = blocked.size;
  $('userRows').innerHTML = users.map(username => {
    const behavior = c.behavior?.[username] || {};
    return '<tr><td>' + esc(username) + '</td><td>' + esc(c.client_ips?.[username] || 'UNKNOWN') +
      '</td><td><span class="pill">ONLINE</span></td><td>' + esc(behavior.total_messages || 0) +
      '</td><td>' + esc(behavior.messages_per_second || 0) + '</td><td>' + esc(behavior.risk || 'SAFE') + '</td></tr>';
  }).join('') || '<tr><td colspan="6" class="small">No chat users online.</td></tr>';
  $('blockedUsers').hidden = blocked.size === 0;
  $('blockedUserRows').innerHTML = Array.from(blocked, username =>
    '<tr><td>' + esc(username) + '</td><td>' + esc(c.blocked_client_ips?.[username] || '—') +
    '</td><td>' + esc(c.block_reasons?.[username] || '—') +
    '</td><td><button type="button" data-unblock="' + esc(username) + '">UNBLOCK</button></td></tr>'
  ).join('');
}
function addSample(n){const t=Date.now()/1000,v=Number(n.packets_per_second||0);if(!samples.length||t-samples[samples.length-1].t>=1.8)samples.push({t:t,v:v});samples=samples.filter(p=>p.t>=t-60).slice(-sampleLimit);drawGraph()}
async function unblock(user) {
  if (!window.SentinelAuth?.authenticated) {
    $('hf-token').focus();
    alert('Authenticate with your administrator token before unblocking a user.');
    return;
  }
  try {
    const response = await window.SentinelAuth.fetch('/api/admin/unblock/' + encodeURIComponent(user), {method: 'POST'});
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || 'Unblock failed');
    }
    await refresh();
  } catch (error) {
    alert(error.message);
  }
}
async function refresh(){if(window.SentinelAuth&&!window.SentinelAuth.canView)return;if(dashboardRefreshBusy)return;dashboardRefreshBusy=true;const rosterAtStart=rosterVersion;try{const rs=await Promise.all([fetch('/api/chat/state',{cache:'no-store'}),fetch('/api/network/state',{cache:'no-store'}),fetch('/api/tunnel/state',{cache:'no-store'}).catch(()=>({ok:false}))]);if(!rs[0].ok||!rs[1].ok)throw new Error('API returned '+rs[0].status+' / '+rs[1].status);const c=await rs[0].json(),n=await rs[1].json();let t=null;if(rs[2]&&rs[2].ok)try{t=await rs[2].json()}catch(_){}if(window.SentinelAuth&&!window.SentinelAuth.canView)return;chatState=rosterAtStart===rosterVersion?c:{...chatState,behavior:c.behavior};networkState=n;mergeEvents(c.events||[]);$('pps').textContent=formatRate(n.packets_per_second);$('bps').textContent=formatBytes(n.bytes_per_second);$('active').textContent=(n.active_flows||[]).length;$('analyses').textContent=n.gatv2_analyses==null?'—':n.gatv2_analyses;$('anomalies').textContent=n.gatv2_anomalies==null?'—':n.gatv2_anomalies;$('mps').textContent=formatRate(c.messages_per_second);$('newFlows').textContent=events.filter(x=>x.type==='flow_started'&&Date.now()/1000-(x.timestamp||0)<=60).length;$('captureStatus').textContent='Capture: '+(n.capture||'unknown')+' · GATv2: '+(n.gatv2||'unknown')+' · Pending inference flows: '+(n.pending_flows||0)+(n.capture_error?' · '+n.capture_error:'')+(n.gatv2_error?' · '+n.gatv2_error:'');if(t){$('tunnelStatusTag').textContent='TUNNEL '+(t.status||'DISABLED').toUpperCase();$('tunnelStatusTag').className='tag '+(t.status==='running'?'ok':t.status==='error'?'bad':'');$('activeJoiningUrl').textContent=t.active_joining_url||'—';$('joiningModeLabel').textContent=t.joining_mode==='public_https'?'PUBLIC HTTPS':'LOCAL WI-FI';$('publicTunnelUrl').textContent=t.public_url||(t.public_hostname?('CONFIGURED ('+t.public_hostname+' - WAITING)'):'DISABLED / NOT CONFIGURED');$('localLanUrl').textContent=t.local_url||'—';$('tunnelDetailNote').textContent=t.error?t.error:(t.status==='running'?'Cloudflare tunnel connected. Public access active.':'Local LAN access active. Phone and laptop attendees on same Wi-Fi can join.')}$('interfaceInfo').textContent='CAPTURE: '+(n.adapter_name?(n.adapter_name+' ['+(n.adapter_type||'NET')+'] '+(n.local_ip?'('+n.local_ip+') ':'')+'['+(n.selection_mode||'auto')+']'):(n.interface||'NOT SELECTED'))+(t&&t.joining_mode==='public_https'?' · PUBLIC: HTTPS (CLOUDFLARE)':' · LOCAL: LAN ONLY');$('updatedAt').textContent='UPDATED: '+new Date().toLocaleTimeString();renderBanner(n);renderIncident(n);renderTimeline();renderTerminal();renderTopology(n);renderFlows(n);renderUsers(chatState);addSample(n)}catch(e){$('captureStatus').textContent='API UNAVAILABLE: '+e.message;$('liveIndicator').className='live wait';$('liveIndicator').textContent='API ERROR';$('warningBanner').className='banner wait';$('bannerTitle').textContent='LIVE STATE UNAVAILABLE';$('bannerCopy').textContent='Network and security state could not be refreshed.'}finally{dashboardRefreshBusy=false}}
let dashboardRetries=0,dashboardTimer=null,dashboardDisposed=false;
function connectDashboard(){
 if(dashboardDisposed||(window.SentinelAuth&&!window.SentinelAuth.canView)||(socket&&socket.readyState<=1))return;
 socket=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/dashboard');
 socket.onopen=()=>{dashboardRetries=0;refresh();};
 socket.onmessage = event => {
  if (window.SentinelAuth && !window.SentinelAuth.canView) return;
  try {
   const update = JSON.parse(event.data);
   if (update.type === 'HTTP_FLOOD_TELEMETRY') return;
   if (update.type === 'snapshot' || update.type === 'users') {
    rosterVersion++;
    chatState = {...chatState, ...update};
    renderUsers(chatState);
    if (networkState) {
     renderBanner(networkState);
     renderIncident(networkState);
    }
    if (update.type === 'snapshot') {
     mergeEvents(update.events);
     renderTerminal();
    }
    return;
   }
   mergeEvents([update]);
   renderTerminal();
   renderTimeline();
   if (['gatv2_analysis', 'flow_started', 'flow_completed'].includes(update.type)) refresh();
  } catch (_) {}
 };
 socket.onclose=()=>{
  $('liveIndicator').className='live wait';$('liveIndicator').textContent='EVENT STREAM OFFLINE';
  if(dashboardDisposed||(window.SentinelAuth&&!window.SentinelAuth.canView)||dashboardRetries>=6)return;
  dashboardTimer=setTimeout(connectDashboard,Math.min(15000,1000*2**dashboardRetries++));
 };
 socket.onerror=()=>{$('liveIndicator').textContent='STREAM ERROR / RETRYING';};
}
$('blockedUserRows').addEventListener('click', event => {
  const button = event.target.closest('[data-unblock]');
  if (button) unblock(button.dataset.unblock);
});
$('refreshButton').addEventListener('click',()=>{dashboardRetries=0;connectDashboard();refresh();});
window.addEventListener('sentinel-auth-changed',()=>{
 clearTimeout(dashboardTimer);dashboardRetries=0;
 if(window.SentinelAuth.canView){connectDashboard();refresh();}
 else {if(socket)socket.close();events=[];networkState=null;chatState=null;rosterVersion++;renderUsers({});}
});
if(window.SentinelAuth)window.SentinelAuth.ready.then(()=>{connectDashboard();refresh();});
else {connectDashboard();refresh();}
const dashboardPoll=setInterval(refresh,2000);
window.addEventListener('pagehide',()=>{dashboardDisposed=true;clearInterval(dashboardPoll);clearTimeout(dashboardTimer);if(socket)socket.close();},{once:true});
</script></body></html>"""

CHAT_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>Sentinel // Secure Chat</title>
  <style>
    :root {
      --bg-dark: #0a0f14;
      --bg-card: #111922;
      --bg-panel: #16222c;
      --bg-panel-hover: #1e2e3b;
      --border: #233544;
      --border-focus: #0f766e;
      --text-main: #f1f5f9;
      --text-muted: #8295a5;
      --text-faint: #475b6c;
      --accent: #0f766e;
      --accent-hover: #115e59;
      --accent-glow: rgba(15, 118, 110, 0.35);
      --msg-out: #0d5f58;
      --msg-in: #1b2936;
      --warning: #f59e0b;
      --warning-bg: rgba(245, 158, 11, 0.12);
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.14);
      --safe: #10b981;
      --radius: 12px;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--font);
      background: var(--bg-dark);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }

    /* Top Bar */
    header.app-bar {
      height: 60px;
      background: var(--bg-card);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 20px;
      z-index: 10;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      color: var(--text-main);
    }

    .brand-icon {
      width: 34px;
      height: 34px;
      background: linear-gradient(135deg, #0f766e, #064e3b);
      border: 1px solid rgba(20, 184, 166, 0.4);
      border-radius: 9px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #5eead4;
      font-weight: 800;
      font-size: 17px;
      box-shadow: 0 0 12px var(--accent-glow);
    }

    .brand-title {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: 0.03em;
    }

    .brand-subtitle {
      font-size: 11px;
      color: var(--text-muted);
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .nav-link {
      color: var(--text-muted);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 6px;
      border: 1px solid var(--border);
      transition: all 0.15s ease;
    }
    .nav-link:hover {
      color: var(--text-main);
      border-color: var(--accent);
      background: rgba(15, 118, 110, 0.1);
    }

    .user-pill {
      display: none;
      align-items: center;
      gap: 8px;
      background: var(--bg-panel);
      padding: 5px 12px;
      border-radius: 99px;
      border: 1px solid var(--border);
      font-size: 13px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--safe);
      box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
    }

    /* Main Container */
    .app-layout {
      flex: 1;
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      height: calc(100vh - 60px);
      max-width: 1600px;
      width: 100%;
      margin: 0 auto;
      background: var(--bg-card);
      border-left: 1px solid var(--border);
      border-right: 1px solid var(--border);
      position: relative;
    }

    /* Left Sidebar: Contacts */
    aside.sidebar {
      background: var(--bg-card);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      height: 100%;
      overflow: hidden;
    }

    .sidebar-head {
      padding: 16px;
      border-bottom: 1px solid var(--border);
    }

    .search-box {
      width: 100%;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      outline: none;
      transition: border-color 0.15s ease;
    }
    .search-box:focus {
      border-color: var(--border-focus);
    }

    .roster-header {
      padding: 12px 16px 6px;
      font-size: 11px;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .user-list {
      flex: 1;
      overflow-y: auto;
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .user-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 12px;
      border-radius: 8px;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease;
      user-select: none;
    }
    .user-item:hover {
      background: var(--bg-panel);
    }
    .user-item.active {
      background: var(--bg-panel);
      border-color: var(--accent);
    }

    .avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 15px;
      color: white;
      background: #334155;
      flex-shrink: 0;
      text-transform: uppercase;
    }

    .user-meta {
      flex: 1;
      min-width: 0;
    }

    .user-meta-name {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-main);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .user-meta-status {
      font-size: 12px;
      color: var(--safe);
      display: flex;
      align-items: center;
      gap: 5px;
      margin-top: 2px;
    }

    .user-empty {
      padding: 32px 16px;
      text-align: center;
      color: var(--text-muted);
      font-size: 13px;
      line-height: 1.5;
    }

    /* Central Chat Section */
    section.chat-area {
      display: flex;
      flex-direction: column;
      height: 100%;
      background: var(--bg-dark);
      position: relative;
    }

    .chat-header {
      height: 64px;
      background: var(--bg-card);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 20px;
      z-index: 5;
    }

    .chat-header-user {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .mobile-back-btn {
      display: none;
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 20px;
      cursor: pointer;
      padding: 6px;
      margin-right: -4px;
    }

    .chat-header-info h2 {
      font-size: 15px;
      font-weight: 700;
      margin-bottom: 2px;
    }

    .chat-header-info p {
      font-size: 11px;
      color: var(--text-muted);
    }

    .security-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(15, 118, 110, 0.15);
      border: 1px solid rgba(20, 184, 166, 0.35);
      color: #2dd4bf;
      padding: 4px 10px;
      border-radius: 99px;
      font-size: 11px;
      font-weight: 600;
    }

    /* Message History / Feed */
    .chat-feed {
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      scroll-behavior: smooth;
    }

    .empty-state {
      margin: auto;
      text-align: center;
      max-width: 360px;
      color: var(--text-muted);
      padding: 20px;
    }
    .empty-state-icon {
      font-size: 40px;
      margin-bottom: 12px;
      opacity: 0.6;
    }
    .empty-state h3 {
      font-size: 16px;
      font-weight: 700;
      color: var(--text-main);
      margin-bottom: 6px;
    }
    .empty-state p {
      font-size: 13px;
      line-height: 1.5;
    }

    /* Message Bubbles */
    .msg-group {
      display: flex;
      flex-direction: column;
      max-width: 75%;
    }
    .msg-group.out {
      align-self: flex-end;
      align-items: flex-end;
    }
    .msg-group.in {
      align-self: flex-start;
      align-items: flex-start;
    }

    .msg-sender {
      font-size: 11px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 4px;
      padding: 0 4px;
    }

    .msg-bubble {
      padding: 10px 14px;
      border-radius: 14px;
      font-size: 14px;
      line-height: 1.45;
      overflow-wrap: anywhere;
      word-break: break-word;
      position: relative;
    }

    .msg-group.out .msg-bubble {
      background: var(--msg-out);
      color: #f8fafc;
      border-bottom-right-radius: 4px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }

    .msg-group.in .msg-bubble {
      background: var(--msg-in);
      color: var(--text-main);
      border: 1px solid var(--border);
      border-bottom-left-radius: 4px;
    }

    .msg-time {
      font-size: 10px;
      color: rgba(255, 255, 255, 0.65);
      margin-top: 4px;
      text-align: right;
    }
    .msg-group.in .msg-time {
      color: var(--text-muted);
    }

    /* Security Annotations Inside Bubble */
    .security-notice {
      margin-top: 6px;
      padding: 4px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .security-notice.warn {
      background: var(--warning-bg);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }
    .security-notice.info {
      background: rgba(15, 118, 110, 0.2);
      color: #5eead4;
      border: 1px solid rgba(20, 184, 166, 0.3);
    }

    /* System Center Alerts */
    .system-alert {
      align-self: center;
      max-width: 90%;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      padding: 8px 16px;
      border-radius: 99px;
      font-size: 12px;
      color: var(--text-muted);
      text-align: center;
    }
    .system-alert.warn {
      background: var(--warning-bg);
      border-color: rgba(245, 158, 11, 0.4);
      color: #fcd34d;
    }
    .system-alert.danger {
      background: var(--danger-bg);
      border-color: rgba(239, 68, 68, 0.4);
      color: #fca5a5;
    }

    /* Message Input Box */
    .chat-composer {
      padding: 14px 20px;
      background: var(--bg-card);
      border-top: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .composer-inner {
      display: flex;
      align-items: center;
      gap: 10px;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 4px 8px 4px 14px;
      transition: border-color 0.15s ease;
    }
    .composer-inner:focus-within {
      border-color: var(--border-focus);
    }

    .chat-input {
      flex: 1;
      background: none;
      border: none;
      color: var(--text-main);
      font-size: 14px;
      font-family: inherit;
      outline: none;
      max-height: 100px;
      padding: 8px 0;
    }
    .chat-input::placeholder {
      color: var(--text-faint);
    }

    .send-btn {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: var(--accent);
      border: none;
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.15s ease;
      flex-shrink: 0;
    }
    .send-btn:hover:not(:disabled) {
      background: var(--accent-hover);
      box-shadow: 0 0 10px var(--accent-glow);
    }
    .send-btn:disabled {
      opacity: 0.35;
      cursor: not-allowed;
      background: var(--bg-panel-hover);
      color: var(--text-faint);
    }

    .composer-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11px;
      color: var(--text-faint);
      padding: 0 4px;
    }

    /* Modal / Onboarding Overlay */
    .onboarding-overlay {
      position: fixed;
      inset: 0;
      background: rgba(5, 10, 15, 0.85);
      backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      padding: 16px;
    }

    .onboarding-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 18px;
      width: 100%;
      max-width: 440px;
      padding: 32px 28px;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.6);
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
    }

    .onboarding-badge {
      width: 58px;
      height: 58px;
      background: linear-gradient(135deg, #0f766e, #064e3b);
      border: 1px solid rgba(20, 184, 166, 0.5);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #5eead4;
      font-size: 28px;
      margin-bottom: 20px;
      box-shadow: 0 0 24px var(--accent-glow);
    }

    .onboarding-card h1 {
      font-size: 22px;
      font-weight: 700;
      margin-bottom: 8px;
    }

    .onboarding-card p {
      font-size: 13px;
      color: var(--text-muted);
      line-height: 1.5;
      margin-bottom: 24px;
    }

    .onboarding-form {
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }

    .input-group {
      text-align: left;
    }

    .input-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 6px;
      display: block;
    }

    .onboarding-input {
      width: 100%;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 12px 14px;
      border-radius: 10px;
      font-size: 15px;
      font-family: inherit;
      outline: none;
      transition: border-color 0.15s ease;
    }
    .onboarding-input:focus {
      border-color: var(--border-focus);
    }

    .input-hint {
      font-size: 11px;
      color: var(--text-faint);
      margin-top: 5px;
    }

    .btn-primary {
      background: var(--accent);
      color: white;
      border: none;
      padding: 13px;
      border-radius: 10px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      margin-top: 6px;
    }
    .btn-primary:hover {
      background: var(--accent-hover);
      box-shadow: 0 0 16px var(--accent-glow);
    }

    .onboarding-err {
      color: var(--danger);
      font-size: 12px;
      margin-top: 4px;
      display: none;
    }

    /* QR Join Box */
    .qr-join-box {
      display: flex;
      align-items: center;
      gap: 14px;
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      margin-bottom: 16px;
      width: 100%;
      text-align: left;
      box-sizing: border-box;
    }
    .qr-code-frame {
      background: #ffffff;
      padding: 5px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.3);
    }
    .qr-code-frame img {
      display: block;
      width: 120px;
      height: 120px;
    }
    .qr-info {
      display: flex;
      flex-direction: column;
      gap: 5px;
      min-width: 0;
      flex: 1;
    }
    .access-badge {
      display: inline-block;
      align-self: flex-start;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.08em;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
    }
    .access-badge.public {
      background: rgba(16, 185, 129, 0.15);
      color: var(--safe);
      border: 1px solid rgba(16, 185, 129, 0.4);
    }
    .access-badge.lan {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.4);
    }
    .access-url-text {
      font-size: 12px;
      font-family: monospace;
      color: var(--text-main);
      word-break: break-all;
      font-weight: 600;
    }
    .access-help {
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.3;
    }
    .btn-copy-url {
      align-self: flex-start;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 11px;
      cursor: pointer;
      margin-top: 2px;
      transition: all 0.15s ease;
    }
    .btn-copy-url:hover {
      background: var(--accent);
      color: #ffffff;
      border-color: var(--accent);
    }
    .nav-btn {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 6px 12px;
      border-radius: 8px;
      font-size: 12px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
      transition: all 0.15s ease;
    }
    .nav-btn:hover {
      border-color: var(--accent);
      color: #5eead4;
    }

    /* Blocked Banner Modal */
    .blocked-dialog {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.85);
      backdrop-filter: blur(8px);
      z-index: 200;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }
    .blocked-card {
      background: #181012;
      border: 1px solid #7f1d1d;
      border-radius: 16px;
      max-width: 400px;
      padding: 28px;
      text-align: center;
      box-shadow: 0 20px 50px rgba(239, 68, 68, 0.25);
    }
    .blocked-icon {
      font-size: 40px;
      color: var(--danger);
      margin-bottom: 14px;
    }
    .blocked-card h2 {
      font-size: 18px;
      color: #fca5a5;
      margin-bottom: 10px;
    }
    .blocked-card p {
      font-size: 13px;
      color: #cbd5e1;
      line-height: 1.5;
      margin-bottom: 20px;
    }

    /* Mobile Responsive */
    @media (max-width: 768px) {
      .app-layout {
        grid-template-columns: 1fr;
        height: calc(100vh - 60px);
        border: none;
      }

      aside.sidebar {
        width: 100%;
        display: flex;
      }
      aside.sidebar.hidden-mobile {
        display: none;
      }

      section.chat-area {
        display: none;
      }
      section.chat-area.active-mobile {
        display: flex;
      }

      .mobile-back-btn {
        display: block;
      }

      .brand-subtitle, .security-badge {
        display: none;
      }
    }
  </style>
</head>
<body>

  <!-- Application Header -->
  <header class="app-bar">
    <div class="brand">
      <div class="brand-icon">⌁</div>
      <div>
        <div class="brand-title">Sentinel Secure Chat</div>
        <div class="brand-subtitle">AI Threat-Mediated Messaging</div>
      </div>
    </div>
    <div class="header-actions">
      <button type="button" class="nav-btn" id="openInviteBtn" title="Show Joining QR Code &amp; URL">⌁ Invite / QR</button>
      <a href="/dashboard" class="nav-link" target="_blank" rel="noopener">SOC Dashboard</a>
      <div id="userPill" class="user-pill">
        <span class="status-dot"></span>
        <span id="currentUsername" style="font-weight: 600;"></span>
      </div>
    </div>
  </header>

  <!-- Main Multi-Column Chat Layout -->
  <main class="app-layout">
    
    <!-- Left Sidebar: Online Directory -->
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-head">
        <input type="text" id="userSearch" class="search-box" placeholder="Filter online users..." aria-label="Search users">
      </div>
      <div class="roster-header">
        <span>Available Recipients</span>
        <span id="onlineCount">0 online</span>
      </div>
      <div class="user-list" id="userList" role="listbox" aria-label="Online users">
        <div class="user-empty">Connect with a handle to view active participants.</div>
      </div>
    </aside>

    <!-- Central Chat Area -->
    <section class="chat-area" id="chatArea">
      
      <!-- Chat Header -->
      <div class="chat-header">
        <div class="chat-header-user">
          <button id="backBtn" class="mobile-back-btn" title="Back to user list" aria-label="Back">←</button>
          <div id="headerAvatar" class="avatar" style="display: none;">?</div>
          <div class="chat-header-info">
            <h2 id="recipientTitle">Select a recipient</h2>
            <p id="recipientStatus">Choose an online user from the sidebar to chat</p>
          </div>
        </div>
        <div class="security-badge" title="Messages are evaluated by the Threat Engine in real-time">
          <span>🛡</span> Threat Engine Active
        </div>
      </div>

      <!-- Feed -->
      <div class="chat-feed" id="chatFeed" aria-live="polite">
        <div class="empty-state" id="feedEmptyState">
          <div class="empty-state-icon">💬</div>
          <h3>Encrypted & Monitored Channel</h3>
          <p>Select a participant on the left to begin exchanging messages. Every transmission is checked for phishing links, content urgency, and flooding.</p>
        </div>
      </div>

      <!-- Composer -->
      <div class="chat-composer">
        <div class="composer-inner">
          <input type="text" id="msgInput" class="chat-input" placeholder="Select an online recipient first..." maxlength="2000" disabled aria-label="Message content">
          <button id="sendBtn" class="send-btn" disabled title="Send Message" aria-label="Send">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <line x1="22" y1="2" x2="11" y2="13"></line>
              <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
            </svg>
          </button>
        </div>
        <div class="composer-footer">
          <span id="statusHint">Choose an online recipient to begin.</span>
          <span id="charCount">0 / 2000</span>
        </div>
      </div>

    </section>
  </main>

  <!-- Onboarding Modal -->
  <div class="onboarding-overlay" id="onboardingModal">
    <div class="onboarding-card">
      <div class="onboarding-badge">⌁</div>
      <h1>Sentinel Secure Chat</h1>
      <p>Connect to the multi-user secure chat network. All messages pass through the Threat Engine to prevent malicious URLs, text attacks, and flooding.</p>
      
      <div class="qr-join-box" id="onboardingQrBox">
        <div class="qr-code-frame">
          <img id="onboardingQrImg" src="/api/tunnel/qr.svg" width="120" height="120" alt="Join QR Code">
        </div>
        <div class="qr-info">
          <div class="access-badge lan" id="onboardingAccessBadge">LOCAL WI-FI ONLY (HTTP)</div>
          <div class="access-url-text" id="onboardingUrlText">Loading join URL...</div>
          <div class="access-help">Scan with mobile camera or share link.</div>
          <button type="button" class="btn-copy-url" id="onboardingCopyBtn" onclick="copyJoinUrl('onboardingUrlText', 'onboardingCopyBtn')">Copy Link</button>
        </div>
      </div>

      <form class="onboarding-form" id="joinForm" onsubmit="event.preventDefault(); connect();">
        <div class="input-group">
          <label for="usernameInput" class="input-label">Choose your handle</label>
          <input type="text" id="usernameInput" class="onboarding-input" placeholder="e.g. alex, auditor, mobile_1" maxlength="24" autocomplete="off" required>
          <div class="input-hint">2–24 characters: letters, numbers, underscores (_), or hyphens (-).</div>
          <div class="onboarding-err" id="joinErr"></div>
        </div>
        <button type="submit" class="btn-primary" id="joinBtn">Join Secure Chat</button>
      </form>
    </div>
  </div>

  <!-- Invite / QR Code Dialog -->
  <div class="onboarding-overlay" id="inviteModal" style="display:none;">
    <div class="onboarding-card">
      <div class="onboarding-badge">⌁</div>
      <h2>Invite Participants</h2>
      <p>Scan this QR code with any mobile device or copy the URL to join from another laptop or phone.</p>
      
      <div class="qr-join-box">
        <div class="qr-code-frame">
          <img id="inviteQrImg" src="/api/tunnel/qr.svg" width="120" height="120" alt="Join QR Code">
        </div>
        <div class="qr-info">
          <div class="access-badge lan" id="inviteAccessBadge">LOCAL WI-FI ONLY (HTTP)</div>
          <div class="access-url-text" id="inviteUrlText">Loading join URL...</div>
          <div class="access-help">Scan with mobile camera or open in any web browser.</div>
          <button type="button" class="btn-copy-url" id="inviteCopyBtn" onclick="copyJoinUrl('inviteUrlText', 'inviteCopyBtn')">Copy Link</button>
        </div>
      </div>
      <button type="button" class="btn-primary" id="closeInviteBtn" style="margin-top:12px;background:var(--bg-panel);border:1px solid var(--border);">Close</button>
    </div>
  </div>

  <!-- Blocked Account Dialog -->
  <div class="blocked-dialog" id="blockedModal">
    <div class="blocked-card">
      <div class="blocked-icon">🚫</div>
      <h2>Account Suspended</h2>
      <p id="blockedReason">Your account has been temporarily blocked due to suspicious activity detected by the Security Threat Engine.</p>
      <button class="btn-primary" onclick="location.reload()" style="background:#7f1d1d;">Reload Application</button>
    </div>
  </div>

  <script>
    (() => {
      'use strict';

      let ws = null;
      let myName = '';
      let activeRecipient = '';
      let onlineUsers = [];
      const messagesByPeer = new Map(); // peerName -> array of message objects

      // DOM Elements
      const $ = id => document.getElementById(id);
      const onboardingModal = $('onboardingModal');
      const usernameInput = $('usernameInput');
      const joinBtn = $('joinBtn');
      const joinErr = $('joinErr');
      const userList = $('userList');
      const userSearch = $('userSearch');
      const onlineCount = $('onlineCount');
      const chatFeed = $('chatFeed');
      const feedEmptyState = $('feedEmptyState');
      const msgInput = $('msgInput');
      const sendBtn = $('sendBtn');
      const charCount = $('charCount');
      const statusHint = $('statusHint');
      const recipientTitle = $('recipientTitle');
      const recipientStatus = $('recipientStatus');
      const headerAvatar = $('headerAvatar');
      const userPill = $('userPill');
      const currentUsername = $('currentUsername');
      const blockedModal = $('blockedModal');
      const blockedReason = $('blockedReason');
      const sidebar = $('sidebar');
      const chatArea = $('chatArea');
      const backBtn = $('backBtn');

      // Helper: deterministic avatar color
      function getAvatarColor(name) {
        let hash = 0;
        for (let i = 0; i < name.length; i++) {
          hash = name.charCodeAt(i) + ((hash << 5) - hash);
        }
        const hue = Math.abs(hash % 360);
        return `hsl(${hue}, 55%, 32%)`;
      }

      function getInitials(name) {
        if (!name) return '?';
        return name.slice(0, 2).toUpperCase();
      }

      // XSS-Safe DOM creation for messages
      function createMessageElement(msg, isSelf) {
        const group = document.createElement('div');
        group.className = 'msg-group ' + (isSelf ? 'out' : 'in');

        const senderLabel = document.createElement('div');
        senderLabel.className = 'msg-sender';
        senderLabel.textContent = isSelf ? 'You' : msg.sender;
        group.appendChild(senderLabel);

        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';

        const body = document.createElement('div');
        body.className = 'msg-body';
        body.textContent = msg.text; // Text content strictly prevents XSS
        bubble.appendChild(body);

        // Genuine backend security indicators
        if (msg.security && msg.security.suspicious_url) {
          const secNotice = document.createElement('div');
          secNotice.className = 'security-notice warn';
          secNotice.textContent = '⚠ Suspicious URL Flagged by Threat Engine';
          bubble.appendChild(secNotice);
        } else if (msg.security && msg.security.urls && msg.security.urls.length > 0) {
          const secNotice = document.createElement('div');
          secNotice.className = 'security-notice info';
          secNotice.textContent = `ℹ ${msg.security.urls.length} URL(s) Inspected & Verified`;
          bubble.appendChild(secNotice);
        }

        const time = document.createElement('div');
        time.className = 'msg-time';
        const dateObj = msg.timestamp ? new Date(msg.timestamp * 1000) : new Date();
        time.textContent = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        bubble.appendChild(time);

        group.appendChild(bubble);
        return group;
      }

      function appendSystemAlert(text, type = 'info') {
        const alert = document.createElement('div');
        alert.className = 'system-alert ' + type;
        alert.textContent = text;
        chatFeed.appendChild(alert);
        chatFeed.scrollTop = chatFeed.scrollHeight;
      }

      // Select conversation partner
      window.selectRecipient = function(user) {
        activeRecipient = user;
        recipientTitle.textContent = user;
        recipientStatus.textContent = 'Active now · Direct Secure Channel';
        headerAvatar.style.display = 'flex';
        headerAvatar.textContent = getInitials(user);
        headerAvatar.style.backgroundColor = getAvatarColor(user);

        msgInput.disabled = false;
        msgInput.placeholder = `Message ${user}... (Enter to send)`;
        statusHint.textContent = `Press Enter to send, Shift+Enter for newline.`;
        validateComposer();
        msgInput.focus();

        // Render conversation history with this peer
        renderFeed();

        // Mobile responsiveness: switch view to chat area
        if (window.innerWidth <= 768) {
          sidebar.classList.add('hidden-mobile');
          chatArea.classList.add('active-mobile');
        }

        updateRosterUI();
      };

      function renderFeed() {
        chatFeed.innerHTML = '';
        if (!activeRecipient) {
          chatFeed.appendChild(feedEmptyState);
          feedEmptyState.style.display = 'block';
          return;
        }

        const history = messagesByPeer.get(activeRecipient) || [];
        if (history.length === 0) {
          const empty = document.createElement('div');
          empty.className = 'empty-state';
          empty.innerHTML = `
            <div class="empty-state-icon">🔒</div>
            <h3>Conversation with ${document.createTextNode(activeRecipient).textContent}</h3>
            <p>No messages exchanged yet in this session. Messages sent here are evaluated in real time by the Threat Engine.</p>
          `;
          chatFeed.appendChild(empty);
        } else {
          history.forEach(m => {
            const isSelf = m.sender === myName;
            chatFeed.appendChild(createMessageElement(m, isSelf));
          });
        }
        chatFeed.scrollTop = chatFeed.scrollHeight;
      }

      function updateRosterUI() {
        const query = (userSearch.value || '').trim().toLowerCase();
        const filtered = onlineUsers.filter(u => u !== myName && (!query || u.toLowerCase().includes(query)));

        onlineCount.textContent = `${onlineUsers.filter(u => u !== myName).length} online`;
        userList.innerHTML = '';

        if (filtered.length === 0) {
          const empty = document.createElement('div');
          empty.className = 'user-empty';
          empty.textContent = onlineUsers.filter(u => u !== myName).length === 0
            ? 'No other users online. Open this page on another device or tab to start messaging!'
            : 'No contacts match your filter.';
          userList.appendChild(empty);
          return;
        }

        filtered.forEach(user => {
          const item = document.createElement('div');
          item.className = 'user-item' + (user === activeRecipient ? ' active' : '');
          item.onclick = () => selectRecipient(user);

          const avatar = document.createElement('div');
          avatar.className = 'avatar';
          avatar.textContent = getInitials(user);
          avatar.style.backgroundColor = getAvatarColor(user);

          const meta = document.createElement('div');
          meta.className = 'user-meta';

          const name = document.createElement('div');
          name.className = 'user-meta-name';
          name.textContent = user;

          const status = document.createElement('div');
          status.className = 'user-meta-status';
          status.innerHTML = '<span class="status-dot"></span> Online';

          meta.appendChild(name);
          meta.appendChild(status);
          item.appendChild(avatar);
          item.appendChild(meta);
          userList.appendChild(item);
        });
      }

      userSearch.addEventListener('input', updateRosterUI);

      // Back button on mobile
      backBtn.onclick = () => {
        sidebar.classList.remove('hidden-mobile');
        chatArea.classList.remove('active-mobile');
      };

      // Composer validation
      function validateComposer() {
        const text = (msgInput.value || '').trim();
        charCount.textContent = `${msgInput.value.length} / 2000`;
        sendBtn.disabled = !text || !activeRecipient || !ws || ws.readyState !== WebSocket.OPEN;
      }

      msgInput.addEventListener('input', validateComposer);
      msgInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          if (!sendBtn.disabled) send();
        }
      });

      // WebSocket Connection
      window.connect = function() {
        const rawName = (usernameInput.value || '').trim();
        if (!/^[A-Za-z0-9_-]{2,24}$/.test(rawName)) {
          joinErr.textContent = 'Use 2–24 letters, numbers, _ or - without spaces.';
          joinErr.style.display = 'block';
          return;
        }

        joinErr.style.display = 'none';
        joinBtn.disabled = true;
        joinBtn.textContent = 'Connecting...';

        myName = rawName;
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${protocol}//${location.host}/ws/chat/${encodeURIComponent(myName)}`;

        ws = new WebSocket(url);

        ws.onopen = () => {
          onboardingModal.style.display = 'none';
          userPill.style.display = 'flex';
          currentUsername.textContent = myName;
          appendSystemAlert(`Connected to secure messaging as @${myName}`, 'info');
        };

        ws.onmessage = (event) => {
          let data;
          try {
            data = JSON.parse(event.data);
          } catch (e) {
            return;
          }

          if (data.type === 'users') {
            onlineUsers = data.users || [];
            updateRosterUI();
            if (activeRecipient && !onlineUsers.includes(activeRecipient)) {
              recipientStatus.textContent = 'User went offline';
            }
          } else if (data.type === 'message') {
            const peer = data.sender === myName ? data.recipient : data.sender;
            if (!messagesByPeer.has(peer)) {
              messagesByPeer.set(peer, []);
            }
            messagesByPeer.get(peer).push(data);

            if (peer === activeRecipient) {
              chatFeed.appendChild(createMessageElement(data, data.sender === myName));
              chatFeed.scrollTop = chatFeed.scrollHeight;
            }
          } else if (data.type === 'warning') {
            appendSystemAlert(`Security Policy Notice: ${data.message}`, 'warn');
          } else if (data.type === 'blocked') {
            blockedReason.textContent = data.message || 'Your account has been temporarily blocked due to suspicious activity.';
            blockedModal.style.display = 'flex';
            msgInput.disabled = true;
            sendBtn.disabled = true;
            ws.close();
          }
        };

        ws.onclose = () => {
          if (blockedModal.style.display !== 'flex') {
            appendSystemAlert('Disconnected from the secure messaging service.', 'warn');
            msgInput.disabled = true;
            sendBtn.disabled = true;
          }
        };

        ws.onerror = () => {
          joinBtn.disabled = false;
          joinBtn.textContent = 'Join Secure Chat';
          joinErr.textContent = 'Unable to establish secure WebSocket connection.';
          joinErr.style.display = 'block';
        };
      };

      // Send Message
      window.send = function() {
        const text = (msgInput.value || '').trim();
        if (!text || !activeRecipient) return;

        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            recipient: activeRecipient,
            text: text
          }));
          msgInput.value = '';
          validateComposer();
        }
      };

      sendBtn.onclick = send;

      // Cloudflare Tunnel & LAN QR Sharing
      async function copyJoinUrl(textId, btnId) {
        const textElem = $(textId);
        const btnElem = $(btnId);
        const text = textElem ? textElem.textContent : '';
        if (!text || text.startsWith('Loading')) return;
        try {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
          } else {
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
          }
          if (btnElem) {
            const orig = btnElem.textContent;
            btnElem.textContent = 'Copied!';
            setTimeout(() => { btnElem.textContent = orig; }, 2000);
          }
        } catch (_) {}
      }
      window.copyJoinUrl = copyJoinUrl;

      async function refreshTunnelState() {
        try {
          const res = await fetch('/api/tunnel/state', { cache: 'no-store' });
          if (!res.ok) return;
          const data = await res.json();
          const isPublic = Boolean(data.is_public_ready && data.public_url);
          const activeUrl = data.active_joining_url || (data.local_url ? (data.local_url + '/chat') : location.href);

          const updateSection = (badgeId, textId) => {
            const badge = $(badgeId);
            const text = $(textId);
            if (badge) {
              badge.className = 'access-badge ' + (isPublic ? 'public' : 'lan');
              badge.textContent = isPublic ? 'PUBLIC ACCESS (HTTPS)' : 'LOCAL WI-FI ONLY (HTTP)';
            }
            if (text) {
              text.textContent = activeUrl;
            }
          };

          updateSection('onboardingAccessBadge', 'onboardingUrlText');
          updateSection('inviteAccessBadge', 'inviteUrlText');
        } catch (_) {}
      }

      const openInviteBtn = $('openInviteBtn');
      const inviteModal = $('inviteModal');
      const closeInviteBtn = $('closeInviteBtn');
      if (openInviteBtn && inviteModal) {
        openInviteBtn.onclick = () => {
          refreshTunnelState();
          inviteModal.style.display = 'flex';
        };
      }
      if (closeInviteBtn && inviteModal) {
        closeInviteBtn.onclick = () => {
          inviteModal.style.display = 'none';
        };
      }

      refreshTunnelState();

    })();
  </script>
</body>
</html>
"""


@router.get("/chat", response_class=HTMLResponse)
async def chat_page() -> str:
    return CHAT_HTML


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page() -> str:
    from backend.http_flood_ui import http_flood_panel
    from backend.security_ui import security_panel
    return DASHBOARD_HTML.replace("</header>", "</header>" + security_panel() + http_flood_panel(), 1)



@router.get("/api/chat/state")
async def chat_state() -> dict:
    behavior = behavior_analyzer.snapshot()
    for username in set(state.clients) | set(state.blocked):
        behavior.setdefault(username, {"total_messages": 0, "messages_last_30_seconds": 0,
                                       "messages_per_second": 0.0, "messages_per_minute": 0,
                                       "unique_recipients": 0, "risk": "SAFE"})
    now = time.time()
    return {**state.dashboard_roster(), "behavior": behavior, "messages": len(state.recent),
            "messages_per_second": sum(now - item.get("timestamp", 0) <= 1 for item in state.recent),
            "messages_last_30_seconds": sum(now - item.get("timestamp", 0) <= 30 for item in state.recent),
            "events": list(state.events)}


@router.get("/api/tunnel/state")
def tunnel_state() -> dict:
    from backend.network.tunnel import tunnel_manager
    return tunnel_manager.status_dict()


@router.get("/api/tunnel/qr.svg")
def tunnel_qr_svg() -> Response:
    from backend.network.tunnel import tunnel_manager
    from backend.network.qr_generator import generate_qr_svg
    svg = generate_qr_svg(tunnel_manager.active_joining_url)
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
    )


@router.websocket("/ws/dashboard")
async def dashboard_socket(ws: WebSocket) -> None:
    if not demo_security.can_view(ws):
        await ws.close(code=1008)
        return
    origin = ws.headers.get("origin")
    request_host = ws.headers.get("host")
    if not await asyncio.to_thread(is_origin_allowed, origin, request_host=request_host):
        logger.warning("[SECURITY] Rejected WebSocket dashboard connection from untrusted origin: %s", origin)
        await ws.close(code=1008)
        return
    await ws.accept()
    dashboard_clients.add(ws)
    try:
        await ws.send_json({"type": "snapshot", **state.dashboard_roster(), "events": list(state.events)})
        while demo_security.can_view(ws):
            try:
                await asyncio.wait_for(ws.receive_text(), timeout=10)
            except asyncio.TimeoutError:
                continue
        await ws.close(code=1008)
    except WebSocketDisconnect:
        pass
    finally:
        dashboard_clients.discard(ws)



@router.post("/api/admin/unblock/{user_id}")
async def unblock_user(user_id: str, request: Request) -> dict:
    demo_security.require_control(request, dashboard=True)
    username = state.blocked_username(user_id)
    if username is None:
        raise HTTPException(status_code=404, detail="User is not blocked.")
    state.blocked.remove(username)
    reason = state.block_reasons.pop(username, "")
    behavior_analyzer.reset(username)
    blocking_manager.unblock_user(username)
    threat_engine.user_cumulative_risk.pop(username.casefold(), None)
    await state.event("admin_unblocked", {"username": username, "previous_reason": reason, "detection_source": "ADMIN"})
    await state.roster()
    return {"status": "unblocked", "username": username}


@router.websocket("/ws/chat/{username}")
async def chat_socket(ws: WebSocket, username: str) -> None:
    origin = ws.headers.get("origin")
    request_host = ws.headers.get("host")
    if not await asyncio.to_thread(is_origin_allowed, origin, request_host=request_host):
        logger.warning("[SECURITY] Rejected WebSocket chat connection for user '%s' from untrusted origin: %s", username, origin)
        await ws.close(code=1008)
        return
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,24}", username):
        await ws.accept()
        await ws.send_json({"type": "blocked", "message": "Username is invalid, already connected, or blocked."})
        await ws.close(code=1008)
        return
    connection = boundary(ws)
    if request_host and f"https://{request_host.casefold().removesuffix(':443')}" == public_origin() and not connection.tunnel:
        await ws.close(code=1008)
        return
    peer_host = ws.client.host if ws.client else None
    client_ip = connection.source if connection.tunnel else resolve_client_ip(peer_host, ws.headers)
    client_port = int(ws.client.port) if ws.client else 0
    server_ip, server_port = ws.scope.get("server") or (None, 0)
    # A tunnel's forwarded visitor address is not the peer of this TCP connection.
    direct_endpoint = (client_ip, client_port, server_ip, server_port, uuid.uuid4().hex) if (
        peer_host == client_ip and server_ip and server_port and client_port and not connection.tunnel
    ) else None
    username_key = username.casefold()
    await ws.accept()
    async with state.lock:
        rejected = state.chat_block_message(username, client_ip)
        if not rejected and any(name.casefold() == username_key for name in state.clients):
            rejected = "Username is already connected."
        if not rejected:
            state.clients[username] = ws
            state.client_ips[username] = client_ip
            if direct_endpoint:
                state.client_endpoints[username] = direct_endpoint
    if rejected:
        await ws.send_json({"type": "blocked", "message": rejected})
        await ws.close(code=1008)
        return
    try:
        await state.roster()
        await state.event("user_joined", {"username": username, "source_ip": client_ip})
        while True:
            raw = await ws.receive_json()
            block_message = state.chat_block_message(username, client_ip)
            if block_message:
                await ws.send_json({"type": "blocked", "message": block_message})
                await ws.close(code=1008)
                break
            recipient = str(raw.get("recipient", "")).strip()
            text = str(raw.get("text", ""))
            if len(text) > MAX_MESSAGE_LENGTH:
                await ws.send_json({"type": "warning", "message": f"Messages are limited to {MAX_MESSAGE_LENGTH} characters."})
                continue
            if not text.strip() or not recipient:
                continue
            behavior, behavior_details = behavior_risk(username, recipient, text)
            message_id = uuid.uuid4().hex
            message_analysis = message_analyzer.analyze(text)
            url_analysis = url_analyzer.analyze(text)
            security = inspect_message(text)
            network_analysis = None
            try:
                # Runtime import avoids the existing runtime -> chat service import cycle.
                from backend.network.runtime import network_runtime
                matching_flows = [f for f in reversed(network_runtime.completed_flows)
                                  if state.flow_matches_client(f, username)]
                candidates = [f for f in matching_flows if f.get("gatv2_status") == "analyzed"]
                if candidates:
                    latest = candidates[0]
                    network_analysis = {"available": True,
                                        "flow_id": latest.get("flow_id"),
                                        "anomaly_probability": latest.get("gatv2_anomaly_probability"),
                                        "is_anomaly": latest.get("gatv2_prediction") == "ATTACK",
                                        "confidence": float(latest.get("gatv2_confidence", 0.0)) * 100}
                    network_association_reason = "matched_exact_chat_tcp_5_tuple"
                elif matching_flows:
                    network_association_reason = "matching_chat_flow_not_yet_analyzed"
                elif any(state.flow_matches_client(f, username)
                         for f in network_runtime.tracker.active_snapshots()):
                    network_association_reason = "matching_chat_flow_still_active"
                else:
                    network_association_reason = "no_captured_flow_matched_chat_tcp_5_tuple"
            except Exception:
                network_analysis = None
                network_association_reason = "network_runtime_unavailable_or_association_failed"
            decision = await threat_engine.evaluate_message_event(
                username, client_ip,
                {**message_analysis, "indicators": message_analysis.get("indicators", [])},
                {**url_analysis, "indicators": url_analysis.get("indicators", [])},
                {"behavior_risk": behavior, "indicators": [behavior_details.get("risk", "SAFE")],
                 **behavior_details},
                network_analysis,
            )
            record = {"message_id": message_id, "sender": username, "recipient": recipient, "source_ip": client_ip,
                      "text": text, "security": security, "behavior": behavior_details,
                      "threat": decision, "network_association_reason": network_association_reason}
            signals = decision.get("signals", {})
            logger.info(
                "THREAT_DECISION user=%s message_id=%s message_risk=%.4f url_risk=%.4f "
                "behavior_risk=%.4f network_risk=%.4f network_signal_available=%s "
                "network_flow_id=%s network_association=%s final_risk=%.4f decision=%s",
                username, message_id, float(signals.get("message_risk", 0.0)),
                float(signals.get("url_risk", 0.0)), float(signals.get("behavior_risk", 0.0)),
                float(signals.get("gatv2_network_risk", 0.0)),
                decision.get("network_signal_available", False),
                (network_analysis or {}).get("flow_id", "none"), network_association_reason,
                float(decision.get("final_risk", decision.get("threat_score", 0.0))), decision.get("action", "UNKNOWN"),
            )
            await state.event("threat_decision", {**decision, "sender": username,
                                                   "recipient": recipient, "message_id": message_id,
                                                   "network_flow_id": (network_analysis or {}).get("flow_id"),
                                                   "network_association_reason": network_association_reason})
            if decision["action"] == "BLOCK_USER":
                state.blocked.add(username)
                state.block_reasons[username] = decision["reason"]
                await ws.send_json({"type": "blocked", "message": state.chat_block_message(username, client_ip)})
                await state.event("blocked", {"username": username, "source_ip": client_ip,
                                               "reason": decision["reason"], "threat": decision})
                await state.roster()
                await ws.close(code=1008)
                break
            block_message = state.chat_block_message(username, client_ip)
            if block_message:
                await ws.send_json({"type": "blocked", "message": block_message})
                await ws.close(code=1008)
                break
            if decision["action"] == "BLOCK_MESSAGE":
                await ws.send_json({"type": "warning", "message": "Message rejected by the security policy.", "threat": decision})
                await state.event("message_blocked", {**record, "reason": decision["reason"]})
                continue
            peer = state.clients.get(recipient)
            if not peer or state.chat_block_message(recipient, state.client_ips.get(recipient)):
                await ws.send_json({"type": "warning", "message": "Recipient is not connected."})
                continue
            delivered = {"type": "message", **record, "timestamp": time.time()}
            state.recent.append(delivered)
            await ws.send_json(delivered)
            await peer.send_json(delivered)
            await state.event("message", record)
            if decision["action"] == "WARN":
                await ws.send_json({"type": "warning", "message": decision["reason"], "threat": decision})
    except WebSocketDisconnect:
        pass
    finally:
        async with state.lock:
            if state.clients.get(username) is ws:
                state.clients.pop(username, None)
                state.client_ips.pop(username, None)
                state.client_endpoints.pop(username, None)
        await state.roster()
        await state.event("user_left", {"username": username})

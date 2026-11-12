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

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi import HTTPException, Header
from backend.security.live_behavior_analyzer import BehaviorAnalyzer, BehaviorConfig
from backend.security.message_analyzer import message_analyzer
from backend.security.url_analyzer import url_analyzer
from backend.security.threat_engine import threat_engine

router = APIRouter()
logger = logging.getLogger(__name__)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl"}
SUSPICIOUS_WORDS = {"verify", "login", "account", "password", "urgent", "suspended", "payment"}
MAX_MESSAGE_LENGTH = 2000


class ChatState:
    def __init__(self) -> None:
        self.clients: dict[str, WebSocket] = {}
        self.client_ips: dict[str, str] = {}
        self.client_endpoints: dict[str, tuple[str, int, int]] = {}
        self.blocked: set[str] = set()
        self.block_reasons: dict[str, str] = {}
        self.recent: deque[dict[str, Any]] = deque(maxlen=200)
        self.events: deque[dict[str, Any]] = deque(maxlen=500)
        self.sent: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self.lock = asyncio.Lock()

    def flow_matches_client(self, flow: dict[str, Any], username: str) -> bool:
        endpoint = self.client_endpoints.get(username)
        if not endpoint or str(flow.get("protocol", "")).upper() != "TCP":
            return False
        client_ip, client_port, server_port = endpoint
        return (
            flow.get("source_ip") == client_ip
            and int(flow.get("source_port", -1)) == client_port
            and int(flow.get("destination_port", -1)) == server_port
        ) or (
            flow.get("destination_ip") == client_ip
            and int(flow.get("destination_port", -1)) == client_port
            and int(flow.get("source_port", -1)) == server_port
        )

    def resolve_flow_user(self, flow: dict[str, Any]) -> str:
        matches = [username for username in self.client_endpoints
                   if self.flow_matches_client(flow, username)]
        return matches[0] if len(matches) == 1 else "UNKNOWN"

    async def event(self, kind: str, data: dict[str, Any]) -> None:
        item = {"type": kind, "timestamp": time.time(), **data}
        self.events.append(item)
        await self.broadcast_dashboard(item)

    async def broadcast_dashboard(self, item: dict[str, Any]) -> None:
        dead = []
        for ws in dashboard_clients:
            try:
                await ws.send_json(item)
            except Exception:
                dead.append(ws)
        for ws in dead:
            dashboard_clients.discard(ws)

    async def roster(self) -> None:
        payload = {"type": "users", "users": sorted(self.clients), "blocked": sorted(self.blocked)}
        for ws in list(self.clients.values()):
            try:
                await ws.send_json(payload)
            except Exception:
                pass


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
<div class="grid stats"><div class="stat"><div class="stat-label">Packets / Sec</div><div class="stat-value cyan" id="pps">—</div><div class="stat-note">LIVE CAPTURE WINDOW</div></div><div class="stat"><div class="stat-label">Bytes / Sec</div><div class="stat-value cyan" id="bps">—</div><div class="stat-note">LIVE CAPTURE WINDOW</div></div><div class="stat"><div class="stat-label">Active Flows</div><div class="stat-value" id="active">—</div><div class="stat-note">OBSERVED BY FLOW TRACKER</div></div><div class="stat"><div class="stat-label">GATv2 Analyses</div><div class="stat-value" id="analyses">—</div><div class="stat-note">COMPLETED INFERENCES</div></div><div class="stat"><div class="stat-label">Anomalies</div><div class="stat-value" id="anomalies">—</div><div class="stat-note">GATv2 ATTACK PREDICTIONS</div></div><div class="stat"><div class="stat-label">Online Users</div><div class="stat-value" id="users">—</div><div class="stat-note">SECURE CHAT</div></div></div>
<div class="grid main-grid"><section class="panel"><div class="panel-head"><div><h2 class="panel-title">LIVE NETWORK ACTIVITY</h2><div class="panel-kicker">PACKETS PER SECOND // ROLLING 60 SECOND WINDOW</div></div><div class="legend"><span><i class="key"></i>CAPTURED TRAFFIC</span><span><i class="key red"></i>GATv2 ATTACK EVENT</span></div></div><div class="chart-wrap"><svg id="activityGraph" viewBox="0 0 900 260" role="img" aria-label="Captured packet rate over the last 60 seconds"></svg></div><div class="chart-foot"><span>TIME →</span><span id="chartRange">LAST 60 SECONDS</span></div></section>
<section class="panel"><div class="panel-head"><div><h2 class="panel-title">GATv2 // MODEL INFERENCE</h2><div class="panel-kicker">EXISTING MODEL OUTPUT / SAVED CLASSIFICATION THRESHOLD</div></div><span class="tag" id="modelTag">MODEL —</span></div><div class="readout-item"><div class="label">LATEST PREDICTION</div><div class="value" id="latest">WAITING FOR ANALYSIS</div></div><div class="prob-track"><div class="prob-fill" id="probFill"></div><div class="prob-marker" id="probMarker"></div></div><div class="prob-scale"><span>0.00</span><span id="thresholdLabel">THRESHOLD —</span><span>1.00</span></div><div class="prob-caption"><span class="small">ANOMALY PROBABILITY</span><strong id="probability">—</strong></div><div class="incident" id="incidentPanel"><div class="incident-label">LATEST GATv2 ATTACK EVENT</div><div class="incident-empty">No GATv2 ATTACK event in the received security event history.</div></div></section></div>
<div class="grid lower-grid" style="margin-top:12px"><section class="panel"><div class="panel-head"><div><h2 class="panel-title">OBSERVED NETWORK TOPOLOGY</h2><div class="panel-kicker">ENDPOINTS FROM REAL CAPTURED FLOWS</div></div><span class="tag" id="topologyCount">0 OBSERVED HOSTS</span></div><div class="topology" id="topology"></div></section><section class="panel"><div class="panel-head"><div><h2 class="panel-title">ATTACK HISTORY // TIMELINE</h2><div class="panel-kicker">GATv2 ATTACK PREDICTIONS FROM LIVE EVENT STREAM</div></div><span class="tag" id="threats">0 EVENTS</span></div><div class="timeline" id="attackHistory"></div></section></div>
<div class="grid lower-grid" style="margin-top:12px"><section class="panel"><div class="panel-head"><div><h2 class="panel-title">SECURITY EVENTS // LIVE TERMINAL</h2><div class="panel-kicker">WEBSOCKET EVENT STREAM + API SNAPSHOT</div></div><span class="tag" id="eventCount">0 EVENTS</span></div><div class="terminal" id="events" aria-live="polite"></div></section><section class="panel"><div class="panel-head"><div><h2 class="panel-title">FLOW TELEMETRY</h2><div class="panel-kicker">LATEST CAPTURED FLOWS / NO SYNTHETIC HOSTS</div></div></div><div class="small" id="captureStatus">Waiting for API state.</div><div class="readout" style="margin-top:10px"><div class="readout-item"><div class="label">NEW FLOWS / 60 SEC</div><div class="value" id="newFlows">0</div></div><div class="readout-item"><div class="label">CURRENT CHAT BLOCKS</div><div class="value" id="blocked">0</div></div><div class="readout-item"><div class="label">MESSAGES / SEC</div><div class="value" id="mps">0</div></div><div class="readout-item"><div class="label">CHAT SECURITY EVENTS</div><div class="value" id="eventCount2">0</div></div></div></section></div>
<section class="panel" style="margin-top:12px"><div class="user-head"><div class="panel-head" style="border:0;margin:0;padding:0"><div><h2 class="panel-title">USER SECURITY</h2><div class="panel-kicker">LIVE CHAT RISK / ADMIN UNBLOCK</div></div></div><div class="user-actions"><input id="adminToken" class="token" type="password" placeholder="Admin token" aria-label="Admin token"><button id="refreshButton" type="button">REFRESH</button></div></div><div class="table-wrap" style="margin-top:12px"><table class="user-table"><thead><tr><th>USERNAME</th><th>CLIENT IP</th><th>STATUS</th><th>MESSAGES</th><th>MSG/SEC</th><th>RISK</th><th>REASON</th><th>ACTION</th></tr></thead><tbody id="userRows"></tbody></table></div></section>
<section class="panel" style="margin-top:12px"><div class="panel-head"><div><h2 class="panel-title">LIVE NETWORK FLOWS</h2><div class="panel-kicker">CAPTURED FLOW TRACKER RECORDS AND GATv2 RESULTS</div></div><span class="tag" id="flowCount">0 FLOWS</span></div><div class="table-wrap"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>PACKETS</th><th>BYTES</th><th>GATv2</th><th>PROBABILITY</th></tr></thead><tbody id="flows"></tbody></table></div></section>
<footer class="footer"><span id="interfaceInfo">CAPTURE INTERFACE: UNKNOWN</span><span>ATTACK CLASSIFICATION IS PROVIDED BY THE EXISTING GATv2 PIPELINE.</span><span id="updatedAt">UPDATED: —</span></footer></main>
<script>
const $=id=>document.getElementById(id);const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let events=[],networkState=null,chatState=null,samples=[],socket=null;const sampleLimit=31;function eventKey(x){return [x.timestamp,x.type,x.flow_id,x.message_id,x.username,x.source_ip].join('|')}function mergeEvents(incoming){const map=new Map(events.map(x=>[eventKey(x),x]));(incoming||[]).forEach(x=>{if(x&&x.type)map.set(eventKey(x),x)});events=Array.from(map.values()).sort((a,b)=>(a.timestamp||0)-(b.timestamp||0)).slice(-500)}function attackEvents(){return events.filter(x=>x.type==='gatv2_analysis'&&(x.gatv2_prediction==='ATTACK'||x.prediction==='ATTACK'))}function timeText(ts){return ts?new Date(ts*1000).toLocaleTimeString(): '—'}function formatRate(value){return Number(value||0).toLocaleString(undefined,{maximumFractionDigits:1})}function formatBytes(value){const n=Number(value||0);if(n<1024)return n.toFixed(0)+' B/s';if(n<1048576)return (n/1024).toFixed(1)+' KB/s';return (n/1048576).toFixed(2)+' MB/s'}function privateIp(ip){if(!ip)return false;if(ip==='::1'||ip.indexOf('fc')===0||ip.indexOf('fd')===0)return true;const m=ip.match(/^(\d{1,3})\.(\d{1,3})\./);if(!m)return false;const a=Number(m[1]),b=Number(m[2]);return a===10||a===127||(a===192&&b===168)||(a===172&&b>=16&&b<=31)}function getFlow(id){if(!networkState)return null;return (networkState.completed_flows||[]).find(f=>f.flow_id===id)||null}
function drawGraph(){const svg=$('activityGraph');const w=900,h=260,left=48,right=15,top=12,bottom=24,pw=w-left-right,ph=h-top-bottom,now=Date.now()/1000,cut=now-60;const points=samples.filter(p=>p.t>=cut);const max=Math.max(1,...points.map(p=>p.v));const ceil=Math.max(5,Math.ceil(max/5)*5);let out='';for(let i=0;i<=4;i++){const val=ceil*(4-i)/4,y=top+ph*i/4;out+='<line x1="'+left+'" y1="'+y+'" x2="'+(w-right)+'" y2="'+y+'" stroke="#1d2c22" stroke-width="1"/><text x="'+(left-8)+'" y="'+(y+3)+'" fill="#728d77" font-size="9" text-anchor="end">'+Math.round(val)+'</text>'}for(let i=0;i<=6;i++){const x=left+pw*i/6;out+='<line x1="'+x+'" y1="'+top+'" x2="'+x+'" y2="'+(top+ph)+'" stroke="#142019" stroke-width="1"/><text x="'+x+'" y="'+(h-5)+'" fill="#728d77" font-size="8" text-anchor="middle">'+(i===6?'NOW':Math.round((i-6)*10)+'s')+'</text>'}if(points.length){const coords=points.map(p=>({x:left+Math.max(0,Math.min(60,p.t-cut))/60*pw,y:top+ph-(Math.min(ceil,p.v)/ceil)*ph}));const line=coords.map(p=>p.x.toFixed(1)+','+p.y.toFixed(1)).join(' ');out+='<polyline points="'+line+'" fill="none" stroke="#54e6ff" stroke-width="2" vector-effect="non-scaling-stroke"/>';const first=coords[0],last=coords[coords.length-1];out+='<polygon points="'+first.x+','+(top+ph)+' '+line+' '+last.x+','+(top+ph)+'" fill="#54e6ff" opacity=".06"/>'}const attacks=attackEvents().filter(x=>x.timestamp>=cut&&x.timestamp<=now);attacks.forEach(a=>{const x=left+(a.timestamp-cut)/60*pw;out+='<line x1="'+x+'" y1="'+top+'" x2="'+x+'" y2="'+(top+ph)+'" stroke="#ff3b4e" stroke-width="1" stroke-dasharray="4 4" opacity=".9"><title>GATv2 ATTACK · '+esc(timeText(a.timestamp))+' · '+esc(a.source_ip||'source unavailable')+'</title></line><path d="M '+(x-5)+' '+(top+ph+1)+' L '+(x+5)+' '+(top+ph+1)+' L '+x+' '+(top+ph-7)+' Z" fill="#ff3b4e"><title>GATv2 ATTACK · '+esc(timeText(a.timestamp))+'</title></path>'});svg.innerHTML=out}
function renderIncident(n){const attacks=attackEvents(),a=attacks.length?attacks[attacks.length-1]:null,flow=a?getFlow(a.flow_id):null,probRaw=a?(a.anomaly_probability!=null?a.anomaly_probability:(flow&&flow.gatv2_anomaly_probability!=null?flow.gatv2_anomaly_probability:null)):null,prob=probRaw==null?null:Number(probRaw),thresholdRaw=(a&&a.threshold!=null?a.threshold:(flow&&flow.gatv2_threshold!=null?flow.gatv2_threshold:n.gatv2_threshold)),threshold=thresholdRaw==null?null:Number(thresholdRaw);const detected=!!a;const latestIsAttack=n.latest_prediction==='ATTACK';$('latest').textContent=n.latest_prediction||'WAITING FOR ANALYSIS';$('latest').className='value'+(n.latest_prediction==='ATTACK'?' pill attack':'');$('probability').textContent=detected&&prob!=null?(prob*100).toFixed(2)+'%':'—';$('probability').className=latestIsAttack?'attack':'';$('probFill').style.width=detected&&prob!=null?(Math.max(0,Math.min(1,prob))*100)+'%':'0%';$('probFill').className='prob-fill'+(latestIsAttack?' attack':'');$('probMarker').style.display=threshold==null?'none':'block';$('probMarker').style.left=(Math.max(0,Math.min(1,threshold||0))*100)+'%';$('thresholdLabel').textContent=threshold==null?'THRESHOLD —':'THRESHOLD '+threshold.toFixed(2);$('modelTag').textContent=n.gatv2==='available'?'MODEL ONLINE':'MODEL OFFLINE';$('modelTag').className='tag '+(n.gatv2==='available'?'ok':'bad');$('threats').textContent=attacks.length+' EVENTS';$('incidentPanel').innerHTML=detected?'<div class="incident-label">GATv2 ATTACK DETECTED · '+esc(timeText(a.timestamp))+'</div><div class="incident-title">NETWORK ATTACK</div><div class="incident-grid"><div><span class="small">SOURCE DEVICE</span><span class="value">'+esc(a.source_ip||'UNKNOWN LAN DEVICE')+' : '+esc(a.source_port==null?'—':a.source_port)+'</span></div><div><span class="small">SOURCE LOCATION</span><span class="value">'+(privateIp(a.source_ip)?'LOCAL NETWORK / WI-FI':'APPROXIMATE LOCATION NOT PROVIDED')+'</span></div><div><span class="small">TARGET</span><span class="value">'+esc(a.destination_ip||'—')+' : '+esc(a.destination_port==null?'—':a.destination_port)+'</span></div><div><span class="small">PROTOCOL</span><span class="value">'+esc(a.protocol||'—')+'</span></div><div><span class="small">GATv2 PROBABILITY</span><span class="value">'+(prob==null?'NOT PROVIDED':(prob*100).toFixed(2)+'%')+'</span></div><div><span class="small">THRESHOLD</span><span class="value">'+threshold.toFixed(2)+'</span></div><div><span class="small">DEVICE NAME</span><span class="value">UNKNOWN LAN DEVICE</span></div><div><span class="small">ACTION REPORTED</span><span class="value">'+esc(a.action||'ALERT')+' · NO FIREWALL STATUS IN API</span></div></div>':'<div class="incident-empty">No GATv2 ATTACK event in the received security event history. Host identity and physical location are shown only when provided by live services.</div>'}
function renderBanner(n){const b=$('warningBanner'),indicator=$('liveIndicator'),secure=n.gatv2==='available'&&n.latest_prediction!=='ATTACK';if(n.latest_prediction==='ATTACK'){b.className='banner attack';$('bannerIcon').textContent='⚠';$('bannerTitle').textContent='LATEST GATv2 RESULT // ATTACK';$('bannerCopy').textContent='A real GATv2 ATTACK prediction is the latest model result. Incident details are from the associated captured flow.';indicator.className='live warn';indicator.textContent='ATTACK RESULT'}else if(n.gatv2!=='available'||n.capture!=='running'){b.className='banner wait';$('bannerIcon').textContent='◌';$('bannerTitle').textContent='MONITORING DEGRADED / STATE INCOMPLETE';$('bannerCopy').textContent='Capture: '+(n.capture||'unknown')+' · GATv2: '+(n.gatv2||'unknown')+' · '+(n.gatv2_error||n.capture_error||'waiting for live state');indicator.className='live wait';indicator.textContent='CHECK STATUS'}else{b.className='banner';$('bannerIcon').textContent='●';$('bannerTitle').textContent='NO CURRENT GATv2 ATTACK RESULT';$('bannerCopy').textContent='Latest GATv2 prediction: '+(n.latest_prediction||'none')+'. Historical attack events remain in the timeline.';indicator.className='live';indicator.textContent='LIVE / SECURE'}$('bannerMeta').textContent='LAST UPDATE: '+new Date().toLocaleTimeString()}
function renderTimeline(){const attacks=attackEvents().slice().reverse();$('attackHistory').innerHTML=attacks.length?attacks.slice(0,60).map(a=>'<div class="timeline-row"><div class="timeline-time">'+esc(timeText(a.timestamp))+'</div><div class="timeline-dot">▲</div><div><div class="desc">GATv2 ATTACK DETECTED</div><div class="sub">'+esc(a.source_ip||'source unavailable')+' → '+esc(a.destination_ip||'target unavailable')+' · '+(Number(a.anomaly_probability!=null?a.anomaly_probability:a.confidence||0)*100).toFixed(2)+'% · '+esc(a.protocol||'')+'</div></div></div>').join(''):'<div class="incident-empty">No GATv2 ATTACK events recorded in the live event history.</div>'}
function renderTerminal(){const recent=events.slice().reverse().slice(0,100);$('events').innerHTML=recent.map(x=>{const bad=(x.type==='gatv2_analysis'&&(x.gatv2_prediction==='ATTACK'||x.prediction==='ATTACK'));const detail=x.reason||x.gatv2_prediction||x.prediction||x.action||x.username||x.source_ip||'';const endpoints=x.source_ip?(x.source_ip+(x.source_port!=null?':'+x.source_port:'')+' → '+(x.destination_ip||'')+(x.destination_port!=null?':'+x.destination_port:'')):'';return '<div class="term-row"><span class="term-time">'+esc(timeText(x.timestamp))+'</span><span class="term-type'+(bad?' attack':'')+'">'+esc(x.type||'EVENT').toUpperCase()+'</span><span class="term-text">'+esc(endpoints||detail)+(endpoints&&detail?' · '+esc(detail):'')+'</span></div>'}).join('');$('eventCount').textContent=events.length+' EVENTS';$('eventCount2').textContent=events.length+' observed'}
function renderTopology(n){const flows=[...(n.active_flows||[]),...(n.completed_flows||[])].slice(-32),hosts=Array.from(new Set(flows.flatMap(f=>[f.source_ip,f.destination_ip]).filter(Boolean)));$('topologyCount').textContent=hosts.length+' OBSERVED HOSTS';if(!hosts.length){$('topology').innerHTML='<div class="topology-empty">No captured flow endpoints observed yet.</div>';return}const w=640,h=280,cx=w/2,cy=h/2,rad=Math.min(100,Math.max(42,hosts.length*9)),pos={};hosts.forEach((ip,i)=>{const angle=-Math.PI/2+2*Math.PI*i/hosts.length;pos[ip]={x:cx+Math.cos(angle)*rad,y:cy+Math.sin(angle)*rad}});let s='<svg viewBox="0 0 '+w+' '+h+'" role="img" aria-label="Observed network flow endpoints">';flows.forEach(f=>{if(!pos[f.source_ip]||!pos[f.destination_ip])return;const attacked=f.gatv2_prediction==='ATTACK';const col=attacked?'#ff3b4e':'#54e6ff';s+='<line x1="'+pos[f.source_ip].x+'" y1="'+pos[f.source_ip].y+'" x2="'+pos[f.destination_ip].x+'" y2="'+pos[f.destination_ip].y+'" stroke="'+col+'" stroke-width="1" opacity=".52"><title>'+esc(f.source_ip)+' → '+esc(f.destination_ip)+' · '+esc(f.protocol||'')+' · '+esc(f.gatv2_prediction||f.gatv2_status||'pending')+'</title></line>'});hosts.forEach(ip=>{const p=pos[ip];s+='<circle cx="'+p.x+'" cy="'+p.y+'" r="18" fill="#0b150e" stroke="#7cff8a" stroke-width="1"/><text x="'+p.x+'" y="'+(p.y+3)+'" fill="#d7e8d9" text-anchor="middle" font-size="8">HOST '+(hosts.indexOf(ip)+1)+'</text><text x="'+p.x+'" y="'+(p.y+31)+'" fill="#8ba791" text-anchor="middle" font-size="9">'+esc(ip)+'</text>'});s+='</svg>';$('topology').innerHTML=s}
function renderFlows(n){const flows=[...(n.active_flows||[]),...(n.completed_flows||[])].slice(-100).reverse();$('flowCount').textContent=flows.length+' FLOWS';$('flows').innerHTML=flows.map(f=>{const pred=f.gatv2_prediction||f.gatv2_status||'PENDING',prob=f.gatv2_anomaly_probability;return '<tr><td>'+esc(timeText(f.last_seen||f.timestamp))+'</td><td>'+esc(f.source_ip||'')+':'+esc(f.source_port==null?'':f.source_port)+'</td><td>'+esc(f.destination_ip||'')+':'+esc(f.destination_port==null?'':f.destination_port)+'</td><td>'+esc(f.protocol||'')+'</td><td>'+esc(f.total_packets==null?'—':f.total_packets)+'</td><td>'+esc(f.total_bytes==null?'—':f.total_bytes)+'</td><td class="pill'+(pred==='ATTACK'?' attack':pred==='pending'?' pending':'')+'">'+esc(pred)+'</td><td>'+((prob==null||Number.isNaN(Number(prob)))?'—':(Number(prob)*100).toFixed(2)+'%')+'</td></tr>'}).join('')||'<tr><td colspan="8" class="small">No flows captured yet.</td></tr>'}
function renderUsers(c){const users=c.behavior||{};$('userRows').innerHTML=Object.entries(users).map(([u,b])=>'<tr><td>'+esc(u)+'</td><td>'+esc(c.client_ips&&c.client_ips[u]||'UNKNOWN')+'</td><td>'+((c.blocked||[]).includes(u)?'<span class="pill attack">BLOCKED</span>':((c.users||[]).includes(u)?'<span class="pill">ONLINE</span>':'OFFLINE'))+'</td><td>'+esc(b.total_messages||0)+'</td><td>'+esc(b.messages_per_second||0)+'</td><td>'+esc(b.risk||'SAFE')+'</td><td>'+esc(c.block_reasons&&c.block_reasons[u]||'—')+'</td><td>'+((c.blocked||[]).includes(u)?'<button type="button" data-unblock="'+esc(u)+'">UNBLOCK</button>':'—')+'</td></tr>').join('')||'<tr><td colspan="8" class="small">No chat users observed.</td></tr>';document.querySelectorAll('[data-unblock]').forEach(btn=>btn.addEventListener('click',()=>unblock(btn.getAttribute('data-unblock'))))}
function addSample(n){const t=Date.now()/1000,v=Number(n.packets_per_second||0);if(!samples.length||t-samples[samples.length-1].t>=1.8)samples.push({t:t,v:v});samples=samples.filter(p=>p.t>=t-60).slice(-sampleLimit);drawGraph()}
async function unblock(user){const r=await fetch('/api/admin/unblock/'+encodeURIComponent(user),{method:'POST',headers:{'X-Admin-Token':$('adminToken').value}});if(!r.ok){const body=await r.json().catch(()=>({}));alert(body.detail||'Unblock failed');return}await refresh()}
async function refresh(){try{const rs=await Promise.all([fetch('/api/chat/state',{cache:'no-store'}),fetch('/api/network/state',{cache:'no-store'})]);if(!rs[0].ok||!rs[1].ok)throw new Error('API returned '+rs[0].status+' / '+rs[1].status);const c=await rs[0].json(),n=await rs[1].json();chatState=c;networkState=n;mergeEvents(c.events||[]);$('pps').textContent=formatRate(n.packets_per_second);$('bps').textContent=formatBytes(n.bytes_per_second);$('active').textContent=(n.active_flows||[]).length;$('analyses').textContent=n.gatv2_analyses==null?'—':n.gatv2_analyses;$('anomalies').textContent=n.gatv2_anomalies==null?'—':n.gatv2_anomalies;$('users').textContent=(c.users||[]).length;$('blocked').textContent=(c.blocked||[]).length;$('mps').textContent=formatRate(c.messages_per_second);$('newFlows').textContent=events.filter(x=>x.type==='flow_started'&&Date.now()/1000-(x.timestamp||0)<=60).length;$('captureStatus').textContent='Capture: '+(n.capture||'unknown')+' · GATv2: '+(n.gatv2||'unknown')+' · Pending inference flows: '+(n.pending_flows||0)+(n.capture_error?' · '+n.capture_error:'')+(n.gatv2_error?' · '+n.gatv2_error:'');$('interfaceInfo').textContent='CAPTURE INTERFACE: '+(n.interface||'NOT SELECTED');$('updatedAt').textContent='UPDATED: '+new Date().toLocaleTimeString();renderBanner(n);renderIncident(n);renderTimeline();renderTerminal();renderTopology(n);renderFlows(n);renderUsers(c);addSample(n)}catch(e){$('captureStatus').textContent='API UNAVAILABLE: '+e.message;$('liveIndicator').className='live wait';$('liveIndicator').textContent='API ERROR';$('warningBanner').className='banner wait';$('bannerTitle').textContent='LIVE STATE UNAVAILABLE';$('bannerCopy').textContent='Network and security state could not be refreshed.'}}
$('refreshButton').addEventListener('click',refresh);socket=new WebSocket((location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/dashboard');socket.onmessage=e=>{try{const x=JSON.parse(e.data);if(x.type==='snapshot'){mergeEvents(x.events||[]);if(chatState)renderTerminal();return}if(x.type==='users'){if(chatState){chatState.users=x.users||[];chatState.blocked=x.blocked||[];renderUsers(chatState)}return}mergeEvents([x]);renderTerminal();renderTimeline();if(x.type==='gatv2_analysis'||x.type==='flow_started'||x.type==='flow_completed')refresh()}catch(_){}};socket.onclose=()=>{ $('liveIndicator').className='live wait';$('liveIndicator').textContent='EVENT STREAM OFFLINE'};refresh();setInterval(refresh,2000);
</script></body></html>"""

CHAT_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Chat</title><style>
body{font:16px system-ui;margin:0;background:#f2f5f8;color:#17212b}.shell{max-width:800px;margin:4vh auto;padding:20px;background:#fff;border:1px solid #dbe3ea;border-radius:12px}.row{display:flex;gap:8px;margin:10px 0}input,select,button{font:inherit;padding:10px;border:1px solid #cbd5df;border-radius:7px}input,select{flex:1;min-width:0}button{background:#126b65;color:white;border:0;cursor:pointer}button:disabled{opacity:.5}#feed{height:48vh;overflow:auto;border:1px solid #e1e7ed;border-radius:8px;padding:10px}.msg{padding:8px 4px;border-bottom:1px solid #eef1f4}.warn{color:#a23c15}.muted{color:#667582;font-size:.9em}</style></head><body><main class="shell"><h1>Local Secure Chat</h1><p class="muted">Messages go through the server and are checked by its security services.</p><div class="row"><input id="name" placeholder="Username" maxlength="24"><button id="join">Join</button></div><div id="status" class="muted">Not connected</div><div id="feed" aria-live="polite"></div><div class="row"><select id="to" aria-label="Online recipient"><option value="">Select an online user</option></select><input id="message" placeholder="Message" maxlength="2000"><button id="send" disabled>Send</button></div><script>
let ws,myName='';const $=id=>document.getElementById(id);function line(text,cls=''){const d=document.createElement('div');d.className='msg '+cls;d.textContent=text;$('feed').append(d);$('feed').scrollTop=$('feed').scrollHeight}function connect(){if(ws&&ws.readyState===WebSocket.OPEN)return;const name=$('name').value.trim();if(!/^[A-Za-z0-9_-]{2,24}$/.test(name)){ $('status').textContent='Use 2–24 letters, numbers, _ or -.';return}myName=name;ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/chat/${encodeURIComponent(name)}`);ws.onopen=()=>{$('status').textContent=`Connected as ${name}`;$('send').disabled=false};ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.type==='message')line(`${x.sender} → ${x.recipient}: ${x.text}`);else if(x.type==='warning')line(x.message,'warn');else if(x.type==='blocked'){$('status').textContent='Your account has been temporarily blocked due to suspicious activity.';line(x.message,'warn');$('send').disabled=true;ws.close()}else if(x.type==='users'){const to=$('to'),prior=to.value;to.innerHTML='<option value="">Select an online user</option>';x.users.filter(u=>u!==myName).forEach(u=>{const o=document.createElement('option');o.value=u;o.textContent=u;to.append(o)});if(x.users.includes(prior))to.value=prior;$('status').textContent=`Connected as ${myName} · Online: ${x.users.filter(u=>u!==myName).join(', ')||'no other users'}`}};ws.onclose=()=>{$('send').disabled=true;if(!$('status').textContent.startsWith('Your account has been temporarily blocked'))$('status').textContent='Disconnected'}}function send(){const recipient=$('to').value,text=$('message').value;if(!recipient){line('Select an online recipient first.','warn');return}if(ws?.readyState===WebSocket.OPEN){ws.send(JSON.stringify({recipient,text}));$('message').value=''}}$('join').onclick=connect;$('send').onclick=send;$('message').onkeydown=e=>{if(e.key==='Enter')send()};
</script></main></body></html>"""


@router.get("/chat", response_class=HTMLResponse)
async def chat_page() -> str:
    return CHAT_HTML


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page() -> str:
    return DASHBOARD_HTML


@router.get("/api/chat/state")
async def chat_state() -> dict:
    behavior = behavior_analyzer.snapshot()
    for username in set(state.clients) | set(state.blocked):
        behavior.setdefault(username, {"total_messages": 0, "messages_last_30_seconds": 0,
                                       "messages_per_second": 0.0, "messages_per_minute": 0,
                                       "unique_recipients": 0, "risk": "SAFE"})
    now = time.time()
    return {"users": sorted(state.clients), "blocked": sorted(state.blocked), "block_reasons": state.block_reasons,
            "client_ips": dict(state.client_ips),
            "behavior": behavior, "messages": len(state.recent),
            "messages_per_second": sum(now - item.get("timestamp", 0) <= 1 for item in state.recent),
            "messages_last_30_seconds": sum(now - item.get("timestamp", 0) <= 30 for item in state.recent),
            "events": list(state.events)}


@router.websocket("/ws/dashboard")
async def dashboard_socket(ws: WebSocket) -> None:
    await ws.accept()
    dashboard_clients.add(ws)
    await ws.send_json({"type": "snapshot", "users": sorted(state.clients), "blocked": sorted(state.blocked), "events": list(state.events), "block_reasons": state.block_reasons})
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        dashboard_clients.discard(ws)


@router.post("/api/admin/unblock/{user_id}")
async def unblock_user(user_id: str, x_admin_token: str | None = Header(default=None)) -> dict:
    token = os.getenv("ADMIN_TOKEN")
    if not token or x_admin_token != token:
        raise HTTPException(status_code=403, detail="Admin token is missing or invalid; configure ADMIN_TOKEN.")
    if user_id not in state.blocked:
        raise HTTPException(status_code=404, detail="User is not blocked.")
    state.blocked.remove(user_id)
    reason = state.block_reasons.pop(user_id, "")
    behavior_analyzer.reset(user_id)
    await state.event("admin_unblocked", {"username": user_id, "previous_reason": reason, "detection_source": "ADMIN"})
    await state.roster()
    return {"status": "unblocked", "username": user_id}


@router.websocket("/ws/chat/{username}")
async def chat_socket(ws: WebSocket, username: str) -> None:
    username = username.strip()
    if username in state.blocked:
        await ws.accept()
        await ws.send_json({"type": "blocked", "message": "Your account has been temporarily blocked due to suspicious activity."})
        await ws.close(code=1008)
        return
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,24}", username) or username in state.clients:
        await ws.accept()
        await ws.send_json({"type": "blocked", "message": "Username is invalid, already connected, or blocked."})
        await ws.close(code=1008)
        return
    await ws.accept()
    client_ip = ws.client.host if ws.client else "unknown"
    client_port = int(ws.client.port) if ws.client else 0
    server = ws.scope.get("server") or (None, int(os.getenv("PORT", "8000")))
    server_port = int(server[1]) if len(server) > 1 and server[1] else int(os.getenv("PORT", "8000"))
    async with state.lock:
        state.clients[username] = ws
        state.client_ips[username] = client_ip
        state.client_endpoints[username] = (client_ip, client_port, server_port)
    await state.roster()
    await state.event("user_joined", {"username": username})
    try:
        while True:
            raw = await ws.receive_json()
            recipient = str(raw.get("recipient", "")).strip()
            text = str(raw.get("text", ""))
            if len(text) > MAX_MESSAGE_LENGTH:
                await ws.send_json({"type": "warning", "message": f"Messages are limited to {MAX_MESSAGE_LENGTH} characters."})
                continue
            if not text.strip() or not recipient:
                continue
            if username in state.blocked:
                await ws.send_json({"type": "blocked", "message": "Your account is blocked."})
                break
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
                await ws.send_json({"type": "blocked", "message": "Your account has been temporarily blocked due to suspicious activity."})
                await state.event("blocked", {"username": username, "source_ip": client_ip,
                                               "reason": decision["reason"], "threat": decision})
                await state.roster()
                await ws.close(code=1008)
                break
            if decision["action"] == "BLOCK_MESSAGE":
                await ws.send_json({"type": "warning", "message": "Message rejected by the security policy.", "threat": decision})
                await state.event("message_blocked", {**record, "reason": decision["reason"]})
                continue
            peer = state.clients.get(recipient)
            if not peer:
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

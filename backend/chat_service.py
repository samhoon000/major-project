"""Small in-memory WebSocket chat and security event service."""

from __future__ import annotations

import asyncio
import re
import time
import os
from collections import defaultdict, deque
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi import HTTPException, Header
from backend.security.behavior_analyzer import BehaviorAnalyzer, BehaviorConfig

router = APIRouter()
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl"}
SUSPICIOUS_WORDS = {"verify", "login", "account", "password", "urgent", "suspended", "payment"}
MAX_MESSAGE_LENGTH = 2000


class ChatState:
    def __init__(self) -> None:
        self.clients: dict[str, WebSocket] = {}
        self.blocked: set[str] = set()
        self.block_reasons: dict[str, str] = {}
        self.recent: deque[dict[str, Any]] = deque(maxlen=200)
        self.events: deque[dict[str, Any]] = deque(maxlen=500)
        self.sent: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self.lock = asyncio.Lock()

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


DASHBOARD_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Security Dashboard</title><style>
body{font:14px system-ui;margin:24px auto;max-width:1200px;padding:0 18px;background:#f3f6f9;color:#17212b}h1{margin:0}h2{font-size:18px}.muted{color:#617080}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}.card,section{background:#fff;border:1px solid #dbe3ea;border-radius:10px;padding:14px}.card b{display:block;font-size:23px;margin-top:4px}section{margin:14px 0;overflow:auto}table{border-collapse:collapse;width:100%;min-width:740px}th,td{text-align:left;padding:8px;border-bottom:1px solid #e7edf2}th{color:#52606e}.event{padding:7px;border-bottom:1px solid #e7edf2}input,button{padding:8px;border:1px solid #cbd5df;border-radius:6px}button{background:#126b65;color:white;cursor:pointer}</style></head><body>
<h1>Security Admin Dashboard</h1><p class="muted">GATv2 analyzes captured network flows. The behavior analyzer detects bulk messaging. <a href="/attack-lab">Open Network Attack Lab</a></p>
<div class="cards"><div class="card">Connected users<b id="users">0</b></div><div class="card">Messages observed<b id="messages">0</b></div><div class="card">Active flows<b id="active">0</b></div><div class="card">Packets / sec<b id="pps">0</b></div><div class="card">Bytes / sec<b id="bps">0</b></div><div class="card">Messages / sec<b id="mps">0</b></div><div class="card">GATv2 analyses<b id="analyses">0</b></div><div class="card">GATv2 anomalies<b id="anomalies">0</b></div><div class="card">Latest prediction<b id="latest">None</b></div><div class="card">Suspicious users<b id="suspicious">0</b></div><div class="card">Blocked users<b id="blocked">0</b></div><div class="card">Security events<b id="eventCount">0</b></div></div>
<section><h2>User Security</h2><table><thead><tr><th>Username</th><th>Status</th><th>Messages</th><th>Messages/sec</th><th>Messages/30 sec</th><th>Risk</th><th>Reason</th><th>Action</th></tr></thead><tbody id="userRows"></tbody></table><p><input id="adminToken" type="password" placeholder="Admin token"> <span class="muted">Set ADMIN_TOKEN on server to enable unblock.</span></p></section>
<section><h2>Network Security / ML Enforcement</h2><p id="latestAnalysis">Loading real capture and GATv2 state.</p><table><thead><tr><th>IP</th><th>Reason</th><th>Probability</th><th>First detected</th><th>Blocked until</th><th>Status</th><th>Action</th></tr></thead><tbody id="networkBlocks"></tbody></table></section>
<section><h2>Live Network Flows</h2><table><thead><tr><th>Timestamp</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Duration</th><th>Packets/sec</th><th>Bytes/sec</th><th>GATv2</th><th>Probability</th></tr></thead><tbody id="flows"></tbody></table><div class="muted" id="captureStatus">Loading capture status</div></section><section><h2>Security Events</h2><div id="events"></div></section>
<script>
const missingDashboardElements=new Set();const $=id=>{const element=document.getElementById(id);if(element)return element;if(!missingDashboardElements.has(id)){console.warn(`Dashboard element #${id} is missing`);missingDashboardElements.add(id)}return {textContent:"",innerHTML:"",value:"",disabled:true}};let ev=[],analyses=0,anomalies=0;const ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/dashboard`);ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.type==='snapshot'){ev=x.events||[];renderEvents();return}ev.unshift(x);ev=ev.slice(0,150);renderEvents();refresh()};function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function renderEvents(){analyses=ev.filter(x=>x.type==='gatv2_analysis').length;anomalies=ev.filter(x=>x.type==='gatv2_analysis'&&x.gatv2_prediction==='ATTACK').length;$('events').innerHTML=ev.slice(0,80).map(x=>`<div class="event"><b>${new Date((x.timestamp||0)*1000).toLocaleTimeString()}</b> · ${esc(x.type)} · ${esc(x.username||x.sender||x.source_ip||'')} · ${esc(x.reason||x.gatv2_prediction||x.text||'')} · ${esc(x.detection_source||'')}</div>`).join('');$('eventCount').textContent=ev.filter(x=>['blocked','threat','gatv2_analysis','network_flow'].includes(x.type)).length;$('analyses').textContent=analyses;$('anomalies').textContent=anomalies}
async function refresh(){try{const [c,n]=await Promise.all([fetch('/api/chat/state').then(r=>r.json()),fetch('/api/network/state').then(r=>r.json())]);$('users').textContent=c.users.length;$('messages').textContent=c.messages;$('mps').textContent=c.messages_per_second;$('blocked').textContent=c.blocked.length;$('active').textContent=n.active_flows.length;$('pps').textContent=n.packets_per_second;$('bps').textContent=n.bytes_per_second;$('latest').textContent=(ev.find(x=>x.type==='gatv2_analysis')||{}).gatv2_prediction||'None';$('suspicious').textContent=Object.values(c.behavior).filter(x=>x.risk==='SUSPICIOUS'||x.risk==='BLOCK').length;$('userRows').innerHTML=Object.entries(c.behavior).map(([u,b])=>`<tr><td>${esc(u)}</td><td>${c.blocked.includes(u)?'BLOCKED':c.users.includes(u)?'ONLINE':'OFFLINE'}</td><td>${b.total_messages}</td><td>${b.messages_per_second}</td><td>${b.messages_last_30_seconds}</td><td>${esc(b.risk)}</td><td>${esc(c.block_reasons[u]||'—')}</td><td>${c.blocked.includes(u)?`<button onclick="unblock('${esc(u)}')">Unblock</button>`:'—'}</td></tr>`).join('');const fs=[...n.active_flows,...n.completed_flows].slice(-100).reverse();$('flows').innerHTML=fs.map(f=>`<tr><td>${new Date((f.last_seen||0)*1000).toLocaleTimeString()}</td><td>${esc(f.source_ip)}:${f.source_port}</td><td>${esc(f.destination_ip)}:${f.destination_port}</td><td>${esc(f.protocol)}</td><td>${f.total_packets}</td><td>${f.total_bytes}</td><td>${Number(f.duration).toFixed(2)}s</td><td>${Number(f.packets_per_second).toFixed(2)}</td><td>${Number(f.bytes_per_second).toFixed(2)}</td><td>${esc(f.gatv2_prediction||f.gatv2_status||'pending')}</td><td>${f.gatv2_anomaly_probability==null?'—':(f.gatv2_anomaly_probability*100).toFixed(1)+'%'}</td></tr>`).join('');$('captureStatus').textContent=`Capture: ${n.capture} · Interface: ${n.interface||'not selected'} · ${n.capture_error||''} · GATv2: ${n.gatv2}${n.gatv2_error?' · '+n.gatv2_error:''}`;renderEvents()}catch(e){$('captureStatus').textContent='Dashboard API unavailable: '+e}}
async function unblock(user){const r=await fetch('/api/admin/unblock/'+encodeURIComponent(user),{method:'POST',headers:{'X-Admin-Token':$('adminToken').value}});alert(r.ok?`${user} unblocked`:((await r.json()).detail||'Unblock failed'));refresh()}async function unblockNetwork(ip){const r=await fetch('/api/admin/network-unblock/'+encodeURIComponent(ip),{method:'POST',headers:{'X-Admin-Token':$('adminToken').value}});alert(r.ok?`${ip} unblocked`:((await r.json()).detail||'Unblock failed'));refresh()}async function networkRefresh(){try{const n=await fetch('/api/network/state').then(r=>r.json());const f=n.latest_analysis;$('latestAnalysis').textContent=f?`${f.gatv2_prediction} · probability ${Number(f.gatv2_anomaly_probability).toFixed(4)} · threshold ${Number(f.gatv2_threshold).toFixed(4)} · ${f.source_ip}:${f.source_port} → ${f.destination_ip}:${f.destination_port} · ${f.protocol} · flow ${f.flow_id}`:`GATv2 ${n.gatv2}: ${n.gatv2_error||'waiting for a finalized flow'}`;$('networkBlocks').innerHTML=n.blocked_sources.map(b=>`<tr><td>${esc(b.source_ip)}</td><td>${esc(b.reason)}</td><td>${Number(b.anomaly_probability).toFixed(4)}</td><td>${new Date(b.first_detected*1000).toLocaleString()}</td><td>${new Date(b.blocked_until*1000).toLocaleString()}</td><td>${esc(b.status)}</td><td>${b.status==='BLOCKED'?`<button onclick="unblockNetwork('${esc(b.source_ip)}')">Unblock</button>`:'—'}</td></tr>`).join('')}catch(e){}}setInterval(()=>{refresh();networkRefresh()},2000);refresh();networkRefresh();
</script></body></html>"""


CHAT_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secure Chat</title><style>
body{font:16px system-ui;margin:0;background:#f2f5f8;color:#17212b}.shell{max-width:800px;margin:4vh auto;padding:20px;background:#fff;border:1px solid #dbe3ea;border-radius:12px}.row{display:flex;gap:8px;margin:10px 0}input,select,button{font:inherit;padding:10px;border:1px solid #cbd5df;border-radius:7px}input,select{flex:1;min-width:0}button{background:#126b65;color:white;border:0;cursor:pointer}button:disabled{opacity:.5}#feed{height:48vh;overflow:auto;border:1px solid #e1e7ed;border-radius:8px;padding:10px}.msg{padding:8px 4px;border-bottom:1px solid #eef1f4}.warn{color:#a23c15}.muted{color:#667582;font-size:.9em}</style></head><body><main class="shell"><h1>Local Secure Chat</h1><p class="muted">Messages go through the server and are checked by its security services.</p><div class="row"><input id="name" placeholder="Username" maxlength="24"><button id="join">Join</button></div><div id="status" class="muted">Not connected</div><div id="feed" aria-live="polite"></div><div class="row"><select id="to" aria-label="Online recipient"><option value="">Select an online user</option></select><input id="message" placeholder="Message" maxlength="2000"><button id="send" disabled>Send</button></div><script>
let ws,myName='';const $=id=>document.getElementById(id);function line(text,cls=''){const d=document.createElement('div');d.className='msg '+cls;d.textContent=text;$('feed').append(d);$('feed').scrollTop=$('feed').scrollHeight}function connect(){if(ws&&ws.readyState===WebSocket.OPEN)return;const name=$('name').value.trim();if(!/^[A-Za-z0-9_-]{2,24}$/.test(name)){ $('status').textContent='Use 2–24 letters, numbers, _ or -.';return}myName=name;ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/chat/${encodeURIComponent(name)}`);ws.onopen=()=>{$('status').textContent=`Connected as ${name}`;$('send').disabled=false};ws.onmessage=e=>{const x=JSON.parse(e.data);if(x.type==='message')line(`${x.sender} → ${x.recipient}: ${x.text}`);else if(x.type==='warning')line(x.message,'warn');else if(x.type==='blocked'){$('status').textContent='Your account has been temporarily blocked due to suspicious activity.';line(x.message,'warn');$('send').disabled=true;ws.close()}else if(x.type==='users'){const to=$('to'),prior=to.value;to.innerHTML='<option value="">Select an online user</option>';x.users.filter(u=>u!==myName).forEach(u=>{const o=document.createElement('option');o.value=u;o.textContent=u;to.append(o)});if(x.users.includes(prior))to.value=prior;$('status').textContent=`Connected as ${myName} · Online: ${x.users.filter(u=>u!==myName).join(', ')||'no other users'}`}};ws.onclose=()=>{$('send').disabled=true;if(!$('status').textContent.startsWith('Your account has been temporarily blocked'))$('status').textContent='Disconnected'}}function send(){const recipient=$('to').value,text=$('message').value;if(!recipient){line('Select an online recipient first.','warn');return}if(ws?.readyState===WebSocket.OPEN){ws.send(JSON.stringify({recipient,text}));$('message').value=''}}$('join').onclick=connect;$('send').onclick=send;$('message').onkeydown=e=>{if(e.key==='Enter')send()};
</script></main></body></html>"""


@router.get("/chat", response_class=HTMLResponse)
async def chat_page() -> str:
    return CHAT_HTML


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> str:
    from backend.network.runtime import network_runtime
    if request.client:
        network_runtime.enforcement.admin_ips.add(request.client.host)
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
            "behavior": behavior, "messages": len(state.recent),
            "messages_per_second": sum(now - item.get("timestamp", 0) <= 1 for item in state.recent),
            "messages_last_30_seconds": sum(now - item.get("timestamp", 0) <= 30 for item in state.recent),
            "events": list(state.events)}


@router.websocket("/ws/dashboard")
async def dashboard_socket(ws: WebSocket) -> None:
    await ws.accept()
    dashboard_clients.add(ws)
    from backend.network.runtime import network_runtime
    if ws.client:
        network_runtime.enforcement.admin_ips.add(ws.client.host)
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


@router.post("/api/admin/network-unblock/{source_ip}")
async def unblock_network_source(source_ip: str, x_admin_token: str | None = Header(default=None)) -> dict:
    token = os.getenv("ADMIN_TOKEN")
    if not token or x_admin_token != token:
        raise HTTPException(status_code=403, detail="Admin token is missing or invalid; configure ADMIN_TOKEN.")
    from backend.network.runtime import network_runtime
    try:
        block = network_runtime.enforcement.unblock(source_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid source IP address.")
    if block is None:
        raise HTTPException(status_code=404, detail="Source is not currently blocked.")
    await state.event("BLOCK_UNBLOCKED", {**block.__dict__, "action": "ADMIN_UNBLOCK"})
    return {"status": block.status, "source_ip": block.source_ip}


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
    async with state.lock:
        state.clients[username] = ws
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
            security = inspect_message(text)
            record = {"sender": username, "recipient": recipient, "source_ip": client_ip, "text": text, "security": security, "behavior": behavior_details}
            if security["suspicious_url"]:
                await ws.send_json({"type": "warning", "message": "Message blocked: URL has multiple suspicious indicators."})
                await state.event("message_blocked", {**record, "reason": "suspicious_url"})
                continue
            if behavior >= 1.0:
                state.blocked.add(username)
                state.block_reasons[username] = "Bulk message flooding"
                await ws.send_json({"type": "blocked", "message": "Your account has been temporarily blocked due to suspicious activity."})
                await state.event("blocked", {"username": username, "source_ip": client_ip, "reason": "Bulk message flooding", "threat_type": "BULK_MESSAGE_FLOOD", "detection_source": "BEHAVIOR", "risk": "HIGH", "behavior": behavior_details})
                await ws.close(code=1008)
                break
            peer = state.clients.get(recipient)
            if not peer:
                await ws.send_json({"type": "warning", "message": "Recipient is not connected."})
                continue
            delivered = {"type": "message", **record, "timestamp": time.time()}
            state.recent.append(delivered)
            await ws.send_json(delivered)
            await peer.send_json(delivered)
            await state.event("message", record)
            if behavior >= 0.5:
                await ws.send_json({"type": "warning", "message": "Unusually rapid or repetitive messages detected."})
                await state.event("threat", {"sender": username, "recipient": recipient, "reason": "Bulk message behavior warning", "threat_type": "BULK_MESSAGE_BEHAVIOR", "detection_source": "BEHAVIOR", "risk": "MEDIUM", "behavior": behavior_details})
    except WebSocketDisconnect:
        pass
    finally:
        async with state.lock:
            if state.clients.get(username) is ws:
                state.clients.pop(username, None)
        await state.roster()
        await state.event("user_left", {"username": username})

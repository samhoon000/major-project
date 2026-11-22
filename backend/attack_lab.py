"""Phone-originated, tightly bounded traffic demonstrations for the local lab."""
from __future__ import annotations

import ipaddress
import os
import threading
import time
from collections import deque

from fastapi import APIRouter, HTTPException, Request, Header, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.background import BackgroundTask

from backend.network.runtime import network_runtime
from backend.network.northfield_probe import enabled as probe_enabled, northfield_probe
from backend.network.port_scan import VERIFY_PATH
from backend.security.http_flood import PolicyCheckConfig, RunConfig, http_flood_simulator, policy_verification

router = APIRouter()

_BURST_LIMIT = 50
_BURST_WINDOW_SECONDS = 15.0
_burst_lock = threading.Lock()
_burst_times: dict[str, deque[float]] = {}


def _is_private_lan_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return any(address in ipaddress.ip_network(network) for network in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    ))


def _current_lan_ipv4(runtime_interface: str | None = None) -> str:
    """Resolve the private IPv4 address for the selected/current Wi-Fi adapter."""
    try:
        from scapy.arch.windows import get_windows_if_list
        adapters = get_windows_if_list()
    except (ImportError, AttributeError, OSError) as exc:
        raise RuntimeError(f"Windows adapter discovery failed: {exc}") from exc

    runtime_interface = runtime_interface or network_runtime.status().get("interface") or ""
    configured_interface = os.getenv("NETWORK_INTERFACE") or os.getenv("CAPTURE_INTERFACE") or ""

    def normalized_guid(value: str) -> str:
        if "NPF_" in value.upper():
            value = value[value.upper().index("NPF_") + 4:]
        return value.strip().strip("{}").casefold()

    preferred_guid = normalized_guid(runtime_interface) if runtime_interface else ""
    configured_guid = normalized_guid(configured_interface) if configured_interface else ""
    configured_label = configured_interface.casefold()

    candidates = []
    for adapter in adapters:
        ips = [str(value).split("%", 1)[0] for value in adapter.get("ips", [])]
        private_ipv4s = [value for value in ips if _is_private_lan_ipv4(value)]
        if not private_ipv4s:
            continue
        guid = str(adapter.get("guid", "")).strip("{}").casefold()
        name = str(adapter.get("name", ""))
        description = str(adapter.get("description", ""))
        labels = {name.casefold(), description.casefold(), guid}
        is_wireless = any(token in (name + " " + description).casefold()
                          for token in ("wi-fi", "wifi", "wireless", "wlan"))
        candidates.append((adapter, private_ipv4s, guid, labels, is_wireless))

    selected = next((row for row in candidates if preferred_guid and row[2] == preferred_guid), None)
    if selected is None and configured_guid:
        selected = next((row for row in candidates if row[2] == configured_guid), None)
    if selected is None and configured_label:
        selected = next((row for row in candidates if configured_label in row[3]), None)
    if selected is None:
        wireless = [row for row in candidates if row[4]]
        if len(wireless) == 1:
            selected = wireless[0]
        elif len(candidates) == 1:
            selected = candidates[0]
        else:
            raise RuntimeError(
                "Could not uniquely identify the Wi-Fi adapter with a private IPv4. "
                "Set NETWORK_INTERFACE to the machine's Wi-Fi adapter name."
            )
    return selected[1][0]


ATTACK_LAB_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>Network Attack Lab</title>
  <style>
    :root{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#17212b;background:#f2f5f8;font-synthesis:none}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;padding:24px 14px;background:linear-gradient(145deg,#eaf5f3,#f2f5f8 48%,#edf2fa)}
    main{width:min(680px,100%);margin:0 auto}.card{background:#fff;border:1px solid #dbe3ea;border-radius:16px;padding:22px;box-shadow:0 12px 32px #17212b12}
    header{margin-bottom:16px}h1{font-size:clamp(1.8rem,7vw,2.5rem);line-height:1.1;margin:0 0 8px;letter-spacing:0}p{line-height:1.55}.intro{color:#536373;margin:0}
    .state-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:20px 0}.state{border:1px solid #dbe3ea;border-radius:10px;padding:12px;min-width:0}.label{display:block;font-size:.8rem;color:#627181;margin-bottom:5px}.value{font-weight:750;overflow-wrap:anywhere}.pill{display:inline-block;border-radius:99px;padding:3px 9px;background:#edf2f6;font-size:.86rem}
    .actions{display:grid;gap:10px;margin:18px 0}.actions button{min-height:48px;width:100%;border:0;border-radius:9px;padding:12px 16px;font:inherit;font-weight:750;color:#fff;background:#126b65;cursor:pointer}.actions button:nth-child(2){background:#365ca8}.actions button.stop{background:#9a3412}.actions button:disabled{opacity:.45;cursor:not-allowed}
    .status{padding:12px;border-radius:9px;background:#f1f5f9;min-height:48px}.fine{color:#5b6877;font-size:.9rem;margin:12px 0}.links{display:flex;gap:18px;flex-wrap:wrap;margin-top:18px}.links a{color:#135e77;font-weight:650}
    @media(min-width:520px){.card{padding:28px}.state-grid{grid-template-columns:repeat(4,1fr)}.actions{grid-template-columns:1fr 1fr 1fr}}
  </style>
</head>
<body>
<main>
  <section class="card" aria-labelledby="title">
    <header><h1 id="title">Network Attack Lab</h1><p class="intro">Authenticated demonstration. HTTP flood requests run only on the host loopback endpoint. Legacy browser tests are available locally.</p></header>
    <p class="links"><a href="/attack-lab">Attack Lab overview</a></p>
    <div class="state-grid" aria-live="polite">
      <div class="state"><span class="label">Target</span><span class="value" id="target">Resolving…</span></div>
      <div class="state"><span class="label">Capture</span><span class="value pill" id="capture">CHECKING</span></div>
      <div class="state"><span class="label">GATv2</span><span class="value pill" id="gatv2">CHECKING</span></div>
      <div class="state"><span class="label">Test status</span><span class="value pill" id="testStatus">READY</span></div>
    </div>
    <div class="actions">
      <button id="portScan" type="button" disabled>Port Scan Test</button>
      <button id="trafficBurst" type="button" disabled>Traffic Burst Test</button>
      <button id="stopTest" class="stop" type="button" disabled>Stop Test</button>
    </div>
    <div id="progress" class="status" role="status" aria-live="polite">Checking the live capture service…</div>
    <p class="fine">Port Scan sends at most 101 browser requests to this laptop on ports 8000–8100, one every 250 ms, for no more than 30 seconds. The browser hides connection details; view real captured flows and GATv2 results in the dashboard.</p>
    <p class="fine">Traffic Burst sends at most 40 small requests to this app over 8 seconds. The server also limits this endpoint to 50 requests per source in any 15-second window. No test data is saved.</p>
    <!-- HTTP_FLOOD_PANEL -->
    <nav class="links"><a href="/dashboard">Live dashboard</a><a href="/chat">Secure chat</a></nav>
  </section>
</main>
<script>
(() => {
  "use strict";
  const MAX_SCAN_REQUESTS = 101;
  const SCAN_INTERVAL_MS = 250;
  const SCAN_MAX_DURATION_MS = 30000;
  const BURST_REQUESTS = 40;
  const BURST_INTERVAL_MS = 200;
  const BURST_MAX_DURATION_MS = 10000;
  const $ = (id) => document.getElementById(id);
  let targetIp = null;
  let testTimer = null;
  let hardStopTimer = null;
  let testControllers = new Set();
  let running = false;
  let starting = false;
  let runtimeTimer = null;

  async function authorizeLab() {
    if (!window.SentinelAuth.local) {
      document.getElementById("hf-error").textContent="Browser scan and burst tests are local-only. Use the server-side HTTP Flood controls remotely.";
      return false;
    }
    const token = document.getElementById("hf-token").value.trim();
    try {
      const response = await window.SentinelAuth.fetch("/api/attack-lab/http-flood/authorize", {method:"POST", headers:token?{"X-Admin-Token":token}:{}});
      if (!response.ok) throw new Error("Local administrator authorization required.");
      return true;
    } catch (error) { document.getElementById("hf-error").textContent = error.message; return false; }
  }
  function setTestStatus(value) { $("testStatus").textContent = value; }
  function setButtons(enabled) {
    $("portScan").disabled = !enabled;
    $("trafficBurst").disabled = !enabled;
    $("stopTest").disabled = enabled || !running;
  }
  function finishTest(message) {
    if (testTimer !== null) clearTimeout(testTimer);
    if (hardStopTimer !== null) clearTimeout(hardStopTimer);
    testTimer = null;
    hardStopTimer = null;
    for (const controller of testControllers) controller.abort();
    testControllers.clear();
    running = false;
    setTestStatus("COMPLETED");
    setButtons(true);
    $("progress").textContent = message;
  }
  function startTest() {
    running = true;
    setTestStatus("RUNNING");
    setButtons(false);
  }
  function sendPhonePortRequest(port) {
    const controller = new AbortController();
    testControllers.add(controller);
    const requestTimeout = setTimeout(() => controller.abort(), 1500);
    fetch(`http://${targetIp}:${port}/`, {method:"GET", mode:"no-cors", cache:"no-store", redirect:"manual", signal:controller.signal})
      .catch(() => {})
      .finally(() => { clearTimeout(requestTimeout); testControllers.delete(controller); });
  }
  async function startPortScan() {
    if (running || starting) return;
    if (!(await authorizeLab())) return;
    starting = true;
    $("portScan").disabled = true;
    $("trafficBurst").disabled = true;
    await refreshRuntime();
    if (!starting || !targetIp) { starting = false; return; }
    const ports = Array.from({length:MAX_SCAN_REQUESTS}, (_, index) => 8000 + index);
    if (!window.confirm(`Send up to ${ports.length} TCP connection attempts from this phone to ${targetIp}, ports 8000–8100?`)) {
      starting = false;
      $("portScan").disabled = false;
      $("trafficBurst").disabled = false;
      return;
    }
    if (!starting) return;
    starting = false;
    startTest();
    const deadline = Date.now() + SCAN_MAX_DURATION_MS;
    let index = 0;
    const attempt = () => {
      if (!running) return;
      if (Date.now() >= deadline || index >= ports.length) {
        finishTest(`Completed ${index} of ${ports.length} fixed-port requests from this phone. Check the live dashboard for captured flows.`);
        return;
      }
      sendPhonePortRequest(ports[index]);
      index += 1;
      $("progress").textContent = `Port Scan Test: ${index}/${ports.length} requests sent from this phone to ${targetIp}.`;
      testTimer = setTimeout(attempt, SCAN_INTERVAL_MS);
    };
    hardStopTimer = setTimeout(() => finishTest("Maximum 30-second test duration reached; outstanding browser requests were stopped."), SCAN_MAX_DURATION_MS);
    attempt();
  }
  async function startTrafficBurst() {
    if (running || starting) return;
    if (!(await authorizeLab())) return;
    starting = true;
    $("portScan").disabled = true;
    $("trafficBurst").disabled = true;
    await refreshRuntime();
    if (!starting || !targetIp) { starting = false; return; }
    if (!window.confirm(`Send up to ${BURST_REQUESTS} requests from this phone to the local lab endpoint over about ${BURST_REQUESTS * BURST_INTERVAL_MS / 1000} seconds?`)) {
      starting = false;
      $("portScan").disabled = false;
      $("trafficBurst").disabled = false;
      return;
    }
    if (!starting) return;
    starting = false;
    startTest();
    const deadline = Date.now() + BURST_MAX_DURATION_MS;
    let sent = 0;
    const sendNext = () => {
      if (!running) return;
      if (Date.now() >= deadline || sent >= BURST_REQUESTS) {
        finishTest(`Completed ${sent} of ${BURST_REQUESTS} requests. Check the live dashboard for captured flows.`);
        return;
      }
      const controller = new AbortController();
      testControllers.add(controller);
      window.SentinelAuth.fetch("/api/attack-lab/burst", {method:"POST", headers:{"Content-Type":"application/json", "X-Admin-Token":document.getElementById("hf-token").value.trim()}, body:JSON.stringify({sequence:sent + 1}), cache:"no-store", signal:controller.signal})
        .then((response) => { if (response.status === 429) finishTest("The server reached its per-source burst limit."); })
        .catch(() => {})
        .finally(() => testControllers.delete(controller));
      sent += 1;
      $("progress").textContent = `Traffic Burst Test: ${sent}/${BURST_REQUESTS} requests sent from this phone.`;
      testTimer = setTimeout(sendNext, BURST_INTERVAL_MS);
    };
    hardStopTimer = setTimeout(() => finishTest("Maximum 10-second burst duration reached; outstanding requests were stopped."), BURST_MAX_DURATION_MS);
    sendNext();
  }
  async function refreshRuntime() {
    if (!window.SentinelAuth.canView) return;
    if (!window.SentinelAuth.local) {
      $("portScan").disabled=true; $("trafficBurst").disabled=true;
      $("progress").textContent="Remote mode: use HTTP Flood below. Browser-originated scan/burst controls remain local-only.";
      return;
    }
    try {
      const response = await fetch("/api/attack-lab/status", {cache:"no-store"});
      const status = await response.json();
      if (!response.ok) throw new Error(status.detail || "Runtime status unavailable");
      targetIp = status.target_ip;
      $("target").textContent = targetIp;
      $("capture").textContent = String(status.capture || "unavailable").toUpperCase();
      $("gatv2").textContent = String(status.gatv2 || "unavailable").toUpperCase();
      if (!running && !starting) {
        const ready = Boolean(targetIp);
        $("portScan").disabled = !ready;
        $("trafficBurst").disabled = !ready;
      }
      if (status.capture !== "running") $("progress").textContent = `Capture is ${status.capture || "unavailable"}. A test may run, but the dashboard can only show traffic that the capture interface receives.`;
    } catch (error) {
      targetIp = null;
      $("target").textContent = "Unavailable";
      $("capture").textContent = "UNAVAILABLE";
      $("gatv2").textContent = "UNAVAILABLE";
      $("portScan").disabled = true;
      $("trafficBurst").disabled = true;
      if (!running) $("progress").textContent = `Lab status unavailable: ${error.message}`;
    }
  }
  $("portScan").addEventListener("click", startPortScan);
  $("trafficBurst").addEventListener("click", startTrafficBurst);
  $("stopTest").addEventListener("click", () => finishTest("Test stopped; pending browser requests were aborted."));
  refreshRuntime();
  runtimeTimer = setInterval(refreshRuntime, 2000);
  window.addEventListener("pagehide", () => {
    if (runtimeTimer !== null) clearInterval(runtimeTimer);
    starting = false;
    if (running) finishTest("Page closed; test requests were stopped.");
  });
})();
</script>
</body>
</html>"""


@router.get("/attack-lab", response_class=HTMLResponse)
def attack_lab_page(request: Request) -> str:
    from backend.http_flood_ui import http_flood_panel
    from backend.security.demo_access import boundary, demo_security, is_remote_operator_console
    from backend.security_ui import security_panel

    local = boundary(request).local
    remote_console = is_remote_operator_console(request) and demo_security.can_view(request)
    if request.query_params.get("view") == "northfield":
        if not local or not probe_enabled():
            raise HTTPException(404)
        from backend.console import FILES, wrap_existing

        document = (FILES / "northfield-probe.html").read_text(encoding="utf-8")
        script = (FILES / "northfield-probe.js").read_text(encoding="utf-8")
        return wrap_existing(request, "lab", document.replace("/* probe script */", script))
    if local:
        from backend.console import FILES

        document = (FILES / "attack-lab.html").read_text(encoding="utf-8")
        style = (FILES / "layout.css").read_text(encoding="utf-8")
        script = "\n".join((FILES / name).read_text(encoding="utf-8")
                           for name in ("layout.js", "attack-lab.js", "port-scan.js"))
        return document.replace("/* lab styles */", style).replace("/* lab script */", script)
    if remote_console and request.query_params.get("view") != "legacy":
        from backend.console import wrap_existing
        document = """<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack Lab · Sentinel AI</title>
<style>
  body { margin:0; background:#080e0b; color:#edf4ff; font:16px system-ui,sans-serif; }
  main { max-width:720px; margin:auto; padding:clamp(16px,5vw,48px); }
  section { background:#101b2b; border:1px solid #324763; border-radius:16px; padding:24px; }
  h1 { font-size:clamp(2rem,5vw,3rem); margin:12px 0; }
  h2 { font-size:1.3rem; }
  p { color:#b7c8de; line-height:1.55; }
  a { color:#a9d9ff; }
  nav { display:flex; flex-wrap:wrap; gap:12px 24px; margin-top:24px; }
</style>
<main>
  <h1>Attack Lab</h1>
  <section aria-labelledby="northfield-target">
    <h2 id="northfield-target">Northfield Student Portal</h2>
    <p>Watch signed portal traffic, detection evidence, and policy status in Monitored Applications.</p>
    <nav aria-label="Lab destinations">
      <!-- northfield probe -->
      <a class="console-link" href="/dashboard/applications?app=northfield-staging">View Live Monitoring</a>
    </nav>
    <!-- lab access -->
  </section>
</main>
</html>"""
        return wrap_existing(request, "lab", document.replace(
            "<!-- lab access -->", "<p>The local policy check is available on the host computer.</p>"))
    return ATTACK_LAB_HTML.replace("</header>", "</header>" + security_panel(), 1).replace("<!-- HTTP_FLOOD_PANEL -->", http_flood_panel(controls=True))


def require_probe_session(request: Request):
    from backend.security.demo_access import boundary, demo_security

    if not probe_enabled() or not boundary(request).local:
        raise HTTPException(404)
    if not demo_security.session(request):
        raise HTTPException(401, "Operator sign-in required")


@router.get("/api/attack-lab/northfield-probe")
async def probe_state(request: Request):
    require_probe_session(request)
    return northfield_probe.snapshot(network_runtime.status())


@router.post("/api/attack-lab/northfield-probe/{action}")
async def probe_command(request: Request, action: str):
    from backend.telemetry.dashboard import require_operator

    require_probe_session(request)
    require_operator(request)
    if request.query_params or request.headers.get("content-length") not in (None, "0") or request.headers.get("transfer-encoding"):
        raise HTTPException(422, "The probe does not take target or workload parameters")
    if action == "start":
        run_id = northfield_probe.start()
        if run_id is None:
            raise HTTPException(429, "Wait for the probe cooldown")
        return {"run_id": run_id}
    if action == "stop":
        await northfield_probe.stop()
    elif action == "reset":
        await northfield_probe.reset()
    else:
        raise HTTPException(404)
    return {"status": action}


@router.get("/api/attack-lab/http-flood-target")
async def http_flood_target(request: Request) -> dict:
    return {"status": "ok", "run_id": request.state.http_lab_run_id}


@router.get("/api/attack-lab/verification")
async def verification_state(request: Request):
    from backend.security.demo_access import boundary

    if not boundary(request).local:
        raise HTTPException(404)
    return policy_verification.get_state()


@router.get("/api/attack-lab/port-scan")
async def port_scan_snapshot(request: Request):
    from backend.security.demo_access import boundary, demo_security

    if not boundary(request).local or not demo_security.can_view(request):
        raise HTTPException(404)
    capture = network_runtime.capture
    return {**network_runtime.port_scan.snapshot(),
            "capture": capture.status if capture else "unavailable",
            "interface": capture.adapter_name if capture else None}


@router.post(VERIFY_PATH)
async def port_scan_verify(request: Request):
    from backend.security.demo_access import boundary, demo_security

    if not boundary(request).local or not request.client:
        raise HTTPException(404)
    demo_security.check_origin(request, required=True)
    listener = request.scope.get("server")
    pair = (request.client.host, listener[0]) if listener else None
    monitor = network_runtime.port_scan
    alert_id = monitor.restriction(pair) if pair else None
    if alert_id:
        return JSONResponse({"status": "restricted", "alert_id": alert_id, "scope": VERIFY_PATH},
                            status_code=429, background=BackgroundTask(monitor.record_rejection, pair, alert_id))
    return {"status": "allowed", "scope": VERIFY_PATH}


def require_verification_control(request: Request):
    from backend.security.demo_access import boundary, demo_security

    if not boundary(request).local:
        raise HTTPException(404)
    demo_security.check_origin(request, required=True)
    if request.query_params:
        raise HTTPException(422, "The policy check takes no query parameters")


@router.post("/api/attack-lab/verification/start", dependencies=[Depends(require_verification_control)])
async def verification_start(request: Request, config: PolicyCheckConfig | None = None):
    server = request.scope.get("server")
    if not server or not server[1]:
        raise HTTPException(503, "Cannot determine the local listener port")
    host = "[::1]" if server[0] == "::1" else "127.0.0.1"
    try:
        return await policy_verification.start_check(f"http://{host}:{server[1]}", config)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/api/attack-lab/verification/{action}", dependencies=[Depends(require_verification_control)])
async def verification_command(request: Request, action: str):
    if (request.headers.get("content-length") not in (None, "0")
            or request.headers.get("transfer-encoding") or await request.body()):
        raise HTTPException(422, "This action takes no parameters")
    if action == "stop":
        return await policy_verification.stop()
    if action == "reset":
        return await policy_verification.reset(stop_running=True)
    raise HTTPException(404)


async def require_lab_admin(request: Request, x_admin_token: str | None = Header(default=None)):
    from backend.security.demo_access import demo_security
    demo_security.require_control(request)


async def require_local_lab_admin(request: Request):
    from backend.security.demo_access import demo_security
    demo_security.require_control(request, local_only=True)


def lab_origin(request: Request):
    # The listening port comes from ASGI server scope, never Host or a submitted URL.
    server = request.scope.get("server")
    if not server or not server[1]:
        raise HTTPException(status_code=503, detail="Cannot determine the local listener port")
    return os.getenv("HTTP_FLOOD_BASE_URL") or f"http://127.0.0.1:{server[1]}"


@router.post("/api/attack-lab/http-flood/authorize", dependencies=[Depends(require_local_lab_admin)])
async def http_flood_authorize():
    return {"authorized": True}


@router.post("/api/attack-lab/http-flood/start", dependencies=[Depends(require_lab_admin)])
async def http_flood_start(request: Request, config: RunConfig) -> dict:
    try:
        return await http_flood_simulator.start(lab_origin(request), config)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/attack-lab/http-flood/monitor", dependencies=[Depends(require_lab_admin)])
async def http_flood_monitor(request: Request) -> dict:
    try:
        return await http_flood_simulator.prepare(lab_origin(request))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/attack-lab/http-flood/stop", dependencies=[Depends(require_lab_admin)])
async def http_flood_stop() -> dict:
    return await http_flood_simulator.stop()


@router.post("/api/attack-lab/http-flood/reset", dependencies=[Depends(require_lab_admin)])
async def http_flood_reset() -> dict:
    try:
        return await http_flood_simulator.reset()
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/attack-lab/http-flood/unblock", dependencies=[Depends(require_lab_admin)])
async def http_flood_unblock() -> dict:
    try:
        return await http_flood_simulator.unblock()
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/api/attack-lab/http-flood/state")
async def http_flood_state() -> dict:
    return http_flood_simulator.get_state()


@router.get("/api/attack-lab/http-flood/ui.js")
async def http_flood_script() -> Response:
    from backend.http_flood_ui import SCRIPT_PATH
    return Response(SCRIPT_PATH.read_text(encoding="utf-8"), media_type="text/javascript")


@router.get("/api/attack-lab/status")
def attack_lab_status() -> dict:
    runtime = network_runtime.status()
    try:
        target_ip = _current_lan_ipv4(runtime.get("interface"))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "target_ip": target_ip,
        "capture": runtime.get("capture", "unavailable"),
        "capture_interface": runtime.get("interface"),
        "capture_error": runtime.get("capture_error"),
        "gatv2": runtime.get("gatv2", "unavailable"),
        "gatv2_error": runtime.get("gatv2_error"),
    }


@router.post("/api/attack-lab/burst", status_code=204, dependencies=[Depends(require_local_lab_admin)])
def attack_lab_burst(request: Request, x_admin_token: str | None = Header(default=None)) -> Response:
    peer_host = request.client.host if request.client else ""
    from backend.chat_service import resolve_client_ip
    source_ip = resolve_client_ip(peer_host, request.headers)

    admin_token = os.getenv("ADMIN_TOKEN")
    is_admin = bool(admin_token and x_admin_token == admin_token)

    if not _is_private_lan_ipv4(source_ip) and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Traffic Burst is available only to private-LAN IPv4 clients or authenticated administrator.",
        )

    now = time.monotonic()
    with _burst_lock:
        for address, recent in list(_burst_times.items()):
            while recent and now - recent[0] >= _BURST_WINDOW_SECONDS:
                recent.popleft()
            if not recent:
                _burst_times.pop(address, None)
        requests_for_source = _burst_times.setdefault(source_ip, deque())
        if len(requests_for_source) >= _BURST_LIMIT:
            raise HTTPException(status_code=429, detail="Traffic Burst limit reached; retry after the rolling window expires.")
        requests_for_source.append(now)
    return Response(status_code=204)

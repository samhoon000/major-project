# Northfield network evidence on Windows

Sentinel’s Attack Lab can correlate one read-only Northfield health request with a captured TCP flow and the saved GATv2 checkpoint’s prediction. It records up to four runs. The health probe fixes the target at `GET http://127.0.0.1:8000/health`, sends one request per run, and enforces a 15-second cooldown and a three-second deadline. Use the disposable Northfield database below.

## Start Northfield

From the Sentinel repository root in PowerShell, use a Python environment with Northfield’s `backend/requirements-dev.txt` and the Northfield frontend dependencies installed. The commands below build the existing frontend and use a new SQLite database for fictional records. Keep this terminal open.

```powershell
$demoFolder = Join-Path $PWD.Path ('data/northfield-network-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $demoFolder | Out-Null
$env:NF_NETWORK_DB = Join-Path $demoFolder 'portal.sqlite3'
$env:NF_NETWORK_JWT = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
$env:NF_NETWORK_PASSWORD = [guid]::NewGuid().ToString('N')
$env:VITE_API_BASE_URL = '/api'

Push-Location .\.northfield-local\frontend
npm.cmd run build
Pop-Location

Write-Host "Demo student: network.student@example.com  Password: $env:NF_NETWORK_PASSWORD"
Push-Location .\.northfield-local\backend
@'
import os

import uvicorn
from app.bootstrap import initialize
from app.config import Settings
from app.main import create_app

settings = Settings(
    _env_file=None, app_env="development", database_url="", sqlite_path=os.environ["NF_NETWORK_DB"],
    jwt_secret=os.environ["NF_NETWORK_JWT"], allowed_origins="http://127.0.0.1:8000",
    seed_demo_data=True, demo_student_email="network.student@example.com",
    demo_student_password=os.environ["NF_NETWORK_PASSWORD"], demo_admin_email="network.admin@example.com",
    demo_admin_password=os.environ["NF_NETWORK_JWT"], session_cross_site=False,
    telemetry_collector_url="", telemetry_app_id="", telemetry_hmac_key="", protection_url="",
    protection_hmac_key="", protection_subject_key="", protection_production_enabled=False,
)
initialize(settings)
uvicorn.run(create_app(settings), host="127.0.0.1", port=8000, proxy_headers=False)
'@ | python -
Pop-Location
```

## Start Sentinel

In a second PowerShell terminal from the Sentinel repository root, use the existing Sentinel Python environment. If Npcap was installed with capture restricted to administrators, use an elevated terminal.

```powershell
$env:SENTINEL_NORTHFIELD_PROBE = '1'
$env:NETWORK_INTERFACE = '\Device\NPF_Loopback'
$env:NETWORK_CAPTURE_FILTER = 'ip and tcp and host 127.0.0.1 and port 8000'
$env:NETWORK_AUTO_QUARANTINE = 'false'
$env:CLOUDFLARE_TUNNEL_TOKEN = ' '
$env:CLOUDFLARE_TUNNEL_MODE = 'disabled'
$env:DASHBOARD_REMOTE_ENABLED = 'false'
$env:SENTINEL_REMOTE_CONSOLE = 'false'
$env:HTTP_FLOOD_REMOTE_ENABLED = 'false'
$env:ADMIN_TOKEN = [guid]::NewGuid().ToString('N')
Write-Host "Sentinel operator token: $env:ADMIN_TOKEN"
python -m uvicorn app:app --host 127.0.0.1 --port 8001 --no-proxy-headers
```

## Four-minute walkthrough

1. **0:00–0:45.** Open [Northfield](http://127.0.0.1:8000/) and sign in using the fictional credentials. Open [Network Evidence](http://127.0.0.1:8001/attack-lab?view=northfield) beside it. Sign in as a Sentinel operator and check that capture and GATv2 report available.
2. **0:45–1:30.** Click **Check Northfield Health** once. Show the actual HTTP status and the measured time to response headers. Note the source and destination ports in **Recorded Runs** when a captured flow matches. Close out any earlier results with **Clear Runs** before starting a new presentation.
3. **1:30–2:30.** Wait for flow expiry and the next inference batch, normally within about 20 seconds with the default settings. Show the flow ID, packet and byte counts, graph ID, score, and checkpoint threshold. In [Network Analysis](http://127.0.0.1:8001/dashboard/network), point out the live packets-per-second chart. Opening the Northfield dashboard again gives ordinary browser traffic for comparison.
4. **2:30–4:00.** Repeat the health check after the cooldown. Compare the two actual responses and predictions. If a score crosses the model threshold, describe it as a model observation. Visit the student dashboard again to show availability. The separate signed policy workflow and its verification are documented in [Northfield staging policy](HTTP_PROTECTION.md).

**Cancel** stops an outstanding probe. **Clear Runs** removes the lab’s report history and leaves the cooldown in force. `Ctrl+C` stops each local server. If capture is unavailable, record that outcome and leave the flow and model evidence blank. An HTTP 200 is not evidence of packet capture.

## Capture, preprocessing, and scope

- Npcap delivers IPv4 TCP packets to Scapy. Sentinel measures IP packet length and groups packets in both directions under a five-tuple. The probe obtains both socket endpoints from the successful HTTP connection. A flow must match those endpoints and start during the same run.
- The live tracker converts duration from seconds to microseconds and computes forward/backward packet counts, bytes per second, and packets per second. Training and live inference share the five edge feature columns, five inductive node features, nonnegative `log1p`, and saved standardizers. The graph uses an IP node for each unique address and a directed edge for each flow. Each live batch receives a graph ID after successful inference.
- CICIDS2017 supplies offline flow exports, while live inference uses runtime expiry and Scapy IP-layer byte counts. Both loopback peers share one graph node and produce a self-edge. Live graph context depends on which flows complete in a batch. These differences can affect the score. The saved `0.53` threshold and checkpoint remain the reference.
- The recorded value is the checkpoint’s softmax anomaly score. A non-chat anomaly appears in Network Analysis without creating a chat anomaly event. The health route is outside Northfield’s signed policy scope, so these runs have neither a policy OFF/ON designation nor a GATv2-triggered HTTP 429.

## Automated verification

```powershell
$env:NORTHFIELD_STAGING_CHECKOUT = Join-Path $PWD.Path '.northfield-local'
$env:SENTINEL_TEST_NPCAP = '1'  # Requires access to the Npcap loopback device.
python -m pytest -q -s tests/test_northfield_probe.py tests/test_network_enforcement.py
```

If Northfield dependencies are in a separate environment, set `NORTHFIELD_STAGING_DEPS` to that environment’s `Lib/site-packages`. The live test prints the observed model score and captured feature vector so results can be reported without inventing a classification.

### Observed integration results

Npcap captured both requests on `\Device\NPF_Loopback`. Both scores were below the checkpoint’s `0.53` threshold.

| Request | HTTP | Packets | IP bytes | Flow duration | Bytes/s | Packets/s | GATv2 |
|---|---:|---:|---:|---:|---:|---:|---|
| Authenticated dashboard stats | 200 | 13 | 1,854 | 30.31 ms | 61,158 | 428.83 | Benign, 0.2002 |
| Health probe | 200 | 13 | 1,067 | 9.18 ms | 116,230 | 1,416.11 | Benign, 0.2244 |

The health probe received HTTP headers in 9.67 ms. The authenticated dashboard stats endpoint returned HTTP 200 again after the probe. These are individual measured flows.

The separate staging-policy regression confirmed a course-access HTTP 204 before enforcement, a signed policy acknowledgment and correlated HTTP 429 for the restricted subject, HTTP 204 for a second student, and verified recovery after policy revocation. That restriction came from the application-layer policy evaluator.

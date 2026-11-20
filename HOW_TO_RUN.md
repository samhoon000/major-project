# Run Sentinel AI on Windows

The FastAPI server serves Chat, the live Dashboard, and the Attack Lab on port 8001. All three use the same process and runtime state.

## Start locally

1. Install Git and 64-bit Python 3.13.2. Install [Npcap](https://npcap.com/#download) in WinPcap-compatible mode if you want live packet capture and GATv2 inference from captured flows. Chat and the application-level demo can run without Npcap.
2. Open PowerShell and run:

   ```powershell
   git clone --branch feature/sentinel-http-demo https://github.com/samhoon000/major-project.git
   cd major-project
   .\setup.ps1
   .\start.ps1 -HostBinding 127.0.0.1 -Port 8001
   ```

3. Open [Chat](http://127.0.0.1:8001/chat), [Dashboard](http://127.0.0.1:8001/dashboard), or [Attack Lab](http://127.0.0.1:8001/attack-lab). Keep the server terminal open. Press Ctrl+C to stop it.

Setup creates a virtual environment, installs dependencies, checks model assets, and creates an ignored `.env` with a generated `ADMIN_TOKEN` when the file is missing. With an existing `.env`, check that `ADMIN_TOKEN` is set. Copy its value into **Administrator token** and choose **Authenticate** when you need admin controls. Keep the token out of Git and URLs.

For a manual launch after setup, run `.\venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8001 --no-proxy-headers` from the repository root. Use one server process. The proxy flag lets the app validate the actual connection peer.

## Optional Cloudflare access

1. Install [cloudflared](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/) and put it on PATH or place `cloudflared.exe` in the repository root.
2. In your local `.env`, set the following values and keep the generated `ADMIN_TOKEN`:

   ```dotenv
   PORT=8001
   CLOUDFLARE_TUNNEL_MODE=quick
   CLOUDFLARE_TUNNEL_TOKEN=
   CLOUDFLARE_PUBLIC_HOSTNAME=
   HTTP_FLOOD_REMOTE_ENABLED=true
   NETWORK_AUTO_QUARANTINE=false
   ```

3. Restart the server using the loopback launch command above. Once the tunnel reports `running`, read the current links at [local tunnel status](http://127.0.0.1:8001/api/tunnel/state), or run:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:8001/api/tunnel/state |
       Select-Object status, edge_connected, public_url, attack_lab_url, dashboard_url
   ```

4. Open the returned HTTPS links. Append `/chat` to the public base URL for Chat. Authenticate separately in each browser profile that needs dashboard telemetry or lab controls. Tunnel restarts can assign a new hostname.

Quick mode needs no Cloudflare account or tunnel token. Use it for temporary demos. If the connector reports `running` but the browser shows an address error, check DNS and try from an approved network. For named tunnels, authentication details, and troubleshooting, see the [HTTP demo guide](docs/HTTP_FLOOD_DEMO.md).

## What changed on this branch

| Area | Change |
| --- | --- |
| Attack Lab | Added a bounded HTTP flood demonstration with a dedicated loopback endpoint, a separate legitimate test client, rolling rate detection, selective HTTP 429 responses, and recovery controls. |
| Dashboard | Added shared live telemetry and charts for detection, blocked requests, and legitimate-client availability. Dashboard clients can reconnect or fall back to polling. Rule-based results and available GATv2 evidence appear separately. |
| Cloudflare | Extended the existing tunnel manager with tokenless Quick mode, a dynamically assigned hostname, and edge connection status. Named tunnel support remains available. |
| Remote access | Added expiring administrator sessions, CSRF checks, login throttling, authenticated dashboard WebSockets, and restrictions on public routes. The dedicated demo endpoint and legacy browser tests stay local. |
| Verification | Added backend and frontend tests for the detector, authentication, tunnel lifecycle, and dashboard updates. |

To run the tests after setup, install pytest in the project virtual environment. The frontend tests use Node.js and its built-in test runner.

```powershell
.\venv\Scripts\python.exe -m pip install pytest
.\venv\Scripts\python.exe -m pytest -q tests --ignore=tests/test_gatv2_mixed.py
node --test tests/http_flood_ui.test.cjs tests/demo_auth_ui.test.cjs
```

The excluded model test needs `data/cleaned_dataset.csv`, which is absent from the checkout. Run that test separately if you have the dataset.

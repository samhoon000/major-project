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

The complete Sentinel console is at [http://127.0.0.1:8001/dashboard](http://127.0.0.1:8001/dashboard). Its sidebar opens Overview, Monitored Applications, Attack Lab, Network Analysis, Chat Security, and Settings in that same application. The standard Quick Tunnel setup below points to `app:app` and uses Sentinel's configured remote access rules. Monitored Applications and its Northfield telemetry are available on loopback. Attack Lab availability on a tunnel follows the existing remote demo configuration.

If a URL displays **Not available in the chat preview.**, it belongs to a temporary chat-only test server. Open the complete console URL above for all six modules. For remote chat, use the public joining link reported by the currently running Sentinel application.

## Part 1 — Publish Sentinel AI with Cloudflare Quick Tunnel

Only the Windows laptop or VM hosting Sentinel needs `cloudflared`. Teammates can join with a browser and internet access. A Quick Tunnel is free for development and provides a temporary HTTPS address without a Cloudflare account or custom domain. [Cloudflare Quick Tunnel docs](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

### Download and verify cloudflared

1. Download the **Windows 64-bit executable** from [Cloudflare Downloads](https://developers.cloudflare.com/tunnel/downloads/).
2. Create a `cloudflared` folder on the host's Desktop. Put the executable there and rename it to `cloudflared.exe`.
3. In PowerShell, verify that the executable reports its version.

   ```powershell
   $cloudflared = Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'cloudflared\cloudflared.exe'
   & $cloudflared --version
   ```

### Verify Sentinel locally

Complete [the local setup](#start-locally) first. If Sentinel is already running from that section, keep its PowerShell window open. Otherwise, open PowerShell in your project folder and start Sentinel on port **8001**, the project's default.

```powershell
.\start.ps1 -HostBinding 127.0.0.1 -Port 8001
```

In a second PowerShell window, confirm `TcpTestSucceeded : True` and open [local Chat](http://127.0.0.1:8001/chat).

```powershell
Test-NetConnection 127.0.0.1 -Port 8001
```

Choose one way to start the tunnel. Sentinel can start it automatically, or you can run the connector in the second window.

### Let Sentinel start the tunnel

1. Put `cloudflared.exe` on PATH or place a copy in the repository root. In the project’s local `.env`, set the following values and keep the generated `ADMIN_TOKEN`.

   ```dotenv
   PORT=8001
   CLOUDFLARE_TUNNEL_MODE=quick
   CLOUDFLARE_TUNNEL_TOKEN=
   CLOUDFLARE_PUBLIC_HOSTNAME=
   DASHBOARD_REMOTE_ENABLED=true
   HTTP_FLOOD_REMOTE_ENABLED=false
   NETWORK_AUTO_QUARANTINE=false
   ```

2. Restart Sentinel with the same loopback launch command. Once the tunnel reports `running`, read the current links at [local tunnel status](http://127.0.0.1:8001/api/tunnel/state), or run:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:8001/api/tunnel/state |
       Select-Object status, edge_connected, public_url, dashboard_url
   ```

### Start the tunnel in a second PowerShell window

Use this option when you want to run the connector yourself. Set `CLOUDFLARE_TUNNEL_MODE=disabled`, leave `CLOUDFLARE_TUNNEL_TOKEN` blank, set `DASHBOARD_REMOTE_ENABLED=true`, and keep `HTTP_FLOOD_REMOTE_ENABLED=false`. Start or restart Sentinel on loopback and finish the local check above. Run the command below in the second PowerShell window.

```powershell
$cloudflared = Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'cloudflared\cloudflared.exe'
& $cloudflared tunnel --url http://127.0.0.1:8001
```

Wait for `Registered tunnel connection`. Copy the generated hostname, for example `something-random.trycloudflare.com`, into `CLOUDFLARE_PUBLIC_HOSTNAME` in `.env`. Restart Sentinel once so it recognizes the public hostname. Keep both PowerShell windows running. If you restart `cloudflared` and get a new hostname, update `.env` and restart Sentinel again.

### Share Chat and open the dashboard

- Share `https://something-random.trycloudflare.com/chat` with your teammates. Replace the example hostname with the one Cloudflare assigned. Anyone with the link can join Chat.
- Open `https://something-random.trycloudflare.com/dashboard`, enter the local `ADMIN_TOKEN`, and select **Authenticate** to view telemetry or unblock users.

Keep Sentinel and its tunnel running while people use the links. Quick Tunnel URLs can change when the connector restarts, and uptime is not guaranteed. [Cloudflare Quick Tunnel docs](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

The SOC dashboard continues to show captured network activity when nobody has joined Chat. GATv2 findings appear as alerts only when the captured flow matches an active direct chat connection. Cloudflare-relayed chat uses message, URL, and behavior checks, and the timeline records those moderation actions.

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

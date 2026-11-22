# Northfield HTTP monitoring

Northfield sends payload-free request metadata to a dedicated Sentinel collector. The collector commits each accepted batch to local SQLite. The SOC Dashboard links to **Monitored Applications**, which uses the existing operator sign-in and a loopback-only WebSocket. The collector runs independently from the SOC dashboard and network inference.

The local [Stage 2 HTTP detection worker](HTTP_DETECTION.md) reads accepted telemetry and reports alerts in Monitored Applications.

## Local setup in PowerShell

1. From the Sentinel repository root, use the same Python environment as the dashboard. The following commands generate a 32-byte key and start the collector.

   ```powershell
   $TelemetryKey = python -c "import secrets; print(secrets.token_hex(32))"
   $env:HTTP_TELEMETRY_KEYS = @{ 'northfield-local' = $TelemetryKey } | ConvertTo-Json -Compress
   $env:HTTP_TELEMETRY_DB = Join-Path $PWD.Path 'data\http-telemetry.sqlite3'
   python -m uvicorn backend.telemetry.api:app --host 127.0.0.1 --port 8091 --no-proxy-headers --no-access-log --limit-concurrency 32 --ws none
   ```

2. In a second shell at the Sentinel repository root, use the same database path. Set an operator token using `ADMIN_TOKEN` in the environment or your local `.env`. For this setup, clear the existing tunnel token and disable the demo tunnel and remote dashboard in your local `.env` (`CLOUDFLARE_TUNNEL_TOKEN=`, `CLOUDFLARE_TUNNEL_MODE=disabled`, `DASHBOARD_REMOTE_ENABLED=false`, `HTTP_FLOOD_REMOTE_ENABLED=false`). Start the dashboard on loopback.

   ```powershell
   $env:HTTP_TELEMETRY_DB = Join-Path $PWD.Path 'data\http-telemetry.sqlite3'
   python -m uvicorn app:app --host 127.0.0.1 --port 8000 --no-proxy-headers
   ```

3. Apply the Northfield branch to a local checkout and follow its README to initialize a local database. Set the following in Northfield's untracked `.env`, using the same 64 hex characters held in `$TelemetryKey` in step 1. Use Northfield's development environment and start its backend on port 8001. Set `API_PROXY_TARGET=http://127.0.0.1:8001` in Northfield's `frontend/.env` before starting Vite.

   ```dotenv
   TELEMETRY_COLLECTOR_URL=http://127.0.0.1:8091/v1/http-events
   TELEMETRY_APP_ID=northfield-local
   TELEMETRY_HMAC_KEY=<64 hex characters from step 1>
   ```

4. Open `http://127.0.0.1:8000/dashboard/applications` and sign in using the Sentinel operator token. In the local Northfield portal, use synthetic credentials to sign in, enroll in a course, and submit an assignment. Look for their route templates, status codes, timestamps, and request IDs in the stream. The dashboard refreshes its bounded snapshot every two seconds.

## Quick Tunnel and Render

Use the free Quick Tunnel for this demo. The collector stays on `127.0.0.1:8091`. Run the proxy and tunnel in separate PowerShell windows from the Sentinel root.

```powershell
python -m uvicorn backend.telemetry.proxy:app --host 127.0.0.1 --port 8092 --no-proxy-headers --no-access-log --limit-concurrency 24 --ws none
```

```powershell
cloudflared tunnel --url http://127.0.0.1:8092 --no-autoupdate
```

The proxy forwards only an exact `POST /v1/http-events` without a query string. It limits the body to 32 KiB and forwards only the signing headers and content type. The collector continues to authenticate requests, reject replays, and enforce its per-application quota. The Sentinel dashboard stays on loopback.

Run these checks against the HTTPS hostname printed by `cloudflared`. Expect 401 for the unsigned POST and 404 for every other probe.

```powershell
$TelemetryPublic = 'https://<generated-host>.trycloudflare.com'
curl.exe -sS -o NUL -w "%{http_code}\n" -X POST "$TelemetryPublic/v1/http-events"
foreach ($Route in '/v1/http-events','/dashboard','/dashboard/applications','/chat','/attack-lab','/api/admin','/predict') {
    curl.exe -sS -o NUL -w "%{http_code}\n" "$TelemetryPublic$Route"
}
```

In **northfield-portal-api → Environment**, set `TELEMETRY_COLLECTOR_URL` to the generated HTTPS URL plus `/v1/http-events`, `TELEMETRY_APP_ID` to `northfield-prod`, and `TELEMETRY_HMAC_KEY` to the existing collector key protected by Windows DPAPI. Select **Save only** when coordinating the initial deploy, then deploy the reviewed Northfield revision. Open [Monitored Applications](http://localhost:8002/dashboard/applications) and compare the portal responses’ `X-Request-ID` headers with the dashboard events. [Cloudflare Quick Tunnels](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/) · [Render environment settings](https://render.com/docs/configure-environment-variables)

**A Quick Tunnel restart changes its public hostname.** Verify the new endpoint, update `TELEMETRY_COLLECTOR_URL` on Render, and redeploy the existing Northfield build so it reads the new value. Keep the app ID and HMAC key. Render Free can lose its local SQLite data on redeploy. [Render Free filesystem behavior](https://render.com/docs/free#local-files-lost-on-redeploy)

## Named tunnel with a Cloudflare zone

1. Create new, distinct 32-byte credentials for production. Configure the collector map with `northfield-prod` and its key, then restart the collector with the same loopback binding and SQLite path as above. Keep the production key in your secret store.
2. Create a separate named Cloudflare Tunnel and choose a dedicated hostname such as `northfield-telemetry.example.com`. In the locally managed tunnel configuration, substitute the tunnel UUID, its credential file path, and your hostname.

   ```yaml
   tunnel: <tunnel UUID>
   credentials-file: 'C:/path/to/tunnel-credentials.json'
   ingress:
     - hostname: northfield-telemetry.example.com
       path: '^/v1/http-events$'
       service: http://127.0.0.1:8091
     - service: http_status:404
   ```

   Route DNS with `cloudflared tunnel route dns <tunnel-name> northfield-telemetry.example.com`. Validate with `cloudflared tunnel --config <config-file> ingress validate` and check the endpoint and `/dashboard` using `cloudflared tunnel --config <config-file> ingress rule <url>`. Start with `cloudflared tunnel --config <config-file> run <tunnel-name>`. Require HTTPS at the Cloudflare hostname. An unsigned HTTPS POST must return 401. Other HTTP methods on the collector path and paths such as `/dashboard`, `/dashboard/applications`, `/chat`, `/api/admin`, `/attack-lab`, and `/predict` must return 404. Keep the existing demo tunnel disabled for this deployment. [Cloudflare tunnel configuration](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)

3. In Render, select **northfield-portal-api → Environment → Add Environment Variable** and enter these three values. Choose **Save only** to stage them without a deploy. Once the Northfield branch has been reviewed and deployment approved, deploy the revision containing the sender. [Render environment settings](https://render.com/docs/configure-environment-variables)

   | Key | Value |
   | --- | --- |
   | `TELEMETRY_COLLECTOR_URL` | `https://northfield-telemetry.example.com/v1/http-events` using your actual hostname |
   | `TELEMETRY_APP_ID` | `northfield-prod` |
   | `TELEMETRY_HMAC_KEY` | The exact 64 lowercase hex characters mapped to `northfield-prod` in `HTTP_TELEMETRY_KEYS` |

4. Open Monitored Applications and select `northfield-prod`. Check for a delivery heartbeat, then use a test account for one login, enrollment, and assignment submission. Compare the dashboard request IDs with the response `X-Request-ID` headers. To disable sending on a later deploy, remove all three Render variables.

## Rollout status

Northfield [PR #1](https://github.com/samhoon000/cybershield-testbed/pull/1) merged into `main` at `7592233464c60fc7829e2c195dbba4ef24e694b2`. The old Quick Tunnel returned HTTP 530. The replacement demo hostname is `asks-obligation-excess-penguin.trycloudflare.com`. Public HTTPS probes confirmed route isolation, HMAC authentication, and replay rejection before the collector URL was updated. Render [redeployed the same reviewed commit](https://dashboard.render.com/web/srv-dc0om6u1egvs738jark0/deploys/dep-dc0sfmjm8hqs73fgg85g). The public proxy returns 404 for the staging policy endpoint.

After recovery, live login, enrollment, and assignment submission with a synthetic account again produced matching `X-Request-ID` values on the authenticated [Monitored Applications](http://localhost:8002/dashboard/applications) stream. Delivery showed Receiving with zero queued events, drops, retries, or failed batches. Detection and Shadow Mode were running, with no mitigation proposal for the normal workflow.

## Restarting a demonstration on Windows

Run each long-lived command in its own PowerShell window. Run the first two from the Sentinel root with the existing Python environment. Stop a foreground service with Ctrl+C in its window. Keep the local database and the encrypted key file between demonstrations.

**Collector.** The rollout stores the production key in the Git-ignored file `data\northfield-prod-key.dpapi`. The Windows account that created the file can decrypt it on the same machine. Use the existing matching key on each restart.

```powershell
$TelemetrySecret = (Get-Content -Raw -LiteralPath .\data\northfield-prod-key.dpapi).Trim() | ConvertTo-SecureString
$TelemetryKey = [System.Net.NetworkCredential]::new('', $TelemetrySecret).Password
$env:HTTP_TELEMETRY_KEYS = @{ 'northfield-prod' = $TelemetryKey } | ConvertTo-Json -Compress
$env:HTTP_TELEMETRY_DB = Join-Path $PWD.Path 'data\http-telemetry.sqlite3'
python -m uvicorn backend.telemetry.api:app --host 127.0.0.1 --port 8091 --no-proxy-headers --no-access-log --limit-concurrency 32 --ws none
```

**Sentinel.** Keep the existing `ADMIN_TOKEN` in the local environment or `.env`. The one-space tunnel token below overrides a token from `.env` and Sentinel trims it to empty. The Stage 1 instance uses port 8002 so the existing local services on ports 8000 and 8001 can continue running.

```powershell
$env:HTTP_TELEMETRY_DB = Join-Path $PWD.Path 'data\http-telemetry.sqlite3'
$env:CLOUDFLARE_TUNNEL_TOKEN = ' '
$env:CLOUDFLARE_TUNNEL_MODE = 'disabled'
$env:DASHBOARD_REMOTE_ENABLED = 'false'
$env:HTTP_FLOOD_REMOTE_ENABLED = 'false'
$env:PORT = '8002'
python -m uvicorn app:app --host 127.0.0.1 --port 8002 --no-proxy-headers
```

**Quick Tunnel.** Start the restricted proxy, then run `cloudflared tunnel --url http://127.0.0.1:8092 --no-autoupdate`. Verify the new HTTPS hostname and update Render as described above.

**Named tunnel alternative.** From the directory containing the dedicated tunnel configuration, run the following after the collector responds on loopback.

```powershell
cloudflared tunnel --config .\northfield-tunnel.yml ingress validate
cloudflared tunnel --config .\northfield-tunnel.yml run northfield-telemetry
```

| Symptom | Recovery |
| --- | --- |
| Laptop restarted | Start the collector, Sentinel, the restricted proxy, and the Quick Tunnel. Update the Render URL and redeploy the existing build if the hostname changed. Sign in to Monitored Applications again if the in-memory operator session expired or Sentinel restarted. |
| Collector restarted | Reuse the existing key, port, and database. An unsigned local POST should return 401. Northfield retries transient delivery failures and reports drops after it reconnects. |
| Tunnel disconnected | Check the local collector and proxy first. If you restart a Quick Tunnel, repeat the HTTPS isolation checks, then point Render at the new hostname. A named tunnel uses its existing configuration and DNS record. |
| Render spun down | Open the deployed portal or backend `/health` and wait for it to wake. The heartbeat resumes while the service is running. |
| Northfield SQLite reset | Use the configured demo seed accounts or register a new synthetic test account. Free Render instances can lose their local SQLite data when restarting, redeploying, or spinning down. [Render Free filesystem behavior](https://render.com/docs/free#local-files-lost-on-redeploy) |
| Telemetry stale with Northfield awake | Check the tunnel and collector, the exact Render URL and app ID, the matching HMAC key, and the Windows clock. Inspect Northfield and collector logs for delivery errors and compare the dashboard’s last delivery time and retry/drop counts after recovery. |

## Wire format and operational limits

- Version 1 uses a JSON envelope with `version`, `events`, and `delivery`. The authenticated header identifies the application deployment. Each request event carries a UUIDv4 request ID, UTC epoch milliseconds, a matched route template or a fixed fallback, a bounded HTTP method, status, duration in milliseconds, and an enumerated authentication outcome. Northfield emits completed API requests and excludes health checks, CORS preflights, and requests disconnected before a status can be assigned.
- The signature is lowercase HMAC-SHA256 with the decoded 32-byte key. The input is newline-separated `POST`, `/v1/http-events`, application ID, UTC epoch seconds, UUIDv4 nonce, and lowercase SHA-256 of the exact body bytes. The corresponding headers are `X-Telemetry-App`, `X-Telemetry-Timestamp`, `X-Telemetry-Nonce`, and `X-Telemetry-Signature`. The collector enforces a two-minute timestamp window, consumes accepted nonces transactionally, and deduplicates by application and request ID within retained history.
- The collector caps a batch at 32 events and 32 KiB, permits up to 600 active nonces per app, and retains up to 50,000 events per app for seven days. Use a distinct deployment ID and key for each app and environment.
- Northfield keeps 512 queued events and drops new arrivals when full. Its single worker coalesces arrivals for 250 ms, sends up to 32 events per batch, and makes up to three attempts for transient failures. Retries use fresh nonces and keep request IDs. Events left in memory when the Northfield process exits are lost.
- Heartbeats arrive every 15 seconds while idle. Delivery becomes stale after 45 seconds without an accepted batch. Sender counter values describe the process at the time of signing and reset when it restarts. The latest successful heartbeat or batch reports drops and retries after recovery. The dashboard shows 25 retained requests per app in a fixed-size snapshot and counts authentication denials, rate-limit denials, and origin denials in the last minute.

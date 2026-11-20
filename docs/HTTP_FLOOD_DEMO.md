# Sentinel HTTP flood demonstration

## What changed

The existing HTTP flood implementation now uses real HTTP/TCP sockets through
`httpx.AsyncClient`, rather than `ASGITransport`. It targets only the dedicated
`/api/attack-lab/http-flood-target` route on a numeric loopback HTTP origin.
There is no submitted target URL, DNS resolution, redirect following, or proxy
environment support. A single authenticated preflight request must prove that
the origin serves this exact Sentinel lab instance before sustained traffic starts.

The default run requests 25 requests/second for 8 seconds with concurrency 4.
Hard limits are 50 requests/second, 20 seconds, concurrency 8, and 1,000 flood
requests. Requests time out after one second. Concurrency saturation skips
dispatch slots instead of building a queue, so actual throughput can be lower
than the requested rate. The UI reports actual measurements.

### Files

| File | Responsibility |
|---|---|
| `backend/security/http_flood.py` | Existing module extended: generator, isolated identities, detection, mitigation, counters, recovery, lifecycle |
| `backend/attack_lab.py` | Existing page integration, protected controls, telemetry and shared script route |
| `backend/chat_service.py` | Existing live dashboard integration; removed broken helper injection; safe iteration of dashboard connections |
| `backend/network/tunnel.py` | Caches LAN discovery for 10 seconds with a single refresh; discovery holds no tunnel lifecycle lock |
| `app.py` | Middleware registration retained; shutdown closes all HTTP lab background tasks |
| `backend/http_flood_ui.py` | New shared panel markup and styling |
| `backend/static/http_flood.js` | New shared renderer, controls, WebSocket updates, polling fallback and visible errors |
| `backend/security/demo_access.py` | Remote boundary, bounded sessions, CSRF, login throttling and remote route restrictions |
| `backend/security_ui.py`, `backend/static/demo_auth.js` | Shared sign-in, credential clearing and cross-tab session updates |
| `.env.example` | Detector configuration and loopback-origin documentation |
| `tests/test_http_flood.py` | Policy, authorization, failure, lifecycle, real-socket and WebSocket integration tests |
| `tests/http_flood_ui.test.cjs` | Dependency-free frontend renderer/control/error tests |
| `tests/test_remote_demo.py`, `tests/demo_auth_ui.test.cjs` | Proxy-boundary, session, multiple-viewer and remote-interface tests |

No model, scaler, GATv2 architecture, or Windows
Firewall policy was changed. No new dependency is required. The React simulator remains
separate; this feature is integrated into the live FastAPI interfaces.

## Architecture and measured behavior

1. An authenticated local administrator or trusted HTTPS tunnel administrator starts normal traffic or an attack.
2. A preflight verifies the listener using a private capability and the current
   run identifier. Failed preflights prevent generation and report an error.
3. Independent HTTP clients generate flood traffic and one legitimate request
   per second. The legitimate monitor is bounded to 120 seconds.
4. Middleware measures authenticated arrivals at the dedicated target. It
   calculates request frequency using a rolling window, independently of the
   Start button and the generator counters.
5. Warning and blocking thresholds produce backend events. At the blocking
   threshold, only the offending `lab-flood` capability receives HTTP 429 with
   `Retry-After`; the legitimate capability remains admitted on the same IP and
   endpoint. Ordinary application routes are outside this limiter.
6. A publisher samples actual one-second arrival counts every 500 ms and sends
   telemetry through the existing dashboard WebSocket broadcaster. Both pages
   also poll once per second for initial state and fallback recovery.
7. The generator ends automatically or is cancelled manually. The block expires
   automatically, or a local administrator can remove it after stopping the run.
8. Reset cancels monitoring/publication, rotates capabilities, clears counts,
   and broadcasts a fresh READY state. Application shutdown cancels every lab task.

Default detector values:

| Setting | Default |
|---|---:|
| `HTTP_FLOOD_WINDOW_SECONDS` | 2 |
| `HTTP_FLOOD_WARNING_RPS` | 5 |
| `HTTP_FLOOD_BLOCK_RPS` | 12 |
| `HTTP_FLOOD_BLOCK_SECONDS` | 10 |

Thresholds apply to the flood identity's arrivals divided by the complete
rolling-window duration. This avoids treating the first request as an infinite
rate. The UI graph shows one-second measured total, accepted and blocked
arrivals, and labels the difference between that graph and the detector window.
The warning event also records the measured normal baseline and spike ratio.
Total observed requests equal accepted plus rejected requests. Generated client
requests can temporarily differ from observed arrivals while requests are in
flight or when the network fails. Client response counters distinguish 200,
429 and failures; failures are never counted as successful mitigation.

Recent graph samples, events, rejection records, endpoint associations and
request windows have explicit bounds. Aggregate counters retain totals for the
run. Each rejection is recorded and broadcast; the visible timeline summarizes
rejections in batches so critical detection/expiry events remain visible.

### Authorization and scope

HTTP flood controls (`monitor`, `start`, `stop`, `unblock`, `reset`) accept the
existing local token header or a short-lived administrator session. Remote
control additionally requires explicit opt-in and the configured HTTPS hostname
through a trusted proxy. Cookie-authenticated changes require same-origin and
CSRF checks. Legacy browser scan/burst controls and their `authorize` endpoint
remain local-only. See the Cloudflare presentation section below for deployment
and authentication details. Missing configuration fails closed.

The dedicated target additionally requires a server-only capability and a
direct loopback peer. Public state/JavaScript responses expose no capability or
administrator token. Tokens entered in the panel are kept only in the page's
memory until authentication succeeds, then cleared. Long-lived credentials are
never stored in localStorage. The generator never creates operating-system firewall rules.

## GATv2 integration

The real HTTP client records its actual local/remote TCP socket endpoints.
The panel looks for analyzed TCP flows with those exact endpoints and a start
time within the run. It displays existing model probabilities only when this
association succeeds. Unrelated host traffic is never borrowed as evidence.

The selected physical Wi-Fi adapter generally does not capture loopback
traffic. In browser validation, the existing physical capture/GATv2 pipeline
continued operating, but no HTTP lab flow was associated. The panel correctly
displayed **Rule-Based HTTP Flood Detection** and no model probability.
HTTP detection remains labelled **Rule-Based HTTP Flood Detection** even if
an independently analyzed, exactly associated GATv2 flow is found. That model's
prediction, probability and actual confidence are displayed separately as
network evidence. No model was retrained or replaced.

## Run the demonstration

Use an existing working Python environment with `requirements.txt` installed.
Configure a strong `ADMIN_TOKEN` in `.env` (the existing setup script generates
one). Do not put a real token in a URL or frontend source.

From the repository directory in PowerShell:

```powershell
$env:PORT = "8001"
rtk proxy python -B -m uvicorn app:app --host 127.0.0.1 --port 8001 --no-proxy-headers
```

If the project virtual environment exists, substitute
`.\venv\Scripts\python.exe` for `python`. The existing `start.ps1` can also
launch the application. Keep one Uvicorn worker because project state is
in memory. `HTTP_FLOOD_BASE_URL` should normally be left blank: the target port
then comes from the actual ASGI listener, never the Host header.

Open two windows on the host laptop:

- Attack Lab: `http://127.0.0.1:8001/attack-lab`
- Dashboard: `http://127.0.0.1:8001/dashboard`

### Presentation walkthrough

1. Enter `ADMIN_TOKEN` into the Attack Lab's administrator field and click
   **Authenticate**. Local token-header controls remain compatible as well.
2. Click **Start normal traffic**. Wait a few seconds. Show the low request
   rate and increasing legitimate-success count in both windows.
3. Keep the defaults (25 req/s, 8 seconds, concurrency 4) and click **Start Attack**.
4. Show the total-arrival spike. Detection is produced by measured requests,
   followed by the HIGH detection alert and selective mitigation alert.
5. Explain the graph: accepted flood traffic falls; blocked traffic rises;
   legitimate requests continue. Show HTTP 429 and legitimate failure counters.
6. Let the run finish, or click **Stop Attack**. Dispatch stops and in-flight
   requests are cancelled/drained. The temporary block remains until expiry.
7. Show **RECOVERED — SOURCE UNBLOCKED** after expiry. Alternatively use
   **Unblock source** after stopping to demonstrate manual recovery.
8. Click **Reset demonstration**. Both pages return to READY. Start normal
   traffic again before repeating. Stop/reset conflicts return HTTP 409 rather
   than racing an active generator.

Closing a browser does not issue an unauthenticated stop beacon. The backend
duration/volume limits remain responsible for automatic stopping. Reset stops
the normal monitor; Ctrl+C stops the application and cancels all lab tasks.

## Validation

Backend regression and real-socket tests:

```powershell
rtk proxy python -B -m pytest -p no:cacheprovider -q tests --ignore=tests/test_gatv2_mixed.py
rtk proxy node --test tests/http_flood_ui.test.cjs tests/demo_auth_ui.test.cjs
```

The mixed-dataset test needs the absent `data/cleaned_dataset.csv`; provide that
dataset to run it separately. It was not treated as passing. On this host,
Windows asyncio tests required permission to use loopback sockets outside the
execution sandbox. Python 3.14/PyTorch and FastAPI lifecycle deprecation warnings
remain upstream/project compatibility warnings.

Local implementation baseline: **117 backend tests passed**, **17 parameterized subtests passed**,
and **4 frontend tests passed**. The baseline backend run reported 43 compatibility/
deprecation warnings. No trained-model artifact changed; the active checkpoint
SHA-256 remains `b836f083fe14203695c40a3c04d909922b53fa2bb3e91deb1f0d537eaeda8d84`.

Validation includes actual Uvicorn sockets, HTTP response accounting, existing
dashboard WebSocket delivery, capability separation, automatic expiry, manual
unblock, repeat runs, invalid targets/configuration, failed local connections,
unrelated-listener rejection, cancellation, concurrent starts, reset and shutdown.
Frontend tests cover controls/auth headers, graph/telemetry consistency, alerts,
visible polling/WebSocket errors, stale snapshots and reset behavior.

Browser validation on November 19, 2026 used the full application on a temporary
loopback listener at port 8766, with a test-only admin token and Cloudflare/
automatic firewall quarantine disabled. The final default run generated **200**
real requests: **23 successful, 177 HTTP 429, 0 failed**. The legitimate client
was observed at **73 successful requests, 0 blocked, 0 failed** after recovery.
Both pages updated automatically. Browser checks also verified manual Stop,
Unblock, Reset, and a repeated run. Console inspection found no errors or
warnings on those pages. The screenshot records an intermediate active moment,
so its counters are lower than the completed run totals above.

An extended session exposed blocking Windows adapter discovery inside the
existing asynchronous tunnel-state route. Stack diagnostics identified
`GetAdaptersAddresses` on the event-loop thread. Tunnel state/QR requests now
use the framework's worker threads, WebSocket origin checks offload discovery,
and status snapshots reuse cached discovery with a single refresh. A synchronization-based test
holds discovery blocked and verifies HTTP lab telemetry responds independently.

### Boundaries

- This demonstrates capability-scoped application rate limiting on a dedicated
  endpoint. It is not a general production DDoS protection service.
- Legitimate availability results describe the measured client, not a guarantee
  about every user or network failure.
- Live GATv2 HTTP-flood recognition/combined detection was not demonstrated.
- Physical-device capture and OS-firewall mitigation remain outside this loopback
  demonstration. Authenticated public controls require the configuration below.
- Runtime state is in memory and assumes one server worker.

## Cloudflare presentation: remote controls, local traffic

```text
Phone / remote laptop browser
  HTTPS UI + authenticated control APIs / WSS telemetry
        -> existing Cloudflare Tunnel -> existing cloudflared
        -> http://127.0.0.1:8001 FastAPI
        -> existing bounded HTTP generator
        -> http://127.0.0.1:8001/api/attack-lab/http-flood-target
        -> rule-based detector -> capability-scoped HTTP 429
        -> existing dashboard broadcaster -> remote viewers
```

Cloudflare transports interface requests and telemetry. The generator sends
its requests directly over the host's loopback stack, independently of the
visitor's IP, public hostname or tunnel availability. Browser scan/burst tests
are disabled remotely. Opening viewers or signing in does not start a generator
or a legitimate monitor. One shared backend controller owns each run.

### Environment and startup

Set these in the ignored `.env` on the host. Values below are placeholders;
never put real credentials into documentation, URLs, source code or screenshots.

```dotenv
HOST=127.0.0.1
PORT=8001
ADMIN_TOKEN=<your-generated-strong-secret>
CLOUDFLARE_TUNNEL_MODE=quick
CLOUDFLARE_PUBLIC_HOSTNAME=
CLOUDFLARE_TUNNEL_TOKEN=
HTTP_FLOOD_REMOTE_ENABLED=true
HTTP_FLOOD_BASE_URL=
TRUSTED_PROXIES=
NETWORK_AUTO_QUARANTINE=false
```

Setup creates an ignored `.env` with a strong `ADMIN_TOKEN` when the file is
missing. Read the token from your local file to authenticate. The example file
keeps remote access off by default.

Keep `HTTP_FLOOD_BASE_URL` blank so the target uses the actual ASGI listening
port. Even an explicitly configured target must be a numeric loopback HTTP
origin and pass the same-instance preflight. The public URL cannot be a target.
`NETWORK_AUTO_QUARANTINE=false` is the existing demonstration default; HTTP
mitigation remains active. The HTTP lab never calls OS firewall quarantine.

Run:

```powershell
rtk proxy python -B -m uvicorn app:app --host 127.0.0.1 --port 8001 --no-proxy-headers
```

The existing application startup calls `TunnelManager.start()` automatically.
It locates `cloudflared` and reuses the existing manager to start a Quick Tunnel
with `tunnel --url http://127.0.0.1:8001 --no-autoupdate`. No account, hostname
or named token is needed. The first temporary trycloudflare.com URL reported by
that child process becomes the exact allowed public origin, including CORS and
WebSocket authentication. Other trycloudflare.com origins are rejected. Until
the manager receives a hostname, remote authentication fails closed.

Read `/api/tunnel/state` locally for the generated Attack Lab and dashboard URLs.
The hostname changes after restarting the tunnel; authenticate again on its new
origin. Quick Tunnels suit temporary demonstrations and have no uptime guarantee;
see the [official Quick Tunnel guide](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).
Application sessions protect remote controls and telemetry. Cloudflare Access
is not configured for this temporary hostname. Use a named tunnel plus Access
when a stable hostname and an additional identity gate are required.

For an existing named tunnel, set mode to `named`, provide its token and exact
public hostname. The manager passes the tunnel token through the supported
`TUNNEL_TOKEN` child environment variable, excluding the administrator token;
the tunnel secret is not placed in process arguments. See Cloudflare's
[run-parameter reference](https://developers.cloudflare.com/tunnel/reference/run-parameters/).
`start.ps1` includes `--no-proxy-headers` as well. Do not use multiple workers.

If an existing external `cloudflared` service already owns the tunnel, keep
that service instead of starting a duplicate daemon. Leave the application's
`CLOUDFLARE_TUNNEL_MODE=disabled`, leave its token blank, set its public hostname and remote opt-in, and
route the existing service to the same loopback listener. In that case the
application's daemon status describes only its own manager; it is not evidence
that the externally managed tunnel is down or publicly verified.

### Optional named tunnel route

In Cloudflare **Networking > Tunnels**, select the existing tunnel. Under
**Routes**, add or edit its **Published application** route. Set your public
hostname and service URL `http://127.0.0.1:8001`. Preserve the original public
Host header; remove an override to `localhost`. Keep browser-facing HTTPS.
The connector should run on this host, connecting from loopback. For a separate
trusted connector, list only its exact IP in `TRUSTED_PROXIES` and configure an
appropriate listener/firewall boundary yourself.

These steps follow Cloudflare's [published-application route documentation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/).
No Cloudflare account, route, DNS record or Access policy was changed by this task.

The hostname is obtained from your existing published route and configured in
`CLOUDFLARE_PUBLIC_HOSTNAME`; it is never hardcoded in JavaScript. The authenticated
tunnel-state response provides Attack Lab, dashboard and WSS URLs when the
managed tunnel is running. Edge registration is distinguished from independently
verified public HTTPS reachability.

### Additional protection with Cloudflare Access

Cloudflare Access is an additional identity gate, not a replacement for Sentinel
administrator authentication. It needs manual account configuration:

1. Open **Zero Trust > Access controls > Applications** and create a self-hosted
   application for the entire public hostname, including API and WebSocket paths.
2. Add a narrowly scoped Allow policy for the presenters' email addresses or
   identity-provider group; avoid a public Bypass policy.
3. Select your identity provider and a short presentation session duration.
4. Enable **Protect with Access** in the tunnel's application/origin settings
   when available, so the connector validates the Access token.
5. Verify that unauthenticated requests are challenged, then authenticate with
   Access and with Sentinel in the browser.

See the [official Access setup instructions](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/).
This application does not treat an unverified Access header as proof of identity.
Access has **not** been configured or publicly tested here.

The backend independently restricts remote paths to the presentation pages,
authentication, required telemetry, chat WebSockets and HTTP flood controls.
Dataset upload/prediction, graph generation, API docs, legacy burst routes and
unrelated administrative routes remain unavailable through the public boundary.
For an extra edge restriction, configure an allowlist/WAF rule for those paths
on this hostname, or publish only the corresponding path routes and deny the
remainder. Do not publish the dedicated flood target. Keep `/api/auth/*`, the
shared UI scripts, `/ws/dashboard`, `/ws/chat/*` and required `/api/*/state` paths
available to the Access-protected application.

### Phone controller and second-laptop viewer

1. Host laptop: start FastAPI and the existing tunnel, then verify the configured
   HTTPS hostname from another network. A green local connector status alone
   does not prove DNS/ingress/public reachability.
2. Phone: open `https://<configured-hostname>/attack-lab`, complete Cloudflare
   Access if enabled, enter `ADMIN_TOKEN`, and click **Authenticate**.
3. Viewer laptop: open `https://<configured-hostname>/dashboard` and authenticate
   separately. No token is put into a query parameter.
4. Phone: click **Start normal traffic**, wait for successful requests, then
   **Start Attack**. Keep the default bounded settings for the presentation.
5. Viewer: show measured attempted/accepted/rejected traffic, the detection
   timestamp/method, mitigation alert, and legitimate-client counts/latency.
6. Phone: **Stop Attack** if desired; wait for expiry or use **Unblock source**.
   Show recovery, then **Reset demonstration**. All devices read shared state.
7. **Sign out** when finished. Signing out revokes that session; it does not
   cancel another administrator's bounded run. Use Stop/Reset first if needed.

### Session, proxy and reconnect details

- Sessions expire after 30 minutes, are held in bounded server memory, and are
  invalidated by logout, server restart or administrator-token rotation.
- Remote cookies use HttpOnly, Secure and SameSite=Strict. Cookie-authenticated
  state changes require a same-origin Origin and a session CSRF nonce in a
  custom header. The long-lived admin token is cleared from the input after login.
- API responses use `Cache-Control: no-store`. Other tabs on the same origin
  restore session status after sign-in/sign-out notifications; no credential
  is transmitted in those notifications.
- Invalid token authentication is limited to eight attempts per source per
  minute and 120 global failures per minute, with bounded bookkeeping.
- `CF-Connecting-IP` and HTTPS forwarding information are accepted only from
  an exact configured proxy IP and the configured public hostname. The visitor
  IP is used for authentication throttling, not as a flood source identity.
- Uvicorn must see the raw socket peer. `--no-proxy-headers` prevents its earlier
  middleware from rewriting that peer before application validation. An
  untrusted peer with forged Cloudflare headers fails closed.
- HTTP flood identities remain private server capabilities. Cloudflare requests
  cannot reach the flood target and are not counted as flood/legitimate probes.
- A dashboard WebSocket needs the same authenticated session and matching
  public HTTPS Origin. Revoked/expired sessions are checked before broadcasts.
- Browser URLs use relative APIs and `location`-derived WS/WSS. Reconnects use
  up to six attempts with capped exponential delay; authenticated polling is a
  fallback. A reconnect restores state through the snapshot/API. Authenticate
  again or reload after retries are exhausted.
- The existing `cloudflared` process handles edge reconnection. The manager
  reports loss of all tracked connections as reconnecting and restores running
  on registration. One lost edge does not mark surviving edges offline.

Cloudflare documents both [WebSocket support and possible connection interruptions](https://developers.cloudflare.com/network/websockets/).

### Troubleshooting

| Symptom | Check |
|---|---|
| Remote administration disabled | Enable remote mode and either Quick mode with an assigned hostname, or a configured named hostname. |
| Public hostname resolves to 0.0.0.0 / browser address invalid | Public access is blocked in the current network environment. Check with the network administrator; do not treat edge registration as public verification. |
| 403 after login/control | Verify `--no-proxy-headers`, loopback connector, HTTPS, original public Host, and expected Origin. |
| 401 telemetry or closed WebSocket | Authenticate in that browser; check session expiry and cookies. |
| CSRF rejection | Use the page's Authenticate button; refresh/re-authenticate rather than copying stale nonces. |
| 429 authentication | Wait 60 seconds; avoid repeated credential guessing. This is separate from flood-target 429 mitigation. |
| Cloudflare 1033/502 | Check existing tunnel/connector, service port 8001, DNS and ingress settings. |
| API works but WSS fails | Check Access/WAF coverage and Cloudflare WebSockets setting; reload after bounded retries. |
| Test won't start | Check same-instance preflight, loopback origin, rate limits and an existing run; Stop then Reset. |
| GATv2 evidence unavailable | Expected for loopback on a physical adapter; the working HTTP detector remains rule-based. |

### Remote validation status

Automated tests emulate a trusted cloudflared HTTP hop and use actual local
Uvicorn/TCP/WebSocket connections. They verify authenticated remote-style
Start/Stop/Unblock/Reset, CSRF, session expiry/logout, spoofing rejection,
sensitive-telemetry restrictions, multiple synchronized viewers, reconnect,
duplicate prevention and local-only generation with legitimate isolation.
These tests are **not** a public Cloudflare connectivity test.

Browser validation verified sign-in and session-authenticated controls on the
local application. On the test PC, the Wi-Fi resolver initially returned
`0.0.0.0` for the assigned Quick Tunnel hostname. After selecting Cloudflare
Secure DNS in Chrome, Chat, Dashboard, and Attack Lab loaded over public
HTTPS and the signed-in dashboard received live updates over WSS.
Cloudflare Access and access from another physical device were not tested.

Validation result for this integration: **137 backend tests passed**, with
**17 parameterized subtests passed**, and **7 frontend tests passed**. The
mixed-dataset test still requires the missing CSV. Browser session validation
observed **200 generated / 23 accepted / 177 rejected / 0 failed** requests,
with **121 legitimate successes / 0 blocked / 0 failed** at the final check.
These are observations from that run, not fixed interface values.

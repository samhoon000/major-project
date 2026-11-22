# Stage 2 HTTP behavioral detection

Sentinel evaluates Northfield’s authenticated HTTP telemetry using deterministic rules. Monitored Applications shows the results as **Detection Mode: Alert Only**. The HTTP worker never invokes the GATv2 model, chat threat engine, firewall, or account controls.

## How an event becomes an alert

1. The Stage 1 collector verifies HMAC, timestamp, nonce, schema, and application identity before committing each request.
2. Starting the worker installs a SQLite trigger. Each newly inserted request is queued in the same transaction with its authenticated deployment ID and SQLite arrival time. The original sender timestamp remains in the evidence. Older Stage 1 history stays visible in the requests table.
3. The separate worker processes the queue in ID order. Rules select preceding arrivals from bounded time windows for the same deployment. Evaluating alerts and advancing the cursor happen in one SQLite transaction. A worker failure rolls back that transaction, leaving telemetry available and queued for retry.
4. Alerts and their operator status persist in SQLite. A continuing signal updates the same alert while its cooldown window remains active. A dismissed incident suppresses continued matching signals during the same window. A qualifying signal after a quiet period can start a new alert.
5. The loopback-only dashboard reads alert summaries and up to 40 recent matching alerts in its existing authenticated WebSocket stream. Session authentication and same-origin CSRF checks protect acknowledge, resolve, and false-positive actions.

The worker reuses the chat engine’s rolling-window pattern. HTTP windows use persisted arrival times and the authenticated deployment ID, which partitions production, test, and local traffic. The dashboard recognizes ID suffixes such as `-prod`, `-staging`, and `-local`. It labels other environments as unspecified. Northfield’s deployed telemetry provides request IDs, strict route templates, status, duration, and auth outcomes. The [attributed revision](HTTP_PROTECTION.md) can add a pseudonym for eligible authenticated student requests. For attributed production bursts and authorization denials, requests must also fall within the original request-time window. Events arriving more than 15 seconds late or clocked more than 5 seconds ahead remain visible in telemetry. They are excluded from subject-scoped production proposals.

## Default rules

| Rule ID | Evidence and threshold | Severity |
| --- | --- | --- |
| `login_failures` | At least 5 explicit `denied` outcomes on `POST /api/auth/login` with HTTP 401 in 60 seconds | Medium |
| `route_burst` | At least 31 requests to one known route template in 10 seconds across all callers | Low |
| `authorization_denials` | At least 5 HTTP 403 responses with an explicit `denied` outcome in 120 seconds | Medium |
| `route_probing` | At least 8 fallback `unmatched` responses with HTTP 404 or 405 in 60 seconds | Low |
| `server_errors` | At least 10 HTTP 5xx responses in 60 seconds, at least 20 total requests, and at least 50% errors | Low |
| `traffic_spike` | At least 100 requests in 60 seconds, at least 100 requests in the preceding five-minute baseline, and at least triple the baseline rate | Info |
| `sensitive_route_frequency` | At least 60 requests in 60 seconds from one verified subject to one eligible Northfield write route, excluding HTTP 429 | Low |
| `repeated_policy_rate_limits` | At least 3 policy-issued HTTP 429 responses in 10 seconds for the same verified subject, method, and route | Medium |

All rules use a default 120-second cooldown. Alerts retain the thresholds in effect when evaluated, first and last observed times, count, explanation, and up to eight contributing request examples including request IDs. Evidence distinguishes verified subject scope from aggregate observations. Confidence describes support for the observed pattern. Severity describes how urgently to review it. The dashboard exposes no ML probability for HTTP alerts.

## Start or restart the worker

Run from the Sentinel root in a separate PowerShell window. Use the same SQLite path as the collector and dashboard. Ctrl+C stops the foreground worker. Restarting resumes from the stored cursor.

```powershell
$env:HTTP_TELEMETRY_DB = Join-Path $PWD.Path 'data\http-telemetry.sqlite3'
python -m backend.telemetry.detection
```

Open [Monitored Applications](http://localhost:8002/dashboard/applications), sign in, and find **Threat Detection** below the Stage 1 request view. The top counts cover retained alerts. Filter the feed by application, severity, rule, or status. Select a rule name in the feed to inspect samples and change the alert’s status.

## Verification

The live Northfield deployment on `7592233` supplied normal login, course enrollment, and assignment submission events. All three response request IDs matched the authenticated dashboard and the worker’s committed cursor. All three were visible about two seconds after the assignment response, with zero Northfield alerts for the workflow and zero delivery drops, retries, or failed batches. The isolated signed replay triggered all six rules and displayed their evidence and operator controls in Chrome.

## Replay an isolated demonstration

The replay uses the collector’s signing and validation code entirely in-process. It creates an independent database and refuses to use an existing file. It first verifies a normal login, enrollment, and submission sequence produces zero alerts. It then verifies the six original aggregate detection rules. The scoped tests cover sensitive-route frequency and repeated policy rate limits.

```powershell
$DemoDb = Join-Path $PWD.Path ('data\http-detection-demo-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.sqlite3')
python -m backend.telemetry.replay --db $DemoDb
$env:HTTP_TELEMETRY_DB = $DemoDb
$env:CLOUDFLARE_TUNNEL_TOKEN = ' '
$env:CLOUDFLARE_TUNNEL_MODE = 'disabled'
$env:DASHBOARD_REMOTE_ENABLED = 'false'
$env:HTTP_FLOOD_REMOTE_ENABLED = 'false'
$env:PORT = '8003'
python -m uvicorn app:app --host 127.0.0.1 --port 8003 --no-proxy-headers
```

Open the [isolated demo dashboard](http://localhost:8003/dashboard/applications). It shows persisted demo alerts even after replay exits. To show a running worker, start the detection command in another shell with `HTTP_TELEMETRY_DB` set to the demo database printed by replay.

## Configure or disable individual rules

Set `HTTP_DETECTION_CONFIG` to a TOML file before starting the worker. Omitted settings use their defaults.

```toml
[login_failures]
threshold = 6
window_seconds = 90
cooldown_seconds = 180

[traffic_spike]
enabled = false
```

All rules accept `enabled`, `threshold`, `window_seconds`, and `cooldown_seconds`. Server errors and traffic spikes also accept `minimum_samples` and `ratio_percent`. For traffic spikes, `baseline_seconds` sets the preceding comparison period, and a ratio of 300% means three times the baseline rate.

## Interpretation and recovery

- **Worker offline or pending events growing** means the worker heartbeat has expired or the cursor is lagging. Check that the worker uses the same SQLite path as the collector. Review the worker log and the last error in the dashboard. Restarting the worker preserves pending events.
- **Telemetry stale** means no valid batch or heartbeat arrived recently. Check [Stage 1 tunnel and collector configuration](NORTHFIELD_TELEMETRY.md). The public Quick Tunnel needs a new Render URL when its hostname changes.
- **Live traffic and no alert** can be normal. Check the rule’s enabled state, minimum sample, threshold, and recent baseline. A login page’s unauthenticated session probe, validation failures, origin denials, and rate-limited requests do not count as explicit login denials. Matched resource 404s do not count as unmatched-route probing.
- Windows use server arrival time. A delayed batch can raise aggregate counts when it arrives. Application bursts and server errors can also reflect legitimate usage, retries, or deployment problems. Treat the evidence as a prompt to investigate.
- Processed detection receipts are kept for 26 hours, covering the Stage 1 transport’s retry eligibility window. Alerts are retained for up to 30 days and capped at 2,000 per deployment. Unprocessed rows remain durable during a worker outage, so allocate disk space for the backlog.
- Future Stage 3 could consume persisted alerts and their dispositions through a separate authorized policy interface. Subject-based mitigation would require reviewed, reliable attribution and explicit enforcement safeguards.

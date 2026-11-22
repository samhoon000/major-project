# Stage 3 HTTP protection

## Architecture and modes

Northfield completes each request before sending HMAC-authenticated telemetry. The existing Cloudflare Quick Tunnel and its restricted loopback proxy accept only telemetry. The detection worker evaluates accepted requests. The protection worker reads persisted alerts and writes decisions to SQLite. A separate signed policy service delivers operator-approved rules. The currently deployed Northfield revision sends aggregate telemetry. The revised code supports attributed observation with enforcement disabled and an independently enabled production rate-limit channel. Chat moderation and GATv2 network quarantine retain their existing independent controls.

| Mode | Availability and behavior |
| --- | --- |
| Alert Only | Default for a fresh database. Stage 2 still detects and records alerts. Stage 3 does not produce proposals. |
| Shadow | Records policy decisions. Request handling continues normally. |
| Challenge | Reserved for an inline integration with a real, monitored verification mechanism. |
| Block | Verified on the isolated staging backend after explicit operator approval. Production remains disabled. |

Shadow decisions can record `ALLOW`, `MONITOR`, `RATE_LIMIT`, or `BLOCK`. `CHALLENGE` is reserved. The dashboard shows proposals, approved rules, delivery acknowledgment, confirmed outcomes, and recovery. Northfield sends actual enforcement outcomes to a separate authenticated receipt ledger.

## Policy

| Decision | Default conditions |
| --- | --- |
| Allow | An alert falls under an application allowlist or a rule, route, or built-in administrative exemption. Normal traffic without an alert produces no decision. |
| Monitor | An alert remains below the corroboration criteria. An isolated alert, a server error spike, or high volume alone can prompt review. |
| Would rate-limit | At least 40 requests in the Stage 2 route burst, with sampled arrivals spanning at least 3 seconds. Requires at least 8 login denials or 5 authorization denials, with at least 5 denials evidenced on the same route. Proposes 60 requests per minute for 60 seconds. |
| Would block | At least 8 explicit login denials, 5 explicit authorization denials, and 8 unmatched probes from three distinct rules on the same application. Records a 120-second proposal scoped to the login route. |

Corroboration uses active alerts from the same authenticated deployment within 120 seconds. It considers evidence quality, severity, counts, route, and duration. Alerts with protected or exempt evidence are excluded. Aggregate proposals are for review. Enforcement requires an application-issued pseudonym and evidence for the exact method and route. The policy accepts no IP or forwarded headers as identity evidence.

Proposals expire automatically in the dashboard, with a hard maximum of 300 seconds. Repeated matches cannot extend the original expiry. The same alert set is deduplicated, and new proposals for the same app, action, and route must wait until expiry plus the cooldown (120 seconds by default). Disposition and expiry affect the proposal record only.

## State and operator controls

The worker installs a SQLite queue that coalesces updates by alert ID. It processes small batches and saves decisions and queue acknowledgements in one transaction. A failed transaction leaves the alerts queued. It skips stale or pre-activation evidence and retains decisions for 30 days. The audit table persists mode changes, emergency toggles, policy configuration diffs, and dismissals. The dashboard shows the latest 40 decisions and 20 audit entries. Browser actions require the existing loopback operator session, same origin, and CSRF validation. The audit identifies operator, local CLI, or worker activity; the existing single administrator token does not identify multiple individual operators.

In [Monitored Applications](http://localhost:8002/dashboard/applications), sign in and scroll to **Protection Overview**. Inspect **Protection Decisions** for request IDs, supporting rules, reasons, expiry, and enforcement status. Expand **Policy Management** for thresholds, allowlists, exemptions, and the audit history. **Dismiss proposal** records a disposition and keeps the original decision. **Emergency disable** returns to Alert Only and dismisses outstanding proposals. **Reset emergency switch** leaves the system in Alert Only until an operator separately enables Shadow.

## Staging enforcement and attribution

Northfield issues a pseudonym after verifying the JWT, persisted session, student account, and CSRF for writes. HMAC binds a Northfield-only attribution key to the app ID, environment, internal user ID, and account creation time. The wire carries only the resulting pseudonym. Anonymous callers, failed authentication, invalid CSRF, and administrators have no enforceable attribution. The collector accepts attributed events under signed `-staging` and `-prod` app IDs. The route-burst and authorization-denial windows partition attributed observations by subject, method, and route. Course access reports an explicit denial when an authenticated student lacks enrollment for an existing course. The public response remains HTTP 404 in both missing-course and missing-enrollment cases.

An approvable proposal requires a verified subject on an allowlisted write route. That subject must meet the sustained route-burst threshold, show successful requests in the burst sample, and produce explicit authorization denials on that same route. The default denial minimum is five for rate limiting and eight for staging blocks. Production supports approved rate limits. Approval rechecks both active alerts, current thresholds and exemptions, destination identity, expiry, emergency state, and duplicate scope. Operator approval is required for every active rule. Health, login, logout, account recovery, administrator, and unlisted routes stay outside policy enforcement.

Staging policy delivery uses a separate loopback service at `POST /v1/policy/sync` on port 8093. Each app has its own policy key, separate from telemetry, attribution, and JWT keys. A versioned HMAC-authenticated sync carries the app, environment, timestamp, nonce, and batched receipts. The server enforces a nonce window and binds each signed response to the requesting nonce. Policy snapshots carry a unique ID, increasing revision, creation and expiry times, and up to 16 exact subject/method/route rules. The maximum snapshot lifetime is 120 seconds. Northfield validates all fields and persists its greatest installed revision in PostgreSQL, or in a sidecar for local SQLite. Restarting starts with an empty cache. An operator can publish a fresh revision without extending any rule. Polling an expired snapshot returns a new empty revision.

The Monitored Applications timeline records recovery after it can match a prior signed enforcement receipt with a successful signed request for the same application, subject, method, and route. The successful request identifies an acknowledged revision under which its scope was unrestricted. The dashboard shows request rate over a ten-second window, total accepted requests, HTTP 429s, and whether an observed request received a mitigation response. The total starts with retained observations at the first upgraded collector startup.

Northfield polls in the background. A failed sync clears the active cache, and expiry works with a monotonic deadline. The inline check reads only local bounded state. It gives matching subjects a fixed-window limit or returns a generic 403 with no detection details. A 429 includes a bounded `Retry-After`. A local `.policy-disabled` marker beside the staging database disables the installed revision. Removing the marker requires a fresh approved revision before enforcement resumes. **Revoke / unblock** publishes a new revision without the selected rule. The dashboard’s emergency switch publishes disabled snapshots for all staging channels. Northfield sends authenticated receipts for applied/disabled revisions and actual blocks or rate-limit responses. Its receipt buffer is bounded and in memory, so saturation or restart can drop unreported receipts.

## Run the isolated mitigation test

Use a Python environment with both repositories’ test dependencies and keep the local Northfield staging branch checked out. From the Sentinel root:

```powershell
$env:NORTHFIELD_STAGING_CHECKOUT = Join-Path $PWD.Path '.northfield-local'
# Optional when Northfield dependencies are in a separate environment.
# $env:NORTHFIELD_STAGING_DEPS = '<Northfield venv>\Lib\site-packages'
python -m pytest -q tests/test_staging_mitigation.py
```

The end-to-end test uses ephemeral loopback ports and temporary storage. Set `NORTHFIELD_TEST_DATABASE_URL` to a disposable loopback PostgreSQL connection URL to run the real HTTP case against PostgreSQL. The test creates and removes its own schema. Two successful requests and two enrollment denials provide the evidence for a rate-limit proposal, using lower thresholds in the isolated test. Approval through the private dashboard API results in HTTP 429 for the target. The test matches that response ID to its signed event and receipt, confirms a second user can use the same route, checks the target's unrelated route, and waits for the authenticated WebSocket to report verified recovery after revocation. Separate tests cover expiry, sync failure, duplicate delivery, replay, and invalid signatures.

For an interactive staging setup, use an isolated Sentinel database and pass `HTTP_STAGING_POLICY_KEYS` as a JSON map of staging app IDs to independently generated 64-digit hex keys. Start the channel with:

```powershell
python -m uvicorn backend.telemetry.policy_api:app --host 127.0.0.1 --port 8093 --no-proxy-headers --no-access-log --limit-concurrency 24 --ws none
```

Point the isolated Northfield backend at `PROTECTION_URL=http://127.0.0.1:8093/v1/policy/sync`. Set `PROTECTION_HMAC_KEY` to the registered channel key and `PROTECTION_SUBJECT_KEY` to a separate 32-byte hex key. Use a `-staging` telemetry ID, independent credentials, and a test database. Start the Stage 2 and Shadow workers against the isolated Sentinel database. See the [Northfield launch guide](NORTHFIELD_TELEMETRY.md) for the collector and backend process pattern. Keep the policy channel off every public tunnel.

In Attack Lab, **View Northfield staging evidence** opens the authenticated Monitored Applications dashboard with `northfield-staging` selected. Use this view to inspect signed portal requests, evidence and proposals, policy delivery, enforcement receipts, and recovery. The existing Attack Lab controls operate on Sentinel’s own loopback endpoint.

## Run and recover

From the Sentinel root, point both workers and the dashboard at the same database. Start the Stage 3 worker in one PowerShell window and change mode from a second window or from the dashboard.

```powershell
$env:HTTP_TELEMETRY_DB = Join-Path $PWD.Path 'data\http-telemetry.sqlite3'
python -m backend.telemetry.protection
```

```powershell
$env:HTTP_TELEMETRY_DB = Join-Path $PWD.Path 'data\http-telemetry.sqlite3'
python -m backend.telemetry.protection --mode shadow
# Emergency stop for proposals, even if the dashboard is down
python -m backend.telemetry.protection --mode emergency-disable
# Reset the latch. This leaves Alert Only selected.
python -m backend.telemetry.protection --mode reset-emergency
```

Restart the worker against the same database to resume. A stale heartbeat indicates the evaluator is offline; check its log, database path, and policy file. If Sentinel is unavailable, existing Northfield request handling continues. Future inline enforcement should default to fail-open on missing, stale, or invalid policy. Fail-closed would reject legitimate traffic during control-plane outages and requires a separately approved availability tradeoff.

Set `HTTP_PROTECTION_CONFIG` to a local TOML file and restart the protection worker to load it. All limits are validated, and configuration changes are audited.

```toml
window_seconds = 120
cooldown_seconds = 120
rate_limit_seconds = 60
block_seconds = 120
minimum_burst = 40
minimum_burst_duration_seconds = 3
minimum_login_denials = 8
minimum_authorization_denials = 5
minimum_unmatched = 8
proposed_requests_per_minute = 60

[applications.example-test]
allowlisted = true

[applications.northfield-prod]
routes = ["/api/example/{item_id}"]
rules = ["server_errors"]
```

## Isolated demonstration

```powershell
$DemoDb = Join-Path $PWD.Path ('data\http-shadow-demo-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.sqlite3')
python -m backend.telemetry.replay --shadow --db $DemoDb
$env:HTTP_TELEMETRY_DB = $DemoDb
$env:CLOUDFLARE_TUNNEL_TOKEN = ' '
$env:CLOUDFLARE_TUNNEL_MODE = 'disabled'
$env:DASHBOARD_REMOTE_ENABLED = 'false'
$env:HTTP_FLOOD_REMOTE_ENABLED = 'false'
$env:PORT = '8003'
python -m uvicorn app:app --host 127.0.0.1 --port 8003 --no-proxy-headers
```

Open the [isolated dashboard](http://localhost:8003/dashboard/applications). The replay signs all batches locally, checks an ordinary workflow and the six Stage 2 patterns, then demonstrates one rate-limit proposal and one block proposal. It refuses to open an existing database. It never sends test traffic to public Northfield or Cloudflare.

## Production rollout after approval

### Current deployment gate

Render showed commit `7592233464c60fc7829e2c195dbba4ef24e694b2` as live in deployment `dep-dc0sfmjm8hqs73fgg85g` on November 22, 2026. Record the reviewed PostgreSQL-capable release SHA after integration review and merge. [Live Render deployment](https://dashboard.render.com/web/srv-dc0om6u1egvs738jark0/deploys/dep-dc0sfmjm8hqs73fgg85g)

Deployment is blocked on data preservation. The live deployment was confirmed on Render Free, which reports shell access is unavailable. The deployed blueprint uses `SQLITE_PATH=/tmp/northfield/portal.sqlite3` and `SEED_DEMO_DATA=true`. The bootstrapped demo tables can coexist with later student accounts, enrollments, submissions, and activity. No complete private export was found in the application or repository. The Sentinel event database contains telemetry only. [Render Free limitations](https://render.com/docs/free)

Keep the current instance in place. If a private backup known to originate from this Render database exists, verify its freshness and integrity, rehearse the import on isolated PostgreSQL, and confirm the restored record counts and how to capture any writes after the export. If a backup is unavailable, establish whether the provider can recover the running database before any plan change or redeploy. Starting with an empty PostgreSQL database requires explicit owner approval that accepts possible loss of existing records. Approval to change Render or deploy is separate.

From the Northfield `backend` directory, run `python -m app.import_sqlite '<verified-backup-path>' --inspect` and compare the digest and counts with the authorized export record. Render’s ephemeral shell starts a separate instance from the build image and cannot read the live Free service’s filesystem. [Render shell access](https://render.com/docs/ssh)

Set `DATABASE_URL` privately to the direct PostgreSQL endpoint with certificate verification, set `SEED_DEMO_DATA=false`, then run `python -m app.bootstrap` and `python -m app.import_sqlite '<verified-backup-path>' --expected-sha256 '<approved SHA-256>'`. PostgreSQL stores portal records and policy revisions. Configure the upgraded Sentinel collector before deploying this Northfield sender so the collector accepts the additional policy metadata.

Verify the existing Render collector URL is reachable before deployment. Starting a new Quick Tunnel gives it a new hostname. If the saved URL is stale, keep the application ID and HMAC key, and include a collector URL update in the separately approved Render environment change. Leave the policy service and policy tunnel off.

### Latest isolated verification

The real HTTP lifecycle ran on loopback with Northfield using PostgreSQL 18.6. Sentinel's SQLite ledger matched HTTP 429 request `8bac6a72-853c-4c9f-bf09-412775b15da3` to its signed rate-limit receipt. It then recorded HTTP 204 request `4ba5c5ce-082b-456e-bf05-decd437dc47c` as recovery under acknowledged revocation revision 4. A second signed-in student retained access to the same route, and the targeted student retained access to an unrelated route.

Northfield's PostgreSQL suite passed 21 tests, including transactional import of a synthetic SQLite backup, login, enrollment, submissions, sessions and policy watermark persistence after restart. The SQLite regression run passed 20 tests and skipped the PostgreSQL-specific test. Sentinel passed 170 Python tests across the defensive suite, including GATv2, plus seven JavaScript tests. Production data import, hosted PostgreSQL, attributed Render telemetry and Remote HTTPS policy delivery remain to be verified.

### Checkpoint 1 — Northfield merge and Sentinel restart

The live `northfield-portal-api` service tracks `main`, and its Auto-Deploy selector was verified as **Off** during preflight. Recheck it immediately before merging. Verify the frontend service is also Off if it could deploy from this merge. If a linked service has auto-deploy enabled, get separate approval to pause it first. Approval to publish the branch and open a pull request does not authorize merging. [Render automatic deployment behavior](https://render.com/docs/deploys)

```powershell
git -C .northfield-local fetch --no-tags origin main
git -C .northfield-local log --oneline origin/main..HEAD
git -C .northfield-local diff --check origin/main
# After approval to publish the branch:
git -C .northfield-local push -u origin codex/northfield-staging-mitigation
```

After approval to publish the updated changes, open or update a pull request against `main`. Confirm its head includes the reviewed PostgreSQL migration, data import command, new wire metadata, and sync-only setting. Wait for required checks and separate merge approval. After merge, record the full SHA on `main` for the manual deploy.

Record the current Sentinel code revision and database location. Take a consistent SQLite backup with the SQLite backup API while the live database may be using WAL. Set `HTTP_TELEMETRY_DB` to the existing absolute path for the collector, dashboard, and both workers. Keep the existing `HTTP_TELEMETRY_KEYS`, `ADMIN_TOKEN`, loopback bindings, telemetry proxy, and Quick Tunnel. Start both workers with `python -m backend.telemetry.detection` and `python -m backend.telemetry.protection`. Restart the collector and dashboard using the [existing startup commands](NORTHFIELD_TELEMETRY.md#restarting-a-demonstration-on-windows). Verify retained events, alerts, and decisions, confirm the detector cursor advances, and check both worker heartbeats. Use the private **Shadow** control or `python -m backend.telemetry.protection --mode shadow` if Shadow is inactive. Resolve any latched emergency with the operator before changing mode.

With `HTTP_TELEMETRY_DB` pointing to the live file, create a private backup from the Sentinel root:

```powershell
$env:SENTINEL_DB_BACKUP = Join-Path $PWD.Path ('data\http-telemetry-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.sqlite3')
@'
from contextlib import closing
from pathlib import Path
import os
import sqlite3

source = Path(os.environ['HTTP_TELEMETRY_DB']).resolve(strict=True)
backup = Path(os.environ['SENTINEL_DB_BACKUP'])
with backup.open('xb'):
    pass
with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as live, closing(sqlite3.connect(backup)) as saved:
    live.backup(saved)
    if saved.execute('PRAGMA integrity_check').fetchone() != ('ok',):
        raise SystemExit('SQLite backup failed integrity check')
print(backup)
'@ | python -
```

### Checkpoint 2 — Deploy attributed Shadow Mode

**Check Northfield data durability before approving a deploy.** The live API is on Render Free without a persistent disk. The blueprint places SQLite under `/tmp/northfield`. A redeploy, restart, or idle spin-down can discard accounts, enrollments, submissions, and other state written to local SQLite. A deploy rollback restores the selected build and configuration. It cannot restore lost student data. Confirm the production data is disposable demo data with explicit authorization to reset it, or verify a supported backup and restore path before scheduling a deploy. Record the currently healthy Render deploy ID and commit, and confirm its rollback artifact is still available. [Render Free storage limits](https://render.com/docs/free#local-files-lost-on-redeploy) · [Render rollback behavior](https://render.com/docs/rollbacks)

After approval to change Render and deploy, select **Save only** on **northfield-portal-api → Environment**. Preserve unrelated settings. Use the following values for the Shadow rollout. [Render environment variables](https://render.com/docs/configure-environment-variables)

| Render variable | Shadow rollout value |
| --- | --- |
| `TELEMETRY_APP_ID` | `northfield-prod` |
| `TELEMETRY_COLLECTOR_URL` | Existing HTTPS Quick Tunnel URL ending in `/v1/http-events` |
| `TELEMETRY_HMAC_KEY` | Existing matching collector key |
| `PROTECTION_SUBJECT_KEY` | New Northfield-only key, 32 random bytes as 64 lowercase hexadecimal characters |
| `PROTECTION_PRODUCTION_ENABLED` | `false` |
| `DATABASE_URL` | Verified production PostgreSQL URL with `sslmode=verify-full` |
| `SEED_DEMO_DATA`, `PROTECTION_SYNC_ONLY` | `false` |
| `PROTECTION_URL`, `PROTECTION_HMAC_KEY`, `PROTECTION_STATE_PATH` | Unset |

Keep `HTTP_POLICY_ALLOW_PRODUCTION` false or unset on Sentinel, leave the policy listener and policy tunnel stopped, and check that zero production policy channels are enabled. The Render receiver must remain off throughout this rollout.

Deploy the reviewed **merged** commit from Render’s Deploys page or use the Render CLI in an authenticated shell. Verify the exact SHA, successful deployment, and `GET /health` returning HTTP 200. [Specific commit deployment](https://render.com/docs/deploys#deploying-a-specific-commit) · [Render CLI options](https://render.com/docs/cli-reference)

```powershell
$RenderServiceId = 'srv-dc0om6u1egvs738jark0'
$ApprovedMergeCommit = '0c80c5fdce4f06dccedddb61ada60d9eab3180ca'
render deploys create $RenderServiceId --commit $ApprovedMergeCommit --wait
curl.exe --fail --silent --show-error https://northfield-portal-api.onrender.com/health
```

1. Open the authenticated [Monitored Applications dashboard](http://localhost:8002/dashboard/applications), select `northfield-prod`, and confirm **Shadow Mode** and **Production enforcement is disabled**.
2. With an authorized student test account, sign in through the normal portal, open the account page, then open an already enrolled test course. In the browser's Network panel, record only the `X-Request-ID`, route, and status for the ordinary authenticated API calls. Use a second authorized student test account for one equivalent request if available.
3. Match those IDs and statuses under **Recent requests**. Confirm the same `s1_…` pseudonym on both authenticated calls from the first student and a different pseudonym for the second student. Sign-in and anonymous events can have an empty pseudonym. Confirm delivery is receiving, loss counters are stable, and the detector consumes the observed event. Keep credentials, request content, and PII outside the verification record.
4. Confirm the approved ordinary student workflows return their normal status and no probe receives a policy-issued HTTP 429. If an unexpected 429 occurs, compare its ID against Sentinel and review whether Northfield's existing application controls produced it before attributing it to Sentinel. Confirm zero active production rules throughout.
5. Leave production thresholds unchanged. Review naturally occurring proposals for the expected identity, method, route, timestamps, and corroborating request IDs. Collecting a few ordinary requests only proves attribution and connectivity. Validate the proposal path using the isolated production-format test in the staging suite. Record production proposal generation as pending if ordinary traffic does not naturally meet the thresholds.

### Checkpoint 3 — Disabled policy synchronization

Only after separate approval, use the Uvicorn command above for a dedicated policy service on `127.0.0.1:8093`. For a temporary pilot, run `cloudflared tunnel --url http://127.0.0.1:8093` in a separate window to obtain a second Quick Tunnel hostname. Set `HTTP_POLICY_PUBLIC_HOST` to that exact hostname and `HTTP_PRODUCTION_POLICY_KEYS` to a JSON map containing `northfield-prod` and a separate 32-byte hex key. Set `HTTP_POLICY_ALLOW_PRODUCTION=false` and use the same `HTTP_TELEMETRY_DB`. Keep admin and dashboard routes private. The only public policy path is `POST /v1/policy/sync`. A request without a valid signature must return 401 and other methods and paths return 404. Quick Tunnel hostname changes require updating the issuer's `HTTP_POLICY_PUBLIC_HOST` and Render's `PROTECTION_URL` before sync resumes.

For the authorized disabled-delivery rehearsal, set Render `PROTECTION_URL=https://<policy-host>/v1/policy/sync`, `PROTECTION_HMAC_KEY` to the matching independent policy key, and `PROTECTION_SYNC_ONLY=true`. Keep `PROTECTION_PRODUCTION_ENABLED=false`. Northfield stores revision state in the migrated PostgreSQL database. Retain independent attribution, telemetry, and JWT keys. Use one replica and one web worker. Confirm a signed, empty, disabled snapshot, a fresh `disabled` acknowledgment, persistence across a receiver restart, and zero active rules.

### Checkpoint 4 — Enforcement authorization and rollback

Production enforcement requires distinct approval. Set Northfield `PROTECTION_SYNC_ONLY=false` and `PROTECTION_PRODUCTION_ENABLED=true` and reload. Set `HTTP_POLICY_ALLOW_PRODUCTION=true` on the issuer and reload. With a fresh disabled acknowledgment, an operator must choose **Enable production**. Wait for an applied acknowledgment of the enabled revision, then approve each specific rate limit individually. Returning to **Alert Only** disables the production channel and clears its rules.

For fast rollback, revoke the individual rule or use **Emergency disable**, then confirm the new revision was received. A delivery failure clears the receiver cache. A later authorized settings change can return Northfield to sync-only or Shadow Mode. After the database cutover, any application rollback build must support the same PostgreSQL schema and connection settings. Confirm `/health` and ordinary portal access. Keep the Sentinel SQLite database and the PostgreSQL watermark. Restore an earlier database backup only for data recovery because it discards newer history. [Render rollback behavior](https://render.com/docs/rollbacks)

## Rollout regression checks

From the Sentinel root, use a Python environment with the dependencies of both repositories or set `NORTHFIELD_STAGING_DEPS` as described above.

```powershell
python -m pytest -q tests/test_staging_mitigation.py tests/test_telemetry_ingest.py tests/test_http_detection.py tests/test_http_protection.py tests/test_remote_demo.py tests/test_cloudflare_tunnel.py tests/test_chat_service.py tests/test_gatv2.py tests/test_unified_threat_engine.py --tb=short -W ignore
node --test tests/demo_auth_ui.test.cjs tests/http_flood_ui.test.cjs
```

From the Northfield backend directory, run `python -m pytest -q --tb=short` using the Northfield Python environment. The cross-repository tests exercise signed production-format fixtures against an isolated collector and actual portal requests against isolated staging. Use only the ordinary authenticated workflow above to verify attributed delivery after an approved Render deploy.

Rollout rehearsal results: 111 Sentinel Python tests passed, 20 Northfield backend tests passed, and 7 JavaScript tests passed. The dashboard script also passed `node --check`.

The optional `python -m pytest -q tests/test_gatv2_mixed.py` check requires `data/cleaned_dataset.csv`, which is absent from the checkout used for this rollout rehearsal.

The rehearsal restarted the collector, authenticated dashboard, detector, and protection worker twice on an isolated SQLite backup made from the live database in read-only mode. It retained 21 events and Shadow Mode, advanced the detection cursor from 14 to 15, and rejected a nonce replay and a duplicate request after restart. The backup contained no alert or decision rows. A separate loopback HTTPS rehearsal rejected an untrusted certificate and verified signed disabled delivery and acknowledgment after restarting the Northfield receiver on the same SQLite sidecar. Attributed Render telemetry and public policy synchronization remain post-approval checks.

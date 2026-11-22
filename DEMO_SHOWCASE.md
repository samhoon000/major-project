# Sentinel and Northfield showcase

## Start on Windows

From the Sentinel repository root in PowerShell, use the Python environment with Sentinel's `requirements.txt` and Northfield's `.northfield-local/backend/requirements-dev.txt` installed. Install the locked Northfield frontend dependencies with `npm.cmd ci --include=dev` in `.northfield-local/frontend`.

If Northfield's Python packages are installed separately, set their absolute path. This workspace uses:

```powershell
$env:NORTHFIELD_STAGING_DEPS = (Resolve-Path .northfield-local/.test-deps).Path
rtk proxy python showcase.py
```

The launcher builds the frontend, creates an isolated database and telemetry ledger, and verifies one signed identity observation for each student. It prints the shared course URL, an operator token, and passwords for `showcase-student@example.com` and `showcase-second@example.com`. Use the values from your current run. Keep the launcher terminal open and press Ctrl+C to stop the services.

| Page | Default URL |
| --- | --- |
| Sentinel Overview | [127.0.0.1:8012/dashboard](http://127.0.0.1:8012/dashboard) |
| Northfield sign-in | [127.0.0.1:8011/login](http://127.0.0.1:8011/login) |
| Monitored Applications | [127.0.0.1:8012/dashboard/applications](http://127.0.0.1:8012/dashboard/applications) |
| Attack Lab | [127.0.0.1:8012/attack-lab](http://127.0.0.1:8012/attack-lab) |
| Network Analysis | [127.0.0.1:8012/dashboard/network](http://127.0.0.1:8012/dashboard/network) |
| Settings | [127.0.0.1:8012/dashboard/settings](http://127.0.0.1:8012/dashboard/settings) |
| Secure Chat | [127.0.0.1:8012/chat](http://127.0.0.1:8012/chat) |
| Chat Security | [127.0.0.1:8012/dashboard/chat-security](http://127.0.0.1:8012/dashboard/chat-security) |
| Isolated HTTP Flood Lab | [127.0.0.1:8012/attack-lab?view=legacy](http://127.0.0.1:8012/attack-lab?view=legacy) |

## Two-minute monitoring walkthrough

1. Open **Settings**. Paste the launcher token into **Administrator token**, then select **Authenticate**. Open **Overview** and point out the overall status and the separate series for application detections and confirmed blocks. Choose **View Monitoring** and confirm Northfield reads **Connected**.
2. Sign in to Northfield with the two disposable accounts in separate browser profiles. Open the shared course URL once in each profile. Return to Sentinel and point out the normal traffic bars and the two signed HTTP 204 responses.
3. Select **Request evidence** on either student card. Show the response time, pseudonymous subject, and request ID. Close **Technical Evidence** to return to the monitoring view.
4. Point out the scoped staging threshold, the alert indicator, and the **Mitigation** panel. The panel shows eligible approval and revocation controls and reports whether Northfield acknowledged the current revision.
5. Open **Network Analysis** to show the capture status, topology, and latest GATv2 prediction. Open **Attack Lab → Advanced labs** to find the separate isolated lab. The Northfield view receives its traffic directly from the signed application ledger.

## Read the graph

The last two minutes are divided into one-second buckets by request timestamp. Empty seconds are zero. **Suspicious** counts retained requests named in detection evidence, excluding alerts marked false positive. **Policy blocked** counts observed responses correlated with a signed block or rate-limit receipt. The chart footer counts every observed HTTP 429, including responses without a matching policy receipt. Requests with an HTTP status under 400 and no matching security evidence are shown as **Normal**. Remaining HTTP errors are counted separately.

The staging threshold applies to one student's course-access route over the detector's arrival window. It is displayed with its scope beside the graph. Markers show retained detection signals, signed acknowledgments for approval revisions, and verified recovery. Student cards report the last observed course-access response. The collector and receiver statuses describe how current those records are.

**Technical Evidence** contains the original request comparison and recent requests, alert detail, protection decisions, signed policy receipts, revisions, and security event timeline. Advanced policy operations use the same operator session, origin checks, and CSRF protection as the compact controls.

## Scenario and verification scope

The pre-existing request-rate showcase remains accessible at `/dashboard/applications?app=northfield-staging&view=legacy`. The earlier two-cycle Playwright results apply to that original view. The redesigned Attack Lab is a navigation page. This revision did not add a Northfield request generator or a repeated unauthorized-access scenario.

Network Analysis uses the existing capture API for packet rates, observed endpoints, and GATv2 scores. Overview counts retained signed block receipts and active application alerts. Its chart and five-event list use the bounded recent evidence from the application stream. Secure Chat has a separate **Chat Security** page. The previous combined dashboard and dataset graph remain accessible under **Settings → Advanced diagnostics**.

- Playwright verified the local routes, sidebar active states, browser history, refresh, shared operator sign-in, idle and disconnected states, signed Northfield requests, and the advanced links. It compared a topology edge with the live network API and confirmed completed GATv2 analyses.
- The focused Sentinel suite passed 37 tests, with 3 deselected. Nine JavaScript UI tests passed. The Northfield backend passed 21 tests and skipped the PostgreSQL integration test because no disposable PostgreSQL URL was configured. Both frontend production builds passed.
- The live browser checks used temporary loopback ports. The redesigned view has no browser verification of detection through enforced HTTP 429 and recovery, repeat runs, or interruption cleanup.

## Screenshots

Screenshots show the running local services at 1920 × 1080 and 1366 × 768. Full-page captures include content below the fold.

| View | Desktop | Laptop |
| --- | --- | --- |
| Overview | [Desktop](docs/screenshots/console/overview-desktop.png) | [Laptop](docs/screenshots/console/overview-laptop.png) |
| Monitored Applications | [Desktop](docs/screenshots/console/applications-desktop.png) | [Laptop](docs/screenshots/console/applications-laptop.png) |
| Attack Lab | [Desktop](docs/screenshots/console/attack-lab-desktop.png) | [Laptop](docs/screenshots/console/attack-lab-laptop.png) |
| Network Analysis | [Desktop](docs/screenshots/console/network-desktop.png) | [Laptop](docs/screenshots/console/network-laptop.png) |
| Settings | [Desktop](docs/screenshots/console/settings-desktop.png) | [Laptop](docs/screenshots/console/settings-laptop.png) |
| Chat Security | [Desktop](docs/screenshots/console/chat-security-desktop.png) | [Laptop](docs/screenshots/console/chat-security-laptop.png) |
| Legacy HTTP Flood Lab | [Desktop](docs/screenshots/console/legacy-lab-desktop.png) | |

## Troubleshooting

- Use `rtk proxy python showcase.py --check` to verify startup, then stop the services automatically.
- If startup fails, inspect the named logs under `data/showcase-*`. Verify that Python dependencies, Node.js, and the Northfield checkout are available.
- If the token or a student session expires, use credentials from the current launcher. Each run has its own keys and databases.
- A disconnected stream reconnects automatically. A stale policy receiver means the dashboard cannot confirm that mitigation is active. Wait for acknowledgment before presenting a policy change as applied.


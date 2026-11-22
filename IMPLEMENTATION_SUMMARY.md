# Sentinel implementation summary

## Repository evidence

- Starting revision `fabcafa3adbb9c6791c5ddead7106aadf0a835c5`. Existing uncommitted work was present in the network capture, Northfield evidence, and enforcement paths.
- `origin/codex/realtime-security-verification` resolves to `e801b80`. Its tree contains `NETWORK_DEMO.md`, `backend/network/runtime.py`, GATv2 inference, and dashboard event handling. The HTTP lab route and guard were added later in `235dfbc` and `cb37f89`, with operator and console integration in `c8d9b47`.
- The local demonstration uses the existing guard and detector with a fixed quota profile, scoped capability, actual HTTP response accounting, and the existing dashboard event broadcaster. The rule activates automatically when observed requests reach the isolated policy threshold.

## Changes

- `backend/attack_lab.py`, `backend/security/http_flood.py`, and `app.py` serve and manage the local policy check and report the lifecycle.
- `backend/console/attack-lab.*`, `overview.*`, `network.*`, `layout.*`, `settings.html`, and `backend/console.py` render the standalone lab, detection pipeline, telemetry, and navigation.
- `backend/telemetry/northfield_monitor.html` aligns the application panel with the console styling.
- `demo_local.py` starts the existing FastAPI routes and network runtime on loopback. `demo_preflight.py` checks the local service, dashboard routes, WebSocket, guard, and model. `tests/test_policy_verification.py` exercises the real HTTP and dashboard stream sequence.

## Historical HTTP chart restoration

- The chart source is `feature/sentinel-http-demo` at `cb37f89`. Monitored Applications uses the original `chart(state)` function from `backend/static/http_flood.js` and the SVG, legend, and chart CSS from `backend/http_flood_ui.py`. It preserves the 900 × 230 view box, 60-second window, three series, dashed threshold, and historical scale calculation. That component has static SVG paths and labels.
- The chart consumes the verification profile's live WebSocket snapshots and uses HTTP polling for recovery. The existing telemetry publisher samples at half-second intervals. Reset clears prior run samples.
- The historical controls were Requests / second (25), Duration in seconds (8), and Concurrency (4). The branch had no separate request-count input. The current policy check locks the request rate and concurrency at one, accepts a duration from one through ten seconds, and defaults to four. The graph's dashed line reads the current policy's actual threshold.
- The standalone page retains Start, Stop, Reset, and automatic mitigation. The live check remains an isolated policy exercise. The historical workload and auxiliary monitor controls differ from the current local workflow.
- This restoration changed `backend/attack_lab.py`, `backend/security/http_flood.py`, `backend/console/layout.css`, and the standalone `attack-lab.html` and `attack-lab.js`. It added `backend/console/http-flood-chart.css` and `backend/console/http-flood-chart.js`.
- The targeted regression run passed 18 Python tests and 17 subtests. The Node suite passed 10 tests, including renderer equivalence, series coordinates, and reset. The SentinelGraph TypeScript and Vite build passed. The real-socket tests verified duration validation, two- and four-second runs, automatic mitigation, HTTP 429 responses, Stop, Reset, dashboard events, and temporary restriction expiry.

## References

- Suricata EVE documents distinct alert, anomaly, flow, and statistics event types. This informed keeping operational metrics distinct from incident evidence. [Suricata EVE documentation](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- Zeek distinguishes wire-observed network connections and protocol logs. The console keeps packets, flows, and application request evidence separately attributed. [Zeek logs](https://docs.zeek.org/en/current/tutorial/logs.html)
- The Overview reconnects its existing dashboard WebSocket and reads the current snapshot through the local API. [FastAPI WebSocket documentation](https://fastapi.tiangolo.com/advanced/websockets/)

## Passive TCP port scan detection

- `backend/network/port_scan.py` tracks initial SYNs by TCP tuple and sequence number, matches TCP refusals to the original attempt, and groups distinct and refused ports by source and destination. It retains one alert per active pattern. The configurable observation window defaults to 30 seconds and can be set with `SENTINEL_PORT_SCAN_WINDOW_SECONDS`.
- `backend/network/capture.py` exposes TCP sequence and acknowledgment fields. `backend/network/runtime.py` observes the existing capture output and samples the rolling counts. GATv2 and the HTTP flood detector continue processing their own evidence.
- `backend/attack_lab.py` serves the localhost-only snapshot and dedicated verification endpoint. A matching loopback source and target pair receives a temporary HTTP restriction on that endpoint. A subsequent HTTP 429 records the outcome. The restriction applies at the HTTP layer.
- `backend/console/port-scan-monitor.html`, `port-scan.js`, and the Attack Lab section render the shared evidence. The chart polls the local API, draws three observed series, and places a marker at the detection time. The graph's mount point is in `backend/telemetry/dashboard.html` and `dashboard.py`. `backend/console/layout.js` provides the marker option.
- `tests/test_port_scan.py` covers TCP matching, distinct port thresholds, duplicate handling, and expiry. `tests/test_policy_verification.py` verifies a real HTTP 429 at the dedicated route after feeding in-memory capture data into the detector.
- `tests/port_scan_ui.test.cjs` verifies the three chart series, missing-sample handling, and detection marker placement. The final regression run passed 39 Python tests and 11 Node tests. The TypeScript and Vite build passed.
- The detection window follows the Zeek failed-connection and distinct-port model. NCSA's notice suppression informed alert deduplication. psad informed the separation between alert, applied restriction, and enforcement evidence. [Zeek](https://github.com/zeek/zeek) · [Zeek scan policy](https://docs.zeek.org/en/v6.0.9/scripts/policy/misc/scan.zeek.html) · [NCSA bro-simple-scan](https://github.com/ncsa/bro-simple-scan) · [psad](https://github.com/mrash/psad)

# Sentinel demo readiness

**READY WITH LIMITATIONS**

## Verified demonstration

The standalone Attack Lab runs an always-active, loopback-only HTTP rate-policy check. The lab reports HTTP response metrics, a five-stage Attack Lifecycle, and the measured result. Overview receives the alert, automatic mitigation, and verified rejection through Sentinel's existing dashboard event stream.

The launcher rehearsal measured four requests, two HTTP 200 responses, two HTTP 429 responses, zero failures, and 8.97 ms mean response latency. The decision came from the rule-based HTTP flood detector. The verified event was recorded after the isolated client received a subsequent HTTP 429.

The socket tests also verified ordered dashboard events, same-origin request validation, Stop, Reset, repeatability, and temporary restriction expiry. Dashboard, Network Analysis, Monitored Applications, Chat Security, and Settings returned HTTP 200 over loopback.

## Network and model evidence

On this Windows host, the preflight reported live capture on Wi-Fi and a loaded GATv2 checkpoint. During the launcher rehearsal the network API reported 1,864 captured packets, seven inference graphs, and 72 predictions. Local preflight inference returned a finite anomaly probability of 0.3293 on its read-only fixture. Network capture and GATv2 classifications have their own evidence in the dashboard.

A separate rehearsal waited through the flow-expiry window. The selected Wi-Fi adapter returned zero completed loopback flows to the test listener and zero GATv2 results associated with that run. The HTTP guard independently returned two HTTP 429 responses.

## Test results and limits

- Selected Python regression suite passed 96 tests and 17 subtests, with two skips and one deselected case. A broader attempt stalled in the existing Chat Security monitor WebSocket test. The local dashboard event-stream test passed.
- An additional 45 application telemetry, protection, and monitoring tests passed.
- Final real-socket policy integration passed both tests. The Node suite passed all nine tests. JavaScript syntax checks, Python compilation, the SentinelGraph TypeScript and Vite build, and the Git diff check passed.
- The launcher and preflight ran over genuine local sockets. Visual browser review and live delivery from the external Monitored Applications integration remain unverified.
- The HTTP result above is from the four-second default run. The isolated policy check also supports up to ten sequential requests. A subsequent HTTP 429 proves enforcement for that temporary client capability and request path.

See the [Windows runbook](DEMO_RUNBOOK.md) and [implementation summary](IMPLEMENTATION_SUMMARY.md).

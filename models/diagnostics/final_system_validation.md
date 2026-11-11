# Final System Validation

**Status: PARTIALLY COMPLETE.** No model was trained or promoted. The active checkpoint remains `models/gatv2_model.pth`.

## Verified runtime

- Npcap is installed; the `npcap` service and capture DLLs were verified earlier in this session. Scapy capture worked on the Wi-Fi NPF interface `\\Device\\NPF_{1F341169-C1D1-4BBE-8C0D-3E33B9534E0C}`.
- The updated app ran on port 8001. After the final code restart, `GET /api/network/state` was queried twice six seconds apart while a chat client was connected: packets rose from 3,436 to 3,452, bytes from 2,244,324 to 2,247,206, completed flows from 201 to 208, and GATv2 analyses from 199 to 203. Capture reported `running`; the selected interface matched the configured Wi-Fi NPF interface.
- The server’s Wi-Fi IPv4 address changed from `192.168.1.81` to `192.168.1.100` during the run. The old URL then failed; the dashboard was reopened at `http://192.168.1.100:8001/dashboard`, where its API-backed live values loaded.
- A captured, completed UDP flow from `192.168.1.100:55056` to `103.89.233.250:53` had 4 packets, 504 bytes, and 7.9053 seconds duration. Its live GATv2 inference batch contained 9 graph nodes and 8 directed flow edges. The existing GATv2 returned `BENIGN`, anomaly probability 0.3065, confidence 0.6935. These values came from the live captured-flow path, not a CSV row.
- The dashboard route is `backend.chat_service.dashboard_page` at `/dashboard`; it returns inline `DASHBOARD_HTML`. The inline script assigned `#messages`, which was missing from the served markup. Added a Recent messages card with that id. A second counter bug let the event window overwrite API analysis totals; the counters now use API totals and the event card is labelled Recent events. The current-IP dashboard loaded live API values and flow rows, the event feed updated, and the browser reported no console errors.
- Two chat clients joined from the same computer and therefore both reported source IP `192.168.1.81`. One normal message was delivered. Its real threat decision was: message risk 0.0, URL risk 0.0, behavior risk 0.0417, network risk 0.0, `network_signal_available=false`, final risk 0.0104, action `ALLOW`.
- A controlled suspicious URL was sent as chat text only and was never visited. The threat event reported message risk 0.24, URL risk 1.0, behavior risk 0.0417, network signal unavailable, final risk 0.70, action `BLOCK_MESSAGE`. The dashboard showed the rejection.
- With the configured 24-message/30-second behavior limit unchanged, a rapid-message test raised behavior risk through 0.7083 to 1.0. The policy rejected subsequent messages, blocked the test sender at 1.0, closed the WebSocket, and rejected a reconnect. The dashboard showed the block.
- The full existing test suite passed: **14 passed, 0 failed** (37 upstream warnings).

## Chat-to-network association limitation

Chat clients are attributed to captured network data only when a captured TCP flow matches that client’s exact WebSocket 5-tuple (client IP/port and server port). During the message test both browser tabs were on the server computer, shared IP `192.168.1.81`, and no captured flow matched either WebSocket endpoint on port 8001. In the final run a chat client stayed connected at `192.168.1.100` while packets, flows, and GATv2 analyses continued to increase; no port-8001 flow was captured. The chat threat decision therefore correctly recorded `network_signal_available=false` with `no_captured_flow_matched_chat_tcp_5_tuple`; it did not borrow an unrelated flow from that host. Structured `THREAT_DECISION` logs include risk fields and association outcome without message content.

## Not verified

- A phone or other physical client was not tested. Although Npcap observed other LAN-originated traffic, its device ownership was not established.
- A real chat WebSocket flow entering the Wi-Fi interface, completing, receiving a GATv2 result, and associating back to its sender was not demonstrated. A second device on the LAN is needed for that check.
- The live flow sample verified graph creation and inference, but the sample was not the chat WebSocket flow.

The active model architecture, checkpoint, and configured decision thresholds were not changed. The production candidate remains unpromoted.

# Runtime validation for the restored GATv2 pipeline

**Current result: 🟡 IMPLEMENTED BUT NOT VERIFIED end-to-end for the phone or local self-scan path.** A controlled TCP connect sweep against the laptop's own Wi-Fi address was completed, but its packets did not appear on the Wi-Fi NPF capture or enter FlowTracker. Physical-phone access and its WebSocket flow have not been verified.

## Runtime status

| Check | Result |
|---|---|
| Npcap | 🟢 Installed; `npcap` kernel service is `RUNNING`. `npf` is not registered as a separate service on this Npcap installation. Driver and Npcap files are present. |
| Wi-Fi adapter | 🟢 `Wi-Fi` / Intel(R) Wi-Fi 6E AX211 160MHz is enabled and connected. Current laptop IPv4 address: `192.168.1.81`. |
| Npcap binding | 🟢 `Npcap Packet Driver (NPCAP)` (`nmap_npcap`) is enabled on Wi-Fi. `AdminOnly=0`, `WinPcapCompatible=1`, `Dot11Support=0`; no configuration changes were made. |
| Scapy interface discovery | 🟡 A normal, non-elevated process lists only `\\Device\\NPF_Loopback`; an elevated process lists the Wi-Fi NPF device. This is a process privilege/access difference, not a missing driver or adapter binding. A six-second elevated passive capture on the Wi-Fi NPF interface received 48 packets. |
| Application interface selection | 🟢 Current checkout now resolves `NETWORK_INTERFACE` or `CAPTURE_INTERFACE` values such as `Wi-Fi` to the current NPF GUID dynamically, prints available capture interfaces and the selected device, and reports an access/interface error without silently choosing loopback. No GUID is hard-coded. |
| FastAPI listener | 🟢 An existing Uvicorn process (PID 2780) is listening on `0.0.0.0:8001`. It runs `app:app` from `C:\Users\bdlsm\OneDrive\Desktop\Major\major-project` (the sibling checkout), not this checkout. A second startup from this checkout reached application startup but could not bind because port 8001 was already occupied; the existing process was left untouched. |
| HTTP access | 🟢 `http://127.0.0.1:8001/chat` and `http://192.168.1.81:8001/chat` returned HTTP 200 from the laptop. `/dashboard` also returned HTTP 200 locally. This verifies laptop loopback and LAN-interface access, not access from a separate phone. |
| Windows Firewall | 🟡 Firewall profiles remain enabled. No inbound rule was added because there is no observed phone connection failure to diagnose; the laptop's own LAN-IP request succeeded. |
| Phone page and WebSocket | 🟡 Not verified: no physical phone browser/session was available in this execution. Phone IP, ephemeral source port, and phone WebSocket flow ID are unknown. |
| FlowTracker / graph / GATv2 | 🟢 The active dashboard reports capture `running`, no capture error, the Wi-Fi NPF device, live traffic counters, completed flows with graph dimensions, and GATv2 `available` with no model error. A new live non-phone sample is recorded below. |

The capture change in this checkout is not the process currently serving port 8001; the active listener belongs to the sibling checkout. Consequently, HTTP and live dashboard evidence below is from that existing process. The current checkout's changes were compiled and its tests pass, but it could not take over the occupied port.

## New live evidence (laptop traffic, not phone traffic)

The active `/api/network/state` endpoint returned this newly analyzed real captured flow:

- Flow ID: `1e501e414da2439fa3ab854ca4835579`
- Source: `104.18.39.21:443`
- Destination: `192.168.1.81:64412`
- Protocol: TCP
- Packets: 7; bytes: 390; duration: 2.0225 seconds
- Live graph: 6 nodes, 11 edges
- GATv2: **BENIGN**; anomaly probability `0.3088`; confidence `0.6912`
- FlowTracker status: `analyzed`

At the time of the dashboard query, the live counters showed 345,441 packets, 253,705,302 bytes, 73 packets/sec, 35,678 bytes/sec, 23,431 GATv2 analyses, 122 anomalies, and latest prediction `BENIGN`. These are values returned by the active server, not simulated values. The sample is fresh evidence of the laptop capture-to-GATv2 path; it is not a substitute for the requested phone flow.

## Artifact and compatibility checks

The five restored model artifacts remain byte-for-byte identical to the source set in the sibling checkout. The active checkpoint SHA-256 is `b836f083fe14203695c40a3c04d909922b53fa2bb3e91deb1f0d537eaeda8d84`; its configuration threshold is `0.53`. The state dict strictly loads into the existing GATv2 class, with 5 node inputs, 5 edge inputs, 64 hidden features, 4 attention heads, and 2 output classes. Both saved scalers expect five features. The current-checkout inference code validates the saved feature configuration and uses its log transform and threshold. No retraining, checkpoint replacement, or architecture change was performed.

The current checkout's live graph feature construction was aligned with the recovered training preprocessing: the same five node features, five CICIDS edge features, nonnegative `log1p` transform, and saved node/edge scalers.

## Remaining phone-only checks

The following remain 🟡 IMPLEMENTED BUT NOT VERIFIED: open `/chat` on a phone on the same Wi-Fi; verify the phone WebSocket connects; record its IP, ephemeral source port, and flow ID; confirm that exact source IP appears in Scapy and FlowTracker; and capture the phone flow's graph and GATv2 prediction in the dashboard. The current evidence cannot establish those steps because no physical phone session was available. No traffic was simulated or fabricated.

## Controlled local self-scan (2026-11-12)

**Result: 🟡 Local self-scan traffic is not suitable for validating the Wi-Fi capture path.** This is the exact reason the scan did not satisfy the end-to-end success criteria; no traffic was forced into the pipeline.

- Target IP: `192.168.1.81`, dynamically read from the active `Wi-Fi` adapter (`Intel(R) Wi-Fi 6E AX211 160MHz`, GUID `{1F341169-C1D1-4BBE-8C0D-3E33B9534E0C}`). The same address matched the active server's Wi-Fi NPF interface.
- Source: local TCP sockets on this laptop; the intended local source address was `192.168.1.81`. The Wi-Fi NPF capture observed no packet tuple for this self-scan.
- Exact test: Nmap was not installed (`where.exe nmap` found no executable), so a native TCP `connect_ex` sweep was used, ports 1–1000, no host discovery, 10 workers paced at 200 ms each (maximum about 50 connection attempts/sec). It completed 1,000 attempts in 46.04 seconds. TCP connects succeeded on ports 135, 139, and 445.
- Pre-test dashboard: HTTP 200 from `/chat` and `/dashboard`; capture `running` on `\\Device\\NPF_{1F341169-C1D1-4BBE-8C0D-3E33B9534E0C}`; GATv2 `available`; threshold `0.53`.
- Npcap/Scapy result: the passive Scapy sniffer on that Wi-Fi NPF interface, filtered to the target and TCP ports 1–1000, captured **0 matching packets**.
- FlowTracker result: **0 scan flows started and 0 completed**. No scan source/destination packet tuple, flow ID, packet count, or bytes were available from the capture path.
- GATv2 result: **0 scan flows analyzed**; no scan probability, confidence, or BENIGN/ATTACK result exists. The dashboard's total packet count increased by 1,031 and GATv2 analyses by 105 during the interval, but these were not correlated with the target/port filter and are not scan evidence. Global latest prediction remained BENIGN.
- Enforcement: no scan flow reached GATv2, so no scan-linked enforcement event occurred. No firewall rule, persistent process, or configuration was created or changed. The API showed one blocked username (`bob`) after the run; without a pre-run snapshot it cannot be attributed to this test, and there was no scan flow or scan-linked enforcement event.

The test was generated solely against this laptop's private address. It did not exercise Npcap → Scapy → FlowTracker → graph/features → GATv2 for scan traffic. Do not treat this as detector success or failure; use a separate authorized LAN device as the traffic source for a valid Wi-Fi capture-path test. No further scan was started.

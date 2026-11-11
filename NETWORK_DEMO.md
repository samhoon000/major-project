# Local network security demo

## Verified setup

- Python 3.14.7, Scapy 2.8.0, and Npcap 1.90 were used.
- Npcap is installed and running; its capture DLLs are present. Scapy successfully captured packets on the Wi-Fi NPF interface:
  `\Device\NPF_{1F341169-C1D1-4BBE-8C0D-3E33B9534E0C}`
- The existing active checkpoint is `models/gatv2_model.pth`. No training occurred and the production candidate was not promoted.

## Start the server

In PowerShell, select an interface listed by Scapy and start FastAPI. The following is the interface used in the verified run:

```powershell
$env:NETWORK_INTERFACE = '\Device\NPF_{1F341169-C1D1-4BBE-8C0D-3E33B9534E0C}'
rtk proxy python -B -m uvicorn app:app --host 0.0.0.0 --port 8001
```

Npcap options and Windows permissions can affect capture access. The API reports whether capture is starting, running, or unavailable; it does not invent packet or flow metrics.

## Open the app

- Current chat URL: `http://192.168.1.100:8001/chat`
- Current dashboard URL: `http://192.168.1.100:8001/dashboard`
- Current live network state: `http://192.168.1.100:8001/api/network/state`

The Wi-Fi address changed from `192.168.1.81` to `192.168.1.100` during validation. If DHCP changes it again, use the current Wi-Fi IPv4 address instead.

For a physical-device test, open the chat URL from another user-owned device on the same trusted Wi-Fi network. The server associates a chat user to a flow only when the captured TCP 5-tuple matches that client’s WebSocket endpoint. A same-computer browser test shares the host IP and does not prove that the Wi-Fi capture observed the WebSocket flow.

The dashboard’s former `#messages` null-reference error was fixed by adding the missing Recent messages element. A second counter bug was fixed so live API analysis totals are not overwritten by the shorter WebSocket event window; the event card now reports recent events. The dashboard polls the chat/network APIs and receives live flow and threat events over its WebSocket.

## Verified demonstrations

- Live packet, flow, and GATv2 state changed while the app was running. A captured UDP flow from `192.168.1.100:55056` to `103.89.233.250:53` contained 4 packets and 504 bytes; its GATv2 inference batch graph had 9 nodes and 8 edges, with a BENIGN prediction and anomaly probability 0.3065.
- One normal chat message was delivered and produced an ALLOW threat decision.
- A suspicious-looking URL sent as chat text was analyzed and blocked without visiting it.
- The configured 24-message behavior threshold was exercised. Rapid traffic caused message rejections, then a user block and WebSocket disconnect. The threshold was not changed.

## Limits

In the verified chat test, both clients were browser tabs on the server computer and shared its then-current address (`192.168.1.81`). No captured flow matched their WebSocket connection on port 8001, so the network signal correctly remained unavailable for those chat decisions. The captured GATv2 flow was real LAN traffic but was not the chat flow. A phone or other physical client was not tested. The old `.81` dashboard URL later failed after DHCP changed the host address; the dashboard was reopened on `.100` and its API-backed metrics worked there.

GATv2 is one network-anomaly signal, not a standalone reliable IDS. If a completed GATv2 result is not associated with the sender’s exact WebSocket flow, the threat engine reports the network signal as unavailable and uses the remaining configured signals.

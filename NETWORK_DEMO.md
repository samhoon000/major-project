# Controlled phone-to-laptop network demo

This demo is limited to a phone you control and the private LAN address of this project laptop. It does not target public addresses or other LAN devices.

## Architecture

Network security is separate from the existing chat security path:

```text
Phone on Wi-Fi → laptop/Npcap → Scapy IPv4 TCP/UDP parser → bidirectional 5-tuple FlowTracker
→ idle/max-age finalized flows → live directed graph + saved node/edge scalers
→ existing GATv2 → class-1 probability vs saved threshold → GATV2_ATTACK_DETECTED
→ source-IP Windows Firewall quarantine → BLOCK_APPLIED → dashboard
```

The existing application path remains chat message inspection, URL inspection, behavior analysis, and its `BLOCK_MESSAGE` / `BLOCK_USER` behavior.

The recovered active GATv2 schema is the source of truth. Node features are `in_degree`, `out_degree`, `total_packets`, `total_bytes`, and `avg_duration`; edge features are `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Flow Bytes/s`, and `Flow Packets/s`. Both vectors receive nonnegative log1p preprocessing before their matching saved `StandardScaler`. The architecture is the existing two-layer `GNNAnomalyDetector` in `model.py`, with 5 node inputs, 5 edge inputs, 64 hidden units, 4 first-layer heads, and a 2-class edge output. The recovered model threshold is 0.53. The runtime does not fall back to `model.pkl` or synthesize predictions.

## Requirements

- Windows laptop and phone on the same Wi-Fi, with client isolation disabled by the router.
- Python dependencies from `requirements.txt`, PyTorch Geometric, and Npcap installed with WinPcap-compatible API support.
- Restored matching GATv2 checkpoint, scalers, and configuration in `models/` (the active checkpoint loads in this environment).
- Administrative rights for the server process if you want Windows Firewall enforcement. Capture may also require elevated rights.
- For firewall protection, set `ADMIN_IPS` to any additional admin addresses before starting the server. The IP that opens `/dashboard` is also protected dynamically.

## Configure Npcap and the network interface

Run a short Scapy inventory from the same Python environment used by the server:

```powershell
python -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"
```

Set `NETWORK_INTERFACE` to the exact interface name from Scapy. Choose the active Wi-Fi adapter. Do not guess from its Windows display label. The API reports the selected interface, capture filter, and any startup error at `/api/network/state`.

Find the laptop's current private IPv4 address with `ipconfig` or inspect `server_ips` from `http://127.0.0.1:8001/api/network/state` after startup. Confirm it is on the same subnet as the phone. The address is discovered from local interfaces and is not hard-coded by the app.

## Start the server

Install dependencies and ensure the trained artifacts exist. In an elevated PowerShell window:

```powershell
$env:NETWORK_INTERFACE = "<exact Scapy Wi-Fi interface name>"
$env:NETWORK_CAPTURE_FILTER = "ip and (tcp or udp)"
$env:NETWORK_BLOCK_SECONDS = "300"
$env:ADMIN_TOKEN = "<choose a private demo token>"
$env:ADMIN_IPS = "<optional comma-separated admin IPs>"
python -m uvicorn app:app --host 0.0.0.0 --port 8001
```

`ADMIN_TOKEN` is required for chat-user and network-source unblock endpoints. The Windows firewall rule blocks inbound traffic from the one source IP associated with an above-threshold GATv2 attack prediction. Rules are named `MajorProject-GATv2-Quarantine-*` and are removed on expiry, manual unblock, or normal app shutdown. If the process or machine terminates unexpectedly, inspect and remove any remaining rules with that prefix in Windows Defender Firewall; runtime cleanup cannot run after a crash.

## Connect and verify the phone

1. Open `http://<laptop-private-LAN-IP>:8001/dashboard` on the admin device.
2. Open `http://<laptop-private-LAN-IP>:8001/chat` on the phone. The chat is a WebSocket client at `/ws/chat/<username>`.
3. Send ordinary messages with a second chat client connected as recipient. The network dashboard should show real packet/flow counts if Npcap is seeing that interface.
4. Check `/api/network/state` for the selected interface, packet counters, active/completed flow tuples, and GATv2 availability. A phone IP, ephemeral source port, laptop destination IP, destination port 8001, and TCP must appear in captured flow data before claiming the phone was observed.
5. If counters remain unchanged, check the selected adapter, Npcap installation, Windows elevation, Wi-Fi client isolation, and host firewall rules. Do not infer capture success from the phone merely loading the page.

## Browser Attack Lab

Open `http://<current-laptop-private-IPv4>:8001/attack-lab` on a phone connected to the same Wi-Fi. The page resolves the target from the server's selected Wi-Fi adapter; it has no target input. **Port Scan Test** sends at most 101 phone-browser requests to this laptop on ports 8000–8100, paced at one request every 250 ms, with a 30-second maximum. **Traffic Burst Test** sends at most 40 phone-browser requests to the fixed local endpoint over about 8 seconds; the server additionally enforces a 50-request rolling limit per source in 15 seconds. **Stop Test** aborts outstanding browser requests and timers.

The lab page reports capture and GATv2 availability only. It does not produce predictions. Wait for real phone flows to appear under Live Network Flows; FlowTracker finalizes flows after its idle timeout, then the existing GATv2 inference and enforcement path decides the result. A page load or a rising global packet count is not proof that the phone's test traffic was captured.

## Controlled PortScan

Only proceed after ordinary phone traffic is demonstrably captured. On a phone with Termux and an authorized `nmap` install, substitute the laptop's current private LAN address (never a hostname that may resolve externally):

```sh
nmap -sT -Pn -n --max-rate 10 -p 7990-8020 <LAPTOP_PRIVATE_LAN_IP>
```

This is a limited TCP connect scan of 31 ports on the project laptop only. Stop if the substituted address is not the laptop's private address. If the phone cannot run this command, use a trusted scanner app configured with exactly that IP and port range. The scan itself does not guarantee that the model will call it an attack.

## What the dashboard should show

The dashboard at `/dashboard` presents packet/byte rates, active and completed flows, GATv2 analysis counts, prediction, class-1 anomaly probability, saved threshold, tuple/source association, event history, and network quarantine state. For a real model attack, the event order is `gatv2_analysis` → `GATV2_ATTACK_DETECTED` → `BLOCK_APPLIED`. It also shows decisions where a block was prevented, such as a protected admin/server address. These fields come from live capture/inference/enforcement state.

A block only occurs when the loaded GATv2 produces class-1 probability at or above its saved threshold and labels that flow `ATTACK`, matching the recovered GATv2 inference engine. Normal and below-threshold flows do not request a block. The server source address, loopback addresses, configured admin addresses, and the address viewing the dashboard are protected. No Wi-Fi subnet-wide rule is created.

## Unblock and expiry

Use the dashboard's network unblock button or call:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8001/api/admin/network-unblock/<SOURCE-IP>" -Headers @{"X-Admin-Token"=$env:ADMIN_TOKEN}
```

Blocks expire after `NETWORK_BLOCK_SECONDS` (300 seconds by default) while the app is running. The expiry event is `BLOCK_EXPIRED`. Restarting the server ends capture; a clean shutdown removes managed rules.

## GATv2 artifacts and training

The active artifact set was restored from the sibling OneDrive checkout `C:\Users\bdlsm\OneDrive\Desktop\Major\major-project\models`. Its exact checkpoint and matching scaler/config filenames are now present under this project's `models/`. `data/full_dataset.csv` is only used by training scripts; it is not required for inference. The recovered training process maps `BENIGN` to class 0 and all other labels to class 1. The training metadata shows PortScan samples among the training input, while this is still binary anomaly classification, not a dedicated PortScan output class.

The GATv2 loader reports available with the restored artifacts. A current physical phone/Npcap flow is still required to validate capture and live inference in this checkout. Do not report an ATTACK prediction based on the unrelated `model.pkl`, packet counts, or a scan alone.

## Limitations and troubleshooting

- A switch/router with Wi-Fi client isolation can prevent the phone from reaching the laptop.
- Npcap capture and firewall rule creation may need administrator privileges.
- A model trained on CICIDS flow features may not generalize to this live flow aggregation or to a short PortScan. Evaluate the actual probability and threshold from captured flows.
- The Windows rule remains until runtime expiry/unblock/normal shutdown. After an abrupt process crash, manually review named rules as described above.
- An inbound firewall block prevents later inbound packets from that source; already established sockets may need to reconnect before the effect is visible.
- The test suite mocks firewall side effects. It does not claim a physical phone test, Npcap capture, model PortScan detection, or a real firewall block.

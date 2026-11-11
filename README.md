# Real-Time Network Security Monitor

This project provides real-time chat, message/URL/behavior analysis, packet capture, flow tracking, live graph construction, GATv2 network anomaly inference, a unified threat engine, and a security dashboard.

## Architecture

```text
Application Security: Message -> Message Analyzer -> URL Analyzer -> Behavior Analyzer -> Threat Engine
Network Security: Real Packets -> Npcap -> Scapy -> Flow Tracker -> Live Graph -> GATv2 -> Network Signal -> Threat Engine
```

The threat engine combines available signals. If a captured flow cannot be validly associated with a chat sender, the decision reports `network_signal_available=false`; unrelated traffic is not attributed to that user.

## Requirements

Basic app: Python 3.11+ recommended and the packages in `requirements.txt`. Full live monitoring: Windows, Npcap, an active Wi-Fi/Ethernet adapter, and permission to capture on it. **Npcap is required for real packet capture and live network/GATv2 monitoring on Windows. It runs as a driver/service; do not manually launch it after installation.**

## Quick start (Windows PowerShell)

```powershell
git clone https://github.com/samhoon000/major-project.git
cd major-project
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Install CPU PyTorch and PyTorch Geometric using their official Windows instructions compatible with your Python version; `torch` is commented out in `requirements.txt`, so install it before `torch-geometric`. Verify imports with `python -c "import torch, torch_geometric; print(torch.__version__)"`. Install Npcap with its WinPcap-compatible API option, then follow the adapter selection and actual packet capture verification in [NETWORK_DEMO.md](NETWORK_DEMO.md).

Scapy must use the interface name it enumerates. Set it for this PowerShell session, then launch:

```powershell
$env:NETWORK_INTERFACE = '<YOUR_NETWORK_INTERFACE>'
python -B -m uvicorn app:app --host 0.0.0.0 --port 8001
```

Find your LAN address with `ipconfig` and use the active adapter's IPv4 address: `http://<YOUR_LAN_IP>:8001/dashboard`, `/chat`, or `/api/network/state`. The default app configuration port is 8000; the live demo command explicitly uses 8001. For access from another device, allow inbound TCP 8001 on a trusted/private network in Windows Firewall; do not disable the firewall.

Required inference artifacts are committed under `models/`: `gatv2_model.pth`, `node_scaler.pkl`, `edge_scaler.pkl`, `feature_config.json`, and `model_config.json`. The full dataset is not required for live inference. **You do not need to train the GATv2 model to run the project. The project uses the existing checkpoint and preprocessing artifacts.**

See [NETWORK_DEMO.md](NETWORK_DEMO.md) for Npcap verification, live flow/API checks, safe chat demonstrations, physical-device testing, and troubleshooting. A physical device must be on the same LAN unless networking is separately configured; the network signal is not guaranteed to be associable with every chat sender.

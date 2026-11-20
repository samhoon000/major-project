# Sentinel AI: Network Intrusion Detection & Secure Chat System

Sentinel AI is a real-time, unified network security and secure messaging platform. It integrates live packet capture, bidirectional TCP/UDP flow tracking, graph attention network (GATv2) anomaly detection, multi-signal threat evaluation, and an interactive SOC administration dashboard.

The system is accessible both locally over Wi-Fi (LAN) and globally across the internet via Cloudflare Tunnel, allowing multiple laptops and mobile phones to connect to the **same** FastAPI application and Threat Engine.

See [How to run Sentinel AI](HOW_TO_RUN.md) for setup, Quick Tunnel access, and a summary of changes on this branch.

---

## 1. System Architecture

```text
[ Attendee Devices (Phone / Laptop) ]
         |
         +--> [ Local Wi-Fi (LAN): http://<LAN_IP>:8001/chat ]
         |
         +--> [ Public Cloudflare Tunnel: https://<CUSTOM_DOMAIN>/chat ]
                         |
                         v
       +------------------------------------+
       |       Unified FastAPI Backend      |
       |  (Single Shared Server on Host)    |
       +------------------------------------+
                         |
      +------------------+------------------+
      |                                     |
      v                                     v
[ Application Security ]           [ Network Security ]
- WebSocket Secure Chat            - Npcap Live Packet Capture
- Message Content Analyzer         - Scapy Sniffer & Decoder
- URL & Phishing Analyzer          - Bidirectional FlowTracker
- Live Behavior Risk Analyzer      - Network Graph Construction
- Unified Threat Engine            - Inductive GATv2 Model (PyG)
- SOC Event Stream (/dashboard)    - Windows Firewall Quarantine
```

### Threat Engine Multi-Signal Fusion
Every chat message and network flow is evaluated by the Threat Engine using weighted multi-signal risk scoring:
$$\text{Final Risk} = w_{\text{network}} \cdot R_{\text{GATv2}} + w_{\text{content}} \cdot R_{\text{message}} + w_{\text{url}} \cdot R_{\text{url}} + w_{\text{behavior}} \cdot R_{\text{behavior}}$$

Decisions:
- **`ALLOW`**: Safe content, normal behavior, and benign/unassociated network signals.
- **`WARN`**: Elevated risk warning displayed to the sender and logged in telemetry.
- **`BLOCK_MESSAGE`**: High-risk message rejected before delivery to recipient.
- **`BLOCK_USER`**: Critical cumulative risk or flooding triggers immediate user termination and administrative quarantine.

---

## 2. Prerequisites

1. **Operating System**: Windows 10 or Windows 11 (64-bit).
2. **Python**: Python **3.13.2** (64-bit) installed and available on `PATH`.
3. **Npcap**: [Npcap Packet Capture Driver](https://npcap.com/#download) (version 1.70+).
   - During Npcap setup, check:
     - `[x] Install Npcap in WinPcap API-compatible Mode`
     - `[x] Support raw 802.11 traffic`
4. **Cloudflare Tunnel (Optional - for Public Access)**:
   - [cloudflared binary](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) on `PATH` or placed in the project root.

---

## 3. Quick Start (Teammate / Multi-Laptop Workflow)

### Step 1: First-Time Setup
Clone the repository, open PowerShell in the project directory, and run the automated setup script:

```powershell
git clone <repository-url>
cd major-project
.\setup.ps1
```

`setup.ps1` automatically:
- Enforces Python 3.13.2.
- Creates an isolated virtual environment (`venv`).
- Verifies and installs all pinned dependencies against `requirements.txt`.
- Validates the 5 GATv2 model artifacts (`models/`).
- Generates a cryptographically secure random `ADMIN_TOKEN` into `.env` (without overwriting existing settings).
- Validates Npcap driver availability.

### Step 2: Launch Application
To launch the application, run:

```powershell
.\start.ps1
```

`start.ps1` automatically detects your active Wi-Fi or Ethernet adapter, prints the local LAN URL and QR code status, and launches Uvicorn on `http://0.0.0.0:8001`.

---

## 4. Attendance & Connectivity

### Local Wi-Fi (LAN) Attendance
1. Connect mobile phones or teammate laptops to the **same Wi-Fi network** as the host laptop.
2. Open the joining URL displayed on the console:
   ```text
   http://<YOUR_LAN_IP>:8001/chat
   ```
3. Alternatively, scan the **QR Code** displayed in the browser or on the SOC Dashboard (`/dashboard`).

### Public Internet Attendance (Cloudflare Named Tunnel)
To allow remote attendees on mobile data or external networks to join the same chat room:
1. Download `cloudflared.exe` and place it in the project root or add to `PATH`.
2. In the [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/):
   - Navigate to **Networks** $\rightarrow$ **Tunnels** $\rightarrow$ **Create a Tunnel**.
   - Choose **Cloudflare Tunnel** (Named tunnel).
   - Add a Public Hostname route pointing to: `http://localhost:8001`.
   - Copy the Tunnel Token.
3. Add the token and hostname to your `.env` file:
   ```dotenv
   CLOUDFLARE_TUNNEL_TOKEN=eyJhIjoi...your_token_here...
   CLOUDFLARE_PUBLIC_HOSTNAME=chat.yourdomain.com
   ```
4. Start the application with `.\start.ps1`. The server will automatically connect to Cloudflare Edge, update the joining QR code to `https://chat.yourdomain.com/chat`, and display the `PUBLIC ACCESS (HTTPS)` badge.

---

## 5. Security Architecture & Controls

### Trusted Proxy-Aware IP Resolution (F-01)
- Forwarded headers (`CF-Connecting-IP`, `X-Forwarded-For`) are **only** honored when requests originate from trusted loopback proxies (`127.0.0.1` / `::1`).
- Direct LAN clients attempting to spoof `CF-Connecting-IP` or `X-Forwarded-For` are ignored; their true physical IP is recorded.
- All client IPs are validated with Python's `ipaddress` module before reaching the Threat Engine and SOC logs.

### WebSocket Origin Validation (F-02)
- Rejects untrusted cross-site WebSocket handshakes (CSWSH) before `ws.accept()`.
- Validates `Origin` against `localhost`, detected LAN IP, RFC 1918 subnets, and the configured `CLOUDFLARE_PUBLIC_HOSTNAME`.

### Administrative Endpoint Protection (F-03)
- Sensitive administrative routes (`/api/upload`, `/api/predict`, `/api/admin/unblock/{user_id}`) strictly require the `X-Admin-Token` header matching `ADMIN_TOKEN`.
- `ADMIN_TOKEN` and `CLOUDFLARE_TUNNEL_TOKEN` are strictly isolated on the backend and are **never** rendered into client HTML, JS, or public API responses.

### Windows Defender Firewall Quarantine
- When GATv2 detects an inductive network anomaly meeting the classification threshold ($P \ge 0.50$), `QuarantineManager` creates a temporary, source-scoped Windows Firewall block rule (`MajorProject-GATv2-Quarantine-<hash>`).
- Localhost and administrative IPs are whitelisted against accidental self-blocking.

---

## 6. Model Artifacts & Preprocessing

The model uses inductive Graph Attention Networks (GATv2) trained for network anomaly detection. Required artifacts are committed under `models/`:
- `models/gatv2_model.pth`: Pretrained PyTorch GATv2 model weights.
- `models/node_scaler.pkl`: StandardScaler fitted on node feature distributions.
- `models/edge_scaler.pkl`: StandardScaler fitted on edge feature distributions.
- `models/model_config.json`: GATv2 layer dimensions and hyperparameter configuration.
- `models/feature_config.json`: Node and edge feature index specifications.

> [!NOTE]
> You do **not** need to train or retrain the GATv2 model. Preprocessing and inference execute inductively at runtime using these verified artifacts.

---

## 7. Known Boundaries & Operational Limitations

1. **Host Packet Capture Scope**:
   - Host packet capture (Scapy/Npcap) monitors packets passing through the host machine's physical network adapter (Wi-Fi/Ethernet) and local loopback.
   - Host packet capture does **not** inspect private internal traffic on remote attendees' home networks. Inbound Cloudflare Tunnel traffic reaches the host as encapsulated tunnel packets.
2. **Npcap Administrator Privileges**:
   - On Windows, opening raw packet capture handles via Npcap requires Administrator privileges unless Npcap was installed with non-admin capture enabled.
   - If started in a non-elevated terminal, chat, threat evaluation, and Cloudflare access continue normally, while network capture status reports `Npcap capture permission denied`.
3. **Physical QR Code Scanning**:
   - While QR Code Model 2 SVG generation is mathematically verified via matrix roundtrip decoders, scanning from a physical smartphone camera depends on screen brightness, ambient glare, and device camera autofocus.

---

## 8. Verification & Test Suite

To execute the complete regression test suite:

```powershell
# Run all unit and integration tests (72 tests)
.\venv\Scripts\python.exe -m unittest discover tests

# Run GATv2 inductive inference regression
.\venv\Scripts\python.exe -m tests.test_gatv2

# Verify model artifact hashes
Get-FileHash models\*.*
```

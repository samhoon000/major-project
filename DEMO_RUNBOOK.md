# Sentinel local demonstration

## Windows startup

Open PowerShell at the repository root. Start one local Sentinel worker with the Python environment that has the project dependencies installed.

```powershell
python .\demo_local.py --port 8001
```

If dependencies are installed in the repository's virtual environment, use `.\venv\Scripts\python.exe` in place of `python`. The project setup is described in [HOW_TO_RUN.md](HOW_TO_RUN.md). Use the same chosen port throughout if 8001 is occupied.

In a second terminal, run the read-only preflight.

```powershell
python .\demo_preflight.py --port 8001
```

- Dashboard [127.0.0.1:8001/dashboard](http://127.0.0.1:8001/dashboard)
- Attack Lab [127.0.0.1:8001/attack-lab](http://127.0.0.1:8001/attack-lab)

The lab uses the same local server, a temporary client capability, and up to ten sequential requests. Set **Duration (seconds)** to ten for the longest run. The four-second default is enough to check the full lifecycle. Requests / second and Concurrency are both fixed at one. Operator authentication for Monitored Applications uses the existing Settings workflow. Network capture requires a usable Scapy/Npcap interface. The existing `NETWORK_INTERFACE` setting selects one explicitly when needed.

## Five-minute presentation

| Time | Show | Say |
| --- | --- | --- |
| 0:00–0:45 | Overview and the detection pipeline | “Sentinel captures network activity, analyzes flows, generates alerts, and applies temporary restrictions under configured policies.” |
| 0:45–1:40 | Network Analysis and the latest GATv2 result | “GATv2 classifies completed flows. This panel shows the latest classification, anomaly probability, inference time, and graph size when a prediction is available.” |
| 1:40–2:30 | Launch Demo Lab, open **View Live Graph**, then start the check from the lab | “The graph in Monitored Applications shows the real requests. The lab shows the detection, alert, and automatically applied restriction.” |
| 2:30–3:30 | Measured result and lifecycle | “The verified stage requires a subsequent real HTTP 429. The result panel shows measured response counts and mean latency.” |
| 3:30–4:25 | Back to Dashboard and Local HTTP protection | “The Overview shows the detector and client identity, the restriction scope, and the recorded rejection.” |
| 4:25–5:00 | Reset, then return to Network Analysis | “Reset clears the lab’s temporary restriction and counters. This alert came from the rule-based HTTP flood detector. GATv2 provides network-flow classifications.” |

## Recovery

- If the lab cannot load, use the numeric loopback URL and confirm the port with the preflight.
- If the run ends before verification, check its timeline and error, select **Reset**, then start again. Select **Stop** to interrupt dispatch. Reset also cancels active dispatch.
- If capture is unavailable, check the capture interface and Npcap permissions. Keep the HTTP results and GATv2 evidence attributable to their own data sources.
- If the application stream requires sign-in, use **Settings → Administrator session** and reopen Monitored Applications.

## Passive port scan monitoring

Open **Monitored Applications → Port Scan Detection** to show connection attempts, distinct destination ports, refusals, and recent events from Scapy/Npcap. Open **Attack Lab → Port Scan Detection** to check the dedicated HTTP endpoint. A matching active restriction produces HTTP 429 and a verification event. Otherwise the endpoint returns HTTP 200.

For a loopback capture rehearsal, open a separate PowerShell session and run:

```powershell
$env:NETWORK_INTERFACE = '\Device\NPF_Loopback'
python .\demo_local.py --port 8002
```

One normal localhost connection in this setup was visible in Npcap and produced zero scan alerts. The dashboard receives telemetry continuously. The automated tests use in-memory packet fixtures for the scan evidence and a real localhost HTTP request for enforcement.

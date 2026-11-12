# SentinelGraph — interactive demo

**Graph-Based Network Intrusion Detection.** A browser prototype of the SentinelGraph pipeline:
network flows → communication graph → GATv2-style scoring → incidents and explanations.

> **Simulation Mode** is the default. All traffic is synthetic and generated in the browser. No packets are sent,
> no machine is attacked, and nothing contacts an external network. The browser does **not** run the trained
> PyTorch model. Scores and attention are simulated until you connect the real model (see below).

## Run it

```bash
cd sentinelgraph
npm install
npm run dev          # http://127.0.0.1:5173
npm run build        # production build in dist/
```

Requires Node 20+.

### Demo controls

| Key / button | Action |
| --- | --- |
| **▶ RUN FULL DEMO** or `D` | Scripted 10-phase story (~45 s): normal → load rises → probing → port scan → detection → highlight → incident → explanation → stop → recovery |
| **PRESENTATION** or `P` | Larger graph and threat view, a story stepper (Observe → Attack → Detect → Investigate → Recover), fewer controls |
| `1`–`6` | Select scenario (Port Scan, DoS, DDoS, Brute Force, C2, Normal) |
| `Space` | Launch / stop the selected simulation |
| `Esc` | Close inspector / dismiss alert |

## How it fits together

```
FlowSource.tick()                SimulationEngine  |  DatasetReplayEngine
   ↓ flows
GraphEngine.observe()            sliding 8 s window → graph context per flow
   ↓ flows + context
DetectionEngine.analyzeBatch()   SimulatedDetectionEngine  |  ModelApiDetectionEngine  ← your GATv2
   ↓ detections
GraphEngine.ingest()             aggregated nodes/edges, risk, attention
   ↓
runtime.ts                       episode state machine → timeline, incidents, alert, summary → UI store
```

Every 500 ms, `src/store/runtime.ts` runs this loop and publishes one snapshot to a Zustand store. React components only read that store.

### Simulation
- **Traffic** (`engine/simulationEngine.ts`): 24 hosts (`engine/topology.ts`) talk using weighted "who-talks-to-whom" patterns (DNS, HTTPS, SMB, LDAP/Kerberos, Postgres, MQTT, …). Each flow has realistic packet counts, bytes, durations and rates. Launching an attack adds scenario-specific flows with a smooth ramp-up and ramp-down:
  - *Port scan*: one source, hundreds of ports, tiny rejected flows.
  - *DoS*: extreme packet rate to `:80`.
  - *DDoS*: 6 external bots plus 2 IoT devices converging on `.24`.
  - *Brute force*: repeated failing SSH on `:22`.
  - *C2*: periodic beacons to an unknown external host on `:4444`, plus large uploads.

  External addresses use RFC 5737 documentation ranges.
- **Graph context** (`engine/graphEngine.ts`): port diversity, pair frequency, fan-out, high-rate fan-in, failure ratio, inter-arrival periodicity, pair pps/bytes.
- **Simulated detector** (`engine/detectionEngine.ts`):
  - Turns features and context into 8 interpretable signals (0–1), then into an anomaly probability with a logistic.
  - Applies a small "message passing" boost for edges into a node under attack.
  - Computes **GAT-style attention** as a softmax over each node's incoming edge scores.
  - A pattern classifier names the attack family. The real model is binary, so this naming step is a heuristic and is labelled as one.

### What is mocked
| Part | Status |
| --- | --- |
| Network traffic | Synthetic (simulator) or mock CICIDS2017 rows. A real CICIDS CSV can be loaded locally on *Attack Simulator → Dataset Replay* |
| Anomaly probability, attention, confidence | Simulated in Simulation Mode; come from your API in Model Mode |
| Attack-family name | Heuristic pattern classifier in both modes, unless the API returns `attack_class` |
| Graph building, incidents, timeline, charts | Real logic running on whatever detections arrive |

## Connecting the real GATv2 model

The UI depends only on the `DetectionEngine` interface in `src/engine/detectionEngine.ts`:

```ts
interface DetectionEngine {
  analyzeFlow(flow, ctx): Promise<Detection>
  analyzeBatch(flows, ctxs): Promise<Detection[]>
}
```

`ModelApiDetectionEngine` already implements it by POSTing each tick's flows to `{MODEL_URL}/api/analyze`, using
CICIDS2017 column names (the same ones `preprocess.py` / `graph_builder.py` use). Switch to it from the
header (**SIMULATION MODE ▾ → Model Mode → Connect**), or set `VITE_MODEL_API_URL` in `sentinelgraph/.env.local`.
If the service is unreachable, the app shows *MODEL OFFLINE*, falls back to the simulator, and retries every 5 s.

**Request**
```json
{ "flows": [ { "flow_id": "f1a", "Source IP": "10.0.0.15", "Destination IP": "10.0.0.24",
  "Destination Port": 443, "Protocol": "6", "Flow Duration": 1200, "Total Fwd Packets": 2,
  "Total Backward Packets": 1, "Flow Bytes/s": 98000.0, "Flow Packets/s": 2500.0 } ] }
```
**Response** (`attention`, `attack_class` and `signals` are optional)
```json
{ "threshold": 0.65, "results": [ { "flow_id": "f1a", "anomaly_probability": 0.947,
  "attention": 0.91, "attack_class": "portscan", "signals": { "packetRate": 0.91 } } ] }
```

Sketch of the endpoint for `app.py`. This is not run as part of this demo; adapt it to how you persist the scalers and the IP encoder:

```python
from pydantic import BaseModel
import torch, numpy as np
from model import GNNAnomalyDetector

FEATURES = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Bytes/s", "Flow Packets/s"]
model = GNNAnomalyDetector(node_dim=5, edge_dim=5)
model.load_state_dict(torch.load("model.pth", map_location="cpu")); model.eval()
THRESHOLD = 0.65  # summary["best_threshold"] from train.py

class AnalyzeRequest(BaseModel):
    flows: list[dict]

@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    df = pd.DataFrame(req.flows)
    ips = sorted(set(df["Source IP"]) | set(df["Destination IP"]))
    idx = {ip: i for i, ip in enumerate(ips)}
    edge_attr = scaler_edge.transform(df[FEATURES])                       # the scaler fitted in graph_builder.py
    node_df = (df.groupby("Source IP")[FEATURES].mean()
                 .reindex(ips).fillna(0))                                 # approximate graph_builder.py node features (src/dst means)
    x = torch.tensor(scaler_node.transform(node_df.values), dtype=torch.float)
    ei = torch.tensor([[idx[s] for s in df["Source IP"]], [idx[d] for d in df["Destination IP"]]])
    with torch.no_grad():
        logits, (att_ei, att) = model(x, ei, torch.tensor(edge_attr, dtype=torch.float), return_attention=True)
    prob = torch.softmax(logits, 1)[:, 1].numpy()
    attn = att.mean(1).numpy()  # one value per edge (same order, since add_self_loops=False)
    return {"threshold": THRESHOLD, "results": [
        {"flow_id": f["flow_id"], "anomaly_probability": float(p), "attention": float(a)}
        for f, p, a in zip(req.flows, prob, attn)]}
```

Run it with `uvicorn app:app --port 8000`. CORS is already open in `app.py`.

## Next steps toward a real system
1. Save the fitted `scaler_node`, `scaler_edge` and `best_threshold` in `train.py` (e.g. `joblib.dump`) so the API can load them.
2. Implement `/api/analyze` as sketched above and switch the UI to Model Mode.
3. Keep a rolling server-side graph (last N seconds) instead of scoring each batch in isolation, so node embeddings see real neighbourhoods.
4. Replace `SimulationEngine` with a live `FlowSource` such as CICFlowMeter or Zeek output streamed over a WebSocket.
5. Add a multi-class head (or a second model) if you want the attack family to come from the model rather than heuristics.
6. Return per-feature attributions (e.g. integrated gradients over `edge_attr`) as `signals`.

## Folder structure
```
sentinelgraph/
├── index.html
├── package.json
├── vite.config.ts
├── public/favicon.svg
└── src/
    ├── main.tsx · App.tsx · index.css        app shell, keyboard shortcuts, visual system (Tailwind v4 tokens)
    ├── engine/                               framework-free pipeline (no React)
    │   ├── types.ts                          Flow, FlowContext, Detection, NodeState, EdgeState, Incident…
    │   ├── topology.ts                       simulated hosts, services, normal traffic patterns
    │   ├── scenarios.ts                      attack scenario metadata
    │   ├── simulationEngine.ts               FlowSource: synthetic traffic + attack envelopes
    │   ├── datasetReplay.ts                  FlowSource: CICIDS2017 mock rows / local CSV parser
    │   ├── graphEngine.ts                    graph construction, sliding-window context, node/edge state
    │   └── detectionEngine.ts                DetectionEngine interface, simulated + Model-API engines
    ├── store/
    │   ├── store.ts                          Zustand UI state
    │   └── runtime.ts                        tick loop, episode/incident logic, actions, full-demo script
    ├── components/
    │   ├── graph/NetworkGraph.tsx            d3-force + d3-zoom SVG graph (hero)
    │   ├── graph/GraphStage.tsx              graph + overlays (alert, inspector, demo HUD, summary)
    │   ├── charts/Charts.tsx                 anomaly, traffic, normal-vs-anomalous, protocols, top hosts
    │   ├── ModelExplanation.tsx              "Why did SentinelGraph flag this?"
    │   ├── DetectionPipeline.tsx · Architecture.tsx
    │   ├── Simulator.tsx · DatasetReplay.tsx
    │   ├── ThreatGauge.tsx · ThreatAlert.tsx · ThreatTimeline.tsx · IncidentFeed.tsx
    │   ├── Inspector.tsx · SummaryModal.tsx · Overlays.tsx · TopBar.tsx · ui.tsx
    ├── views/                                Overview · Simulator · Graph · Engine · Incidents
    └── lib/                                  formatting, colours, random helpers
```

import { clamp, gauss, rand } from '../lib/random'
import { classify, edgeKey, WINDOW_MS } from './graphEngine'
import type { AttackType, Detection, Flow, FlowContext, Signal, SignalKey } from './types'

/**
 * ─────────────────────────────────────────────────────────────────────────────
 *  DETECTION ENGINE CONTRACT
 *
 *  Everything in the UI consumes `Detection` objects produced by a DetectionEngine.
 *  Two implementations exist:
 *
 *   • SimulatedDetectionEngine  — runs in the browser. It does NOT run your trained
 *     GATv2. It scores flows with hand-tuned feature heuristics and mimics GAT-style
 *     attention with a softmax over each node's incoming edges. Labelled "Simulation Mode".
 *
 *   • ModelApiDetectionEngine   — POSTs flows to your Python service, which builds the
 *     graph and runs the real GNNAnomalyDetector (model.py). Labelled "Model Mode".
 *
 *  To connect the real model, implement the endpoint described in README.md
 *  (POST /api/analyze) — no UI changes needed.
 * ─────────────────────────────────────────────────────────────────────────────
 */
export interface DetectionEngine {
  readonly mode: 'simulation' | 'model'
  readonly label: string
  threshold: number
  /** Classify one flow given its graph context. */
  analyzeFlow(flow: Flow, ctx: FlowContext): Promise<Detection>
  /** Classify a batch (one simulation tick). Real models should implement this directly. */
  analyzeBatch(flows: Flow[], ctxs: FlowContext[]): Promise<Detection[]>
  reset(): void
}

export const SIGNAL_LABELS: Record<SignalKey, string> = {
  packetRate: 'Packet Rate',
  portDiversity: 'Port Diversity',
  flowFrequency: 'Flow Frequency',
  connectionCount: 'Connection Count',
  flowDuration: 'Short-Flow Burst',
  failedAttempts: 'Failed Attempts',
  sourceFanIn: 'Source Fan-in',
  externalBeacon: 'External Beaconing',
}

const COMMON_PORTS = new Set([53, 80, 443, 123, 993, 587, 25, 22])
const AUTH_PORTS = new Set([21, 22, 23, 3389, 445, 389])
const WIN_SEC = WINDOW_MS / 1000

/**
 * Interpretable per-flow signals (0..1) derived from flow features + graph context.
 * In Simulation Mode they drive the score; in Model Mode they are shown as a heuristic
 * explanation unless the API returns its own feature attributions.
 */
export function computeSignals(flow: Flow, ctx: FlowContext): Signal[] {
  const perSec = ctx.pairFrequency / WIN_SEC
  const short = flow.flow_duration < 5 && flow.packet_count <= 3 ? 1 : flow.flow_duration < 50 ? 0.4 : 0
  const v: Record<SignalKey, number> = {
    packetRate: clamp((Math.log10(ctx.pairPps + 1) - 1.9) / 1.5),
    portDiversity: clamp((ctx.dstPortDiversity - 4) / 40),
    flowFrequency: clamp((perSec - 2.5) / 12),
    connectionCount: clamp((ctx.srcFanOut - 7) / 8),
    flowDuration: short * clamp(perSec / 15),
    failedAttempts: ctx.failedRatio * clamp(perSec / 8),
    sourceFanIn: clamp((ctx.dstHeavyFanIn - 1) / 4) * clamp((ctx.pairPps - 100) / 200),
    externalBeacon: ctx.external
      ? clamp(
          0.3 +
            (COMMON_PORTS.has(flow.destination_port) ? 0 : 0.25) +
            (ctx.pairFrequency >= 4 ? (1 - clamp(ctx.periodicity)) * 0.3 : 0) +
            clamp(ctx.pairBytes / 2e7) * 0.2,
        )
      : 0,
  }
  return (Object.keys(v) as SignalKey[])
    .map((key) => ({ key, label: SIGNAL_LABELS[key], value: v[key] }))
    .sort((a, b) => b.value - a.value)
}

/** Maps the dominant signals to a coarse attack family (the real model is binary). */
export function patternClassifier(signals: Signal[], p: number, threshold: number, dstPort?: number): AttackType {
  if (p < Math.min(0.4, threshold)) return 'normal'
  const s = Object.fromEntries(signals.map((x) => [x.key, x.value])) as Record<SignalKey, number>
  if (s.portDiversity >= 0.6) return 'portscan'
  if (s.sourceFanIn >= 0.5) return 'ddos'
  if (s.externalBeacon >= 0.5) return 'c2'
  if (dstPort !== undefined && AUTH_PORTS.has(dstPort) && (s.flowFrequency >= 0.5 || s.failedAttempts >= 0.5)) return 'bruteforce'
  if (s.failedAttempts >= 0.6 && s.packetRate < 0.7) return 'bruteforce'
  if (s.packetRate >= 0.6) return 'dos'
  const byTop: Record<SignalKey, AttackType> = {
    packetRate: 'dos', portDiversity: 'portscan', flowFrequency: 'dos', connectionCount: 'portscan',
    flowDuration: 'portscan', failedAttempts: 'bruteforce', sourceFanIn: 'ddos', externalBeacon: 'c2',
  }
  return byTop[signals[0].key]
}

export const confidenceFor = (p: number, threshold: number) => clamp(0.5 + 0.5 * Math.tanh(5 * Math.abs(p - threshold)), 0.5, 0.995)

const sigmoid = (x: number) => 1 / (1 + Math.exp(-x))

// ─────────────────────────────────────────────────────────────────────────────
//  Simulation Mode
// ─────────────────────────────────────────────────────────────────────────────
export class SimulatedDetectionEngine implements DetectionEngine {
  readonly mode = 'simulation' as const
  readonly label = 'Simulated GATv2 inference (browser heuristics)'
  threshold = 0.65
  /** dst → (src → {score, seen}) — the detector's view of each node's incoming edges */
  private incoming = new Map<string, Map<string, { score: number; seen: number }>>()

  reset() {
    this.incoming.clear()
  }

  async analyzeFlow(flow: Flow, ctx: FlowContext): Promise<Detection> {
    return (await this.analyzeBatch([flow], [ctx]))[0]
  }

  async analyzeBatch(flows: Flow[], ctxs: FlowContext[]): Promise<Detection[]> {
    const now = flows.length ? flows[0].ts : Date.now()
    // 1. local edge score from interpretable features
    const scored = flows.map((f, i) => {
      const signals = computeSignals(f, ctxs[i])
      const [a, b, c] = signals
      const z = 1.1 * a.value + 0.9 * ((a.value + b.value + c.value) / 3)
      return { f, signals, local: sigmoid(6 * (z - 0.95)) }
    })

    // 2. update incoming-edge memory (the "graph" the attention layer sees)
    for (const s of scored) {
      let m = this.incoming.get(s.f.destination_ip)
      if (!m) this.incoming.set(s.f.destination_ip, (m = new Map()))
      const prev = m.get(s.f.source_ip)
      const score = prev ? prev.score + (s.local - prev.score) * 0.4 : s.local
      m.set(s.f.source_ip, { score, seen: now })
    }
    const attention = new Map<string, number>()
    const neighbourRisk = new Map<string, number>()
    for (const [dst, m] of this.incoming) {
      let sum = 0
      let risk = 0
      for (const [src, e] of m) {
        if (now - e.seen > WINDOW_MS) {
          m.delete(src)
          continue
        }
        sum += Math.exp(6 * e.score)
        risk = Math.max(risk, e.score)
      }
      for (const [src, e] of m) attention.set(edgeKey(src, dst), Math.exp(6 * e.score) / sum)
      neighbourRisk.set(dst, risk)
    }

    // 3. "message passing": benign edges into a node under attack inherit a little risk
    return scored.map(({ f, signals, local }) => {
      const nr = neighbourRisk.get(f.destination_ip) ?? 0
      let p = 1 - (1 - local) * (1 - 0.18 * nr)
      p = 0.975 * p + rand(0.004, 0.05) + gauss() * 0.012
      p = clamp(p, 0.004, 0.992)
      return {
        flowId: f.id,
        anomaly_probability: p,
        classification: classify(p, this.threshold),
        confidence: confidenceFor(p, this.threshold),
        attention: attention.get(edgeKey(f.source_ip, f.destination_ip)) ?? 0,
        attack_class: patternClassifier(signals, p, this.threshold, f.destination_port),
        signals,
        source: 'simulation',
      }
    })
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Model Mode — your Python GATv2 service
// ─────────────────────────────────────────────────────────────────────────────

/** Request row: CICIDS2017 column names, exactly what preprocess.py / graph_builder.py use. */
export interface ModelRequestFlow {
  flow_id: string
  'Source IP': string
  'Destination IP': string
  'Destination Port': number
  Protocol: string
  'Flow Duration': number // microseconds, as in CICIDS2017
  'Total Fwd Packets': number
  'Total Backward Packets': number
  'Flow Bytes/s': number
  'Flow Packets/s': number
}

export interface ModelResponse {
  threshold?: number
  results: {
    flow_id: string
    anomaly_probability: number
    /** GATv2 attention for this edge (from return_attention_weights=True), averaged over heads */
    attention?: number
    attack_class?: AttackType
    /** optional feature attributions, 0..1 */
    signals?: Partial<Record<SignalKey, number>>
  }[]
}

export function toModelRequest(f: Flow): ModelRequestFlow {
  return {
    flow_id: f.id,
    'Source IP': f.source_ip,
    'Destination IP': f.destination_ip,
    'Destination Port': f.destination_port,
    Protocol: f.protocol === 'TCP' ? '6' : f.protocol === 'UDP' ? '17' : f.protocol === 'ICMP' ? '1' : '0',
    'Flow Duration': Math.round(f.flow_duration * 1000),
    'Total Fwd Packets': f.fwd_packets,
    'Total Backward Packets': f.bwd_packets,
    'Flow Bytes/s': f.byte_rate,
    'Flow Packets/s': f.packet_rate,
  }
}

export class ModelApiDetectionEngine implements DetectionEngine {
  readonly mode = 'model' as const
  readonly label: string
  threshold = 0.65
  private url: string

  constructor(baseUrl: string) {
    this.url = baseUrl.replace(/\/$/, '') + '/api/analyze'
    this.label = `GATv2 via ${baseUrl}`
  }

  reset() {}

  async analyzeFlow(flow: Flow, ctx: FlowContext): Promise<Detection> {
    return (await this.analyzeBatch([flow], [ctx]))[0]
  }

  async analyzeBatch(flows: Flow[], ctxs: FlowContext[]): Promise<Detection[]> {
    if (!flows.length) return []
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 1500)
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ flows: flows.map(toModelRequest) }),
        signal: ctrl.signal,
      })
      if (!res.ok) throw new Error(`Model API ${res.status}`)
      const body = (await res.json()) as ModelResponse
      if (typeof body.threshold === 'number') this.threshold = body.threshold
      const byId = new Map(body.results.map((r) => [r.flow_id, r]))
      return flows.map((f, i) => {
        const r = byId.get(f.id)
        const p = clamp(r?.anomaly_probability ?? 0)
        const signals = r?.signals
          ? (Object.entries(r.signals) as [SignalKey, number][])
              .map(([key, value]) => ({ key, label: SIGNAL_LABELS[key] ?? key, value }))
              .sort((a, b) => b.value - a.value)
          : computeSignals(f, ctxs[i])
        return {
          flowId: f.id,
          anomaly_probability: p,
          classification: classify(p, this.threshold),
          confidence: confidenceFor(p, this.threshold),
          attention: r?.attention ?? 0,
          attack_class: r?.attack_class ?? patternClassifier(signals, p, this.threshold, f.destination_port),
          signals,
          source: 'model',
        }
      })
    } finally {
      clearTimeout(timer)
    }
  }
}

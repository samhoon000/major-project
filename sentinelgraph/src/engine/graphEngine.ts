import { isInternal } from './topology'
import type {
  AnalyzedFlow, AttackType, Classification, EdgeState, Flow, FlowContext, Host, HostRole, NodeState, Signal,
} from './types'

/**
 * GraphEngine turns a stream of flows into a communication graph:
 *   hosts → nodes, flows → (aggregated, directed) edges.
 * It also computes the sliding-window graph context (fan-in, fan-out, port diversity…) that both the
 * simulated detector and the real GATv2 model consume as node/edge features.
 */

export const WINDOW_MS = 8000
const EDGE_TTL_MS = 15000
const NODE_TTL_MS = 20000

export const edgeKey = (src: string, dst: string) => `${src}->${dst}`

interface PairAgg {
  flows: number
  failed: number
  packets: number
  bytes: number
  ports: Set<number>
  times: number[]
}

export interface GraphSnapshot {
  nodes: NodeState[]
  edges: EdgeState[]
}

export class GraphEngine {
  private window: Flow[] = []
  private nodes = new Map<string, NodeState>()
  private edges = new Map<string, EdgeState>()
  private maxNodes: number
  threshold = 0.65

  constructor(hosts: Host[], maxNodes = 40) {
    this.maxNodes = maxNodes
    this.reset(hosts)
  }

  reset(hosts: Host[], maxNodes = this.maxNodes) {
    this.maxNodes = maxNodes
    this.window = []
    this.nodes.clear()
    this.edges.clear()
    for (const h of hosts) this.nodes.set(h.id, blankNode(h, 0))
  }

  /** Add new flows to the window and compute graph context for each of them. */
  observe(flows: Flow[], now: number): FlowContext[] {
    this.window.push(...flows)
    const cutoff = now - WINDOW_MS
    let i = 0
    while (i < this.window.length && this.window[i].ts < cutoff) i++
    if (i) this.window.splice(0, i)

    const winSec = WINDOW_MS / 1000
    const pairs = new Map<string, PairAgg>()
    const fanOut = new Map<string, Set<string>>()
    const fanIn = new Map<string, Set<string>>()
    const inbound = new Map<string, number>()

    for (const f of this.window) {
      const k = edgeKey(f.source_ip, f.destination_ip)
      let p = pairs.get(k)
      if (!p) pairs.set(k, (p = { flows: 0, failed: 0, packets: 0, bytes: 0, ports: new Set(), times: [] }))
      p.flows++
      if (f.failed) p.failed++
      p.packets += f.packet_count
      p.bytes += f.bytes
      p.ports.add(f.destination_port)
      p.times.push(f.ts)
      setAdd(fanOut, f.source_ip, f.destination_ip)
      setAdd(fanIn, f.destination_ip, f.source_ip)
      inbound.set(f.destination_ip, (inbound.get(f.destination_ip) ?? 0) + f.packet_count)
    }

    const heavyFanIn = new Map<string, number>()
    for (const [k, p] of pairs) {
      if (p.packets / winSec > 150) {
        const dst = k.split('->')[1]
        heavyFanIn.set(dst, (heavyFanIn.get(dst) ?? 0) + 1)
      }
    }

    return flows.map((f) => {
      const p = pairs.get(edgeKey(f.source_ip, f.destination_ip))!
      return {
        dstPortDiversity: p.ports.size,
        pairFrequency: p.flows,
        srcFanOut: fanOut.get(f.source_ip)?.size ?? 1,
        dstFanIn: fanIn.get(f.destination_ip)?.size ?? 1,
        failedRatio: p.flows ? p.failed / p.flows : 0,
        external: !isInternal(f.destination_ip),
        dstInboundRate: (inbound.get(f.destination_ip) ?? 0) / winSec,
        pairPps: p.packets / winSec,
        dstHeavyFanIn: heavyFanIn.get(f.destination_ip) ?? 0,
        periodicity: interArrivalCv(p.times),
        pairBytes: p.bytes,
      }
    })
  }

  /** Fold analyzed flows into the aggregated graph state. */
  ingest(analyzed: AnalyzedFlow[], now: number, dtMs: number) {
    const dt = dtMs / 1000
    const groups = new Map<string, AnalyzedFlow[]>()
    for (const f of analyzed) {
      const k = edgeKey(f.source_ip, f.destination_ip)
      const g = groups.get(k)
      if (g) g.push(f)
      else groups.set(k, [f])
      this.touchNode(f.source_ip, now, f.destination_port, false)
      this.touchNode(f.destination_ip, now, f.destination_port, true)
    }

    // ---- edges ----------------------------------------------------------------
    for (const [k, g] of groups) {
      const src = g[0].source_ip
      const dst = g[0].destination_ip
      if (!this.nodes.has(src) || !this.nodes.has(dst)) continue
      let e = this.edges.get(k)
      if (!e) {
        e = blankEdge(k, src, dst, g[0].protocol, now)
        this.edges.set(k, e)
      }
      let packets = 0
      let bytes = 0
      let dur = 0
      let top = g[0]
      let attn = 0
      for (const f of g) {
        packets += f.packet_count
        bytes += f.bytes
        dur += f.flow_duration
        attn += f.detection.attention
        if (f.detection.anomaly_probability > top.detection.anomaly_probability) top = f
        if (e.ports.length < 64 && !e.ports.includes(f.destination_port)) e.ports.push(f.destination_port)
      }
      e.flows += g.length
      e.packets += packets
      e.bytes += bytes
      e.rate = ema(e.rate, g.length / dt, 0.35)
      e.pps = ema(e.pps, packets / dt, 0.35)
      e.avgDuration = ema(e.avgDuration || dur / g.length, dur / g.length, 0.3)
      const p = top.detection.anomaly_probability
      e.anomaly = e.anomaly + (p - e.anomaly) * (p > e.anomaly ? 0.5 : 0.3)
      e.peakAnomaly = Math.max(e.peakAnomaly, e.anomaly)
      e.attention = ema(e.attention, attn / g.length, 0.45)
      e.protocol = top.protocol
      e.lastSeen = now
      if (p >= 0.4 || e.anomaly < 0.4) {
        e.signals = top.detection.signals
        e.attackClass = top.detection.attack_class
      }
    }

    // decay edges that saw nothing this tick
    for (const [k, e] of this.edges) {
      if (!groups.has(k)) {
        e.rate *= 0.82
        e.pps *= 0.82
        e.anomaly *= 0.9
        e.attention = e.attention * 0.95
        // window evidence fades with the edge
        if (e.signals.length) e.signals = e.signals.map((x) => ({ ...x, value: x.value * 0.9 }))
      }
      e.classification = classify(e.anomaly, this.threshold)
      if (now - e.lastSeen > EDGE_TTL_MS && e.anomaly < 0.1) this.edges.delete(k)
    }

    // ---- nodes ----------------------------------------------------------------
    const outMax = new Map<string, EdgeState>()
    const inMax = new Map<string, EdgeState>()
    const peers = new Map<string, Set<string>>()
    for (const e of this.edges.values()) {
      if (!outMax.has(e.source) || outMax.get(e.source)!.anomaly < e.anomaly) outMax.set(e.source, e)
      if (!inMax.has(e.target) || inMax.get(e.target)!.anomaly < e.anomaly) inMax.set(e.target, e)
      setAdd(peers, e.source, e.target)
      setAdd(peers, e.target, e.source)
    }
    const pktIn = new Map<string, number>()
    const pktOut = new Map<string, number>()
    for (const f of analyzed) {
      pktOut.set(f.source_ip, (pktOut.get(f.source_ip) ?? 0) + f.packet_count)
      pktIn.set(f.destination_ip, (pktIn.get(f.destination_ip) ?? 0) + f.packet_count)
    }
    for (const [id, n] of this.nodes) {
      const po = pktOut.get(id) ?? 0
      const pi = pktIn.get(id) ?? 0
      n.packets += po + pi
      n.outRate = ema(n.outRate, po / dt, 0.35)
      n.inRate = ema(n.inRate, pi / dt, 0.35)
      n.connections = peers.get(id)?.size ?? 0
      const o = outMax.get(id)?.anomaly ?? 0
      const i = (inMax.get(id)?.anomaly ?? 0) * 0.92
      const target = Math.max(o, i)
      n.risk = n.risk + (target - n.risk) * (target > n.risk ? 0.5 : 0.25)
      const driver = o >= i ? outMax.get(id) : inMax.get(id)
      n.behaviors = driver && driver.anomaly > 0.3 ? driver.signals : []
      if (n.risk < 0.35) n.status = 'HEALTHY'
      else if (n.risk < this.threshold) n.status = 'ELEVATED'
      else n.status = o >= i ? 'SUSPICIOUS' : 'TARGET'
      if (n.dynamic && now - n.lastSeen > NODE_TTL_MS && n.connections === 0) this.nodes.delete(id)
    }
  }

  snapshot(): GraphSnapshot {
    return {
      nodes: [...this.nodes.values()].map((n) => ({ ...n })),
      edges: [...this.edges.values()].map((e) => ({ ...e, ports: e.ports.slice() })),
    }
  }

  private touchNode(ip: string, now: number, port: number, inbound: boolean) {
    const n = this.nodes.get(ip)
    if (n) {
      n.lastSeen = now
      return
    }
    if (this.nodes.size >= this.maxNodes && !this.evict()) return
    const host: Host = {
      id: ip,
      ip,
      role: isInternal(ip) ? (inbound ? roleForPort(port) : 'Workstation') : 'External Host',
      zone: isInternal(ip) ? (inbound && roleForPort(port) !== 'Workstation' ? 'servers' : 'office') : 'external',
      dynamic: true,
    }
    this.nodes.set(ip, blankNode(host, now))
  }

  /** Free a slot by dropping the stalest benign dynamic node. */
  private evict(): boolean {
    let victim: NodeState | undefined
    for (const n of this.nodes.values()) {
      if (!n.dynamic || n.risk > 0.3) continue
      if (!victim || n.lastSeen < victim.lastSeen) victim = n
    }
    if (!victim) return false
    this.nodes.delete(victim.id)
    for (const [k, e] of this.edges) if (e.source === victim.id || e.target === victim.id) this.edges.delete(k)
    return true
  }
}

export function classify(p: number, threshold: number): Classification {
  if (p >= threshold) return 'ANOMALOUS'
  if (p >= 0.4) return 'SUSPICIOUS'
  return 'NORMAL'
}

function roleForPort(port: number): HostRole {
  if (port === 80 || port === 443 || port === 8080) return 'Web Server'
  if (port === 22 || port === 21 || port === 88 || port === 389) return 'Auth / SSH Server'
  if (port === 53) return 'DNS Server'
  if (port === 3306 || port === 5432 || port === 1433) return 'Database'
  if (port === 445 || port === 139) return 'File Server'
  if (port === 25 || port === 993 || port === 587) return 'Mail Server'
  return 'Workstation'
}

function blankNode(h: Host, now: number): NodeState {
  return {
    ...h,
    packets: 0,
    bytes: 0,
    connections: 0,
    risk: 0,
    status: 'HEALTHY',
    inRate: 0,
    outRate: 0,
    lastSeen: now,
    behaviors: [] as Signal[],
  }
}

function blankEdge(id: string, source: string, target: string, protocol: EdgeState['protocol'], now: number): EdgeState {
  return {
    id, source, target, protocol,
    packets: 0, bytes: 0, flows: 0, rate: 0, pps: 0, avgDuration: 0,
    anomaly: 0, peakAnomaly: 0, attention: 0,
    classification: 'NORMAL', attackClass: 'normal' as AttackType,
    lastSeen: now, signals: [], ports: [],
  }
}

const ema = (prev: number, x: number, a: number) => prev + (x - prev) * a

function setAdd(m: Map<string, Set<string>>, k: string, v: string) {
  let s = m.get(k)
  if (!s) m.set(k, (s = new Set()))
  s.add(v)
}

/** Coefficient of variation of inter-arrival gaps; 1 for too-few samples (no evidence of periodicity). */
function interArrivalCv(times: number[]): number {
  if (times.length < 4) return 1
  times = [...times].sort((a, b) => a - b)
  const gaps: number[] = []
  for (let i = 1; i < times.length; i++) gaps.push(times[i] - times[i - 1])
  const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length
  if (mean <= 0) return 1
  const sd = Math.sqrt(gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length)
  return sd / mean
}

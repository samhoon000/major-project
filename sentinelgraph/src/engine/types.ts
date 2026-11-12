// Shared domain types for SentinelGraph.
// These mirror the feature set used by the Python pipeline (preprocess.py / graph_builder.py)
// so the simulated engine can later be swapped for the real GATv2 model without UI changes.

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'OTHER'

export type AttackType = 'normal' | 'portscan' | 'dos' | 'ddos' | 'bruteforce' | 'c2'

export type Intensity = 'LOW' | 'MEDIUM' | 'HIGH'

export type HostRole =
  | 'Core Router'
  | 'Firewall'
  | 'Web Server'
  | 'Database'
  | 'DNS Server'
  | 'Auth / SSH Server'
  | 'File Server'
  | 'Mail Server'
  | 'Workstation'
  | 'IoT Device'
  | 'Printer'
  | 'External Host'

/** One network flow — the unit the detector classifies (an edge in the graph). */
export interface Flow {
  id: string
  ts: number // epoch ms
  source_ip: string
  destination_ip: string
  source_port: number
  destination_port: number
  protocol: Protocol
  /** Total Fwd Packets + Total Backward Packets */
  packet_count: number
  fwd_packets: number
  bwd_packets: number
  bytes: number
  /** milliseconds */
  flow_duration: number
  /** packets per second (CICIDS "Flow Packets/s") */
  packet_rate: number
  /** bytes per second (CICIDS "Flow Bytes/s") */
  byte_rate: number
  /** connection was reset / rejected / auth failed */
  failed: boolean
  /** Ground-truth label when known (dataset replay or simulator), never shown to the detector */
  truth?: string
}

/** Graph-context features computed by the graph engine over a sliding window. */
export interface FlowContext {
  /** distinct destination ports contacted by src→dst in window */
  dstPortDiversity: number
  /** flows src→dst in window */
  pairFrequency: number
  /** distinct destinations contacted by src in window */
  srcFanOut: number
  /** distinct sources sending to dst in window */
  dstFanIn: number
  /** fraction of failed flows src→dst in window */
  failedRatio: number
  /** destination is outside the protected network */
  external: boolean
  /** inbound packet rate (pps) currently arriving at dst */
  dstInboundRate: number
  /** packet rate (pps) of the src→dst pair over the window */
  pairPps: number
  /** distinct high-rate sources sending to dst in window */
  dstHeavyFanIn: number
  /** coefficient of variation of inter-arrival times src→dst (low = machine-like periodicity) */
  periodicity: number
  /** bytes sent src→dst in window */
  pairBytes: number
}

export type SignalKey =
  | 'packetRate'
  | 'portDiversity'
  | 'flowFrequency'
  | 'connectionCount'
  | 'flowDuration'
  | 'failedAttempts'
  | 'sourceFanIn'
  | 'externalBeacon'

export interface Signal {
  key: SignalKey
  label: string
  value: number // 0..1
}

export type Classification = 'NORMAL' | 'SUSPICIOUS' | 'ANOMALOUS'

/** What a detector returns for a single flow. Identical contract for simulated and real model. */
export interface Detection {
  flowId: string
  anomaly_probability: number // 0..1
  classification: Classification
  confidence: number // 0..1
  /** GAT attention weight of this edge among the destination's incoming edges */
  attention: number
  /** Coarse attack family. The real model is binary; this comes from a pattern classifier. */
  attack_class: AttackType
  signals: Signal[]
  source: 'simulation' | 'model'
}

export interface AnalyzedFlow extends Flow {
  detection: Detection
}

export interface Host {
  id: string // ip
  ip: string
  role: HostRole
  zone: 'core' | 'dmz' | 'servers' | 'office' | 'iot' | 'external'
  label?: string
  dynamic?: boolean
}

export type HostStatus = 'HEALTHY' | 'ELEVATED' | 'SUSPICIOUS' | 'COMPROMISED' | 'TARGET'

export interface NodeState extends Host {
  packets: number
  bytes: number
  connections: number
  risk: number // 0..1
  status: HostStatus
  inRate: number // pps smoothed
  outRate: number
  lastSeen: number
  behaviors: Signal[]
}

export interface EdgeState {
  id: string // src->dst
  source: string
  target: string
  protocol: Protocol
  packets: number
  bytes: number
  flows: number
  rate: number // flows/s smoothed
  pps: number
  avgDuration: number
  anomaly: number // smoothed 0..1
  peakAnomaly: number
  attention: number
  classification: Classification
  attackClass: AttackType
  lastSeen: number
  signals: Signal[]
  ports: number[]
}

export type ThreatLevel = 'LOW' | 'GUARDED' | 'ELEVATED' | 'HIGH' | 'CRITICAL'

export type Severity = 'CRITICAL' | 'WARNING' | 'INFO'

export interface Incident {
  id: string
  severity: Severity
  title: string
  attackClass: AttackType
  source: string
  target: string
  risk: number
  attention: number
  ts: number
  edgeId: string
  signals: Signal[]
  flowsObserved: number
  status: 'ACTIVE' | 'CONTAINED'
}

export type TimelineStage = 'NORMAL' | 'SPIKE' | 'ANOMALY' | 'DETECTED' | 'CRITICAL' | 'STOPPED' | 'RECOVERED'

export interface TimelineEvent {
  id: string
  ts: number
  stage: TimelineStage
  label: string
}

export interface MetricPoint {
  t: number
  flows: number
  normal: number
  anomalous: number
  packets: number
  anomaly: number // max smoothed anomaly
  meanAnomaly: number
}

export interface ScenarioConfig {
  attack: AttackType
  intensity: Intensity
  durationSec: 5 | 10 | 20
}

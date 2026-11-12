import { create } from 'zustand'
import type { GraphSnapshot } from '../engine/graphEngine'
import type { DatasetInfo, ReplaySpeed } from '../engine/datasetReplay'
import type { AttackPhase } from '../engine/simulationEngine'
import type {
  AttackType, Incident, MetricPoint, Protocol, ScenarioConfig, Signal, ThreatLevel, TimelineEvent,
} from '../engine/types'

export type View = 'overview' | 'simulator' | 'graph' | 'engine' | 'incidents'
export type Selection = { kind: 'node'; id: string } | { kind: 'edge'; id: string } | null
export type NetworkStatus = 'NORMAL' | 'ELEVATED' | 'UNDER ATTACK' | 'RECOVERING'
export type ModelStatus = 'simulation' | 'connecting' | 'online' | 'offline'
export type Story = 'OBSERVE' | 'ATTACK' | 'DETECT' | 'INVESTIGATE' | 'RECOVER'

export interface EpisodeSummary {
  id: string
  attackClass: AttackType
  source: string
  target: string
  flowsAnalyzed: number
  suspiciousFlows: number
  peakAnomaly: number
  peakAttention: number
  confidence: number
  detectedAt: number | null
  startedAt: number
  endedAt: number
  edgeId: string
  signals: Signal[]
  incidentId: string | null
}

export interface DemoState {
  running: boolean
  phase: number
  title: string
  caption: string
}

export interface ReplayState {
  info: DatasetInfo
  speed: ReplaySpeed
  cursor: number
  playing: boolean
  tp: number
  fp: number
  tn: number
  fn: number
  lastTruth: string
}

export interface SentinelState {
  ready: boolean
  // pipeline configuration
  engineMode: 'simulation' | 'model'
  modelUrl: string
  modelStatus: ModelStatus
  source: 'simulation' | 'replay'
  threshold: number

  // simulator
  scenario: ScenarioConfig
  simPhase: AttackPhase
  attackLevel: number
  activeAttack: AttackType
  load: number

  // live analysis
  graph: GraphSnapshot
  metrics: MetricPoint[]
  markers: { t: number; label: string; kind: 'detect' | 'stop' }[]
  totals: { flows: number; anomalous: number; packets: number }
  protocols: Record<Protocol, number>
  threatScore: number
  threatLevel: ThreatLevel
  networkStatus: NetworkStatus
  inference: { active: boolean; latencyMs: number; flowsPerSec: number; stage: number }
  topEdgeId: string | null
  story: Story

  incidents: Incident[]
  timeline: TimelineEvent[]
  alertIncidentId: string | null
  summary: EpisodeSummary | null
  episodeActive: boolean

  // ui
  view: View
  selection: Selection
  focus: { ids: string[]; nonce: number }
  presentation: boolean
  explainPulse: number
  investigated: boolean
  demo: DemoState
  replay: ReplayState
}

export const useSentinel = create<SentinelState>(() => ({
  ready: false,
  engineMode: 'simulation',
  modelUrl: (import.meta.env.VITE_MODEL_API_URL as string | undefined) ?? 'http://127.0.0.1:8000',
  modelStatus: 'simulation',
  source: 'simulation',
  threshold: 0.65,

  scenario: { attack: 'portscan', intensity: 'MEDIUM', durationSec: 10 },
  simPhase: 'idle',
  attackLevel: 0,
  activeAttack: 'normal',
  load: 1,

  graph: { nodes: [], edges: [] },
  metrics: [],
  markers: [],
  totals: { flows: 0, anomalous: 0, packets: 0 },
  protocols: { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
  threatScore: 0,
  threatLevel: 'LOW',
  networkStatus: 'NORMAL',
  inference: { active: false, latencyMs: 0, flowsPerSec: 0, stage: 0 },
  topEdgeId: null,
  story: 'OBSERVE',

  incidents: [],
  timeline: [],
  alertIncidentId: null,
  summary: null,
  episodeActive: false,

  view: 'overview',
  selection: null,
  focus: { ids: [], nonce: 0 },
  presentation: false,
  explainPulse: 0,
  investigated: false,
  demo: { running: false, phase: 0, title: '', caption: '' },
  replay: {
    info: { name: 'CICIDS2017', rows: 50000, origin: 'mock', labels: {} },
    speed: 5,
    cursor: 0,
    playing: false,
    tp: 0,
    fp: 0,
    tn: 0,
    fn: 0,
    lastTruth: 'BENIGN',
  },
}))

export const set = useSentinel.setState
export const get = useSentinel.getState

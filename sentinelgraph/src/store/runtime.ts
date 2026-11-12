import { DatasetReplayEngine, MOCK_HOSTS, parseCicidsCsv, type ReplaySpeed } from '../engine/datasetReplay'
import {
  ModelApiDetectionEngine, SimulatedDetectionEngine, confidenceFor, type DetectionEngine,
} from '../engine/detectionEngine'
import { GraphEngine } from '../engine/graphEngine'
import { SCENARIOS } from '../engine/scenarios'
import { SimulationEngine, type FlowSource } from '../engine/simulationEngine'
import { SIM_HOSTS } from '../engine/topology'
import type {
  AnalyzedFlow, AttackType, Detection, EdgeState, Incident, MetricPoint, Protocol, ScenarioConfig, Severity,
  ThreatLevel, TimelineEvent, TimelineStage,
} from '../engine/types'
import { uid } from '../lib/random'
import { get, set, type EpisodeSummary, type Selection, type View } from './store'

/**
 * Runtime — the orchestrator. Every tick:
 *
 *   FlowSource.tick()  →  GraphEngine.observe() (graph context)
 *                      →  DetectionEngine.analyzeBatch()
 *                      →  GraphEngine.ingest()  →  episode / incident logic  →  store
 */

const TICK_MS = 500
const HISTORY = 120 // 60 s of metric points

const sim = new SimulationEngine()
const replay = new DatasetReplayEngine()
const simDetector = new SimulatedDetectionEngine()
let modelDetector: ModelApiDetectionEngine | null = null
let modelRetryAt = 0
const graph = new GraphEngine(SIM_HOSTS)

let source: FlowSource = sim
let busy = false
let clock = Date.now()

// rolling stats
const protoWindow: Record<Protocol, number>[] = []
let threat = 0
let baselineFlows = 20

// ── episode tracking ────────────────────────────────────────────────────────
interface Episode {
  id: string
  startedAt: number
  stages: Set<TimelineStage>
  flows: number
  suspicious: number
  peak: number
  peakAttention: number
  peakConfidence: number
  attackClass: AttackType
  edgeId: string
  source: string
  target: string
  detectedAt: number | null
  stoppedAt: number | null
  aboveTicks: number
  calmTicks: number
  primaryIncident: string | null
  warnedEdges: Set<string>
  signals: EdgeState['signals']
  operator: boolean // started by the simulator (vs. detection-driven in replay)
}
let episode: Episode | null = null

// ─────────────────────────────────────────────────────────────────────────────
let booted = false
export async function boot() {
  if (booted) return
  booted = true
  sim.onAutoStop = () => onAttackStopped('Scheduled duration elapsed')
  // warm-up: 30 s of normal traffic so charts and graph are populated on first paint
  clock = Date.now() - 30_000
  for (let i = 0; i < 60; i++) {
    clock += TICK_MS
    await step(clock, true)
  }
  set({ ready: true })
  setInterval(() => {
    if (busy) return
    clock = Date.now()
    void step(clock, false)
  }, TICK_MS)
}

function detector(): DetectionEngine {
  const s = get()
  if (s.engineMode === 'model' && modelDetector && (s.modelStatus !== 'offline' || clock >= modelRetryAt)) return modelDetector
  return simDetector
}

async function step(now: number, warm: boolean) {
  busy = true
  try {
    const flows = source.tick(now, TICK_MS)
    const ctxs = graph.observe(flows, now)
    const t0 = performance.now()
    let detections: Detection[]
    const d = detector()
    try {
      detections = await d.analyzeBatch(flows, ctxs)
      if (d.mode === 'model' && get().modelStatus !== 'online') set({ modelStatus: 'online' })
      if (d.mode === 'model') graph.threshold = d.threshold
    } catch {
      set({ modelStatus: 'offline' })
      modelRetryAt = now + 5000
      detections = await simDetector.analyzeBatch(flows, ctxs)
    }
    const latency = performance.now() - t0
    const analyzed: AnalyzedFlow[] = flows.map((f, i) => ({ ...f, detection: detections[i] }))
    graph.ingest(analyzed, now, TICK_MS)
    publish(analyzed, now, latency, warm)
  } finally {
    busy = false
  }
}

const LEVEL_FLOORS: [ThreatLevel, number][] = [['CRITICAL', 0.85], ['HIGH', 0.65], ['ELEVATED', 0.45], ['GUARDED', 0.3], ['LOW', 0]]
let lastLevel: ThreatLevel = 'LOW'

/** Threat level with hysteresis, so the label doesn't flicker around a boundary. */
function levelFor(score: number): ThreatLevel {
  const raw = LEVEL_FLOORS.find(([, f]) => score >= f)![0]
  const rank = (l: ThreatLevel) => LEVEL_FLOORS.findIndex(([x]) => x === l)
  if (rank(raw) > rank(lastLevel)) {
    // dropping: only once the score is clearly below the current level's floor
    const floor = LEVEL_FLOORS[rank(lastLevel)][1]
    if (score > floor - 0.06) return lastLevel
  }
  lastLevel = raw
  return raw
}

function publish(analyzed: AnalyzedFlow[], now: number, latency: number, warm: boolean) {
  const s = get()
  const thr = detector().threshold
  const snap = graph.snapshot()
  const dt = TICK_MS / 1000

  // ── tick metrics
  let anomalous = 0
  let packets = 0
  let pSum = 0
  const proto: Record<Protocol, number> = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 }
  for (const f of analyzed) {
    if (f.detection.anomaly_probability >= thr) anomalous++
    packets += f.packet_count
    pSum += f.detection.anomaly_probability
    proto[f.protocol]++
  }
  protoWindow.push(proto)
  if (protoWindow.length > 20) protoWindow.shift()
  const protocols: Record<Protocol, number> = { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 }
  for (const p of protoWindow) for (const k of Object.keys(p) as Protocol[]) protocols[k] += p[k]

  let top: EdgeState | null = null
  let anomEdges = 0
  for (const e of snap.edges) {
    if (!top || e.anomaly > top.anomaly) top = e
    if (e.anomaly >= thr) anomEdges++
  }
  const maxA = top?.anomaly ?? 0
  threat += (maxA * (0.85 + 0.15 * Math.min(1, anomEdges / 3)) - threat) * 0.35
  const threatLevel = levelFor(threat)

  const point: MetricPoint = {
    t: now,
    flows: analyzed.length / dt,
    normal: (analyzed.length - anomalous) / dt,
    anomalous: anomalous / dt,
    packets: packets / dt,
    anomaly: maxA,
    meanAnomaly: analyzed.length ? pSum / analyzed.length : 0,
  }
  const metrics = [...s.metrics, point].slice(-HISTORY)
  if (!episode && s.simPhase === 'idle') baselineFlows = baselineFlows * 0.95 + point.flows * 0.05

  // ── replay accuracy (ground truth is only used for scoring, never by the detector)
  let replayPatch = {}
  if (source === replay) {
    let { tp, fp, tn, fn } = s.replay
    let lastTruth = s.replay.lastTruth
    for (const f of analyzed) {
      const attack = f.truth !== 'BENIGN'
      const flagged = f.detection.anomaly_probability >= thr
      if (attack && flagged) tp++
      else if (attack) fn++
      else if (flagged) fp++
      else tn++
      lastTruth = f.truth ?? lastTruth
    }
    replayPatch = {
      replay: { ...s.replay, tp, fp, tn, fn, lastTruth, cursor: replay.cursor, playing: replay.playing && !replay.done },
    }
    if (replay.done && replay.playing) replay.playing = false
  }

  const events = warm ? null : updateEpisode(now, top, snap.edges, analyzed, thr, threatLevel)

  set({
    graph: snap,
    metrics,
    totals: {
      flows: s.totals.flows + analyzed.length,
      anomalous: s.totals.anomalous + anomalous,
      packets: s.totals.packets + packets,
    },
    protocols,
    threatScore: threat,
    threatLevel,
    simPhase: sim.phase,
    attackLevel: sim.level,
    activeAttack: sim.attack,
    load: sim.load,
    topEdgeId: top && top.anomaly > 0.25 ? top.id : null,
    threshold: thr,
    inference: {
      active: analyzed.length > 0,
      latencyMs: latency,
      flowsPerSec: point.flows,
      stage: (s.inference.stage + 1) % 6,
    },
    ...replayPatch,
    ...(events ?? {}),
  })
}

// ── episode state machine ────────────────────────────────────────────────────
function updateEpisode(
  now: number, top: EdgeState | null, edges: EdgeState[], analyzed: AnalyzedFlow[], thr: number, level: ThreatLevel,
) {
  const s = get()
  const maxA = top?.anomaly ?? 0
  const patch: Partial<ReturnType<typeof get>> = {}
  let timeline = s.timeline
  let incidents = s.incidents
  let markers = s.markers

  const addEvent = (stage: TimelineStage, label: string, ts = now) => {
    if (!episode || episode.stages.has(stage)) return
    episode.stages.add(stage)
    const ev: TimelineEvent = { id: uid('t'), ts, stage, label }
    timeline = [...timeline, ev]
  }

  // detection-driven start (replay, or anomalies without an operator-launched attack)
  if (!episode && maxA >= 0.45 && top) {
    startEpisode(now, false)
    timeline = get().timeline
  }
  if (!episode) {
    return { networkStatus: maxA >= 0.45 ? 'ELEVATED' : 'NORMAL', story: 'OBSERVE' } as const
  }
  const ep = episode

  // track the strongest edge of this episode
  if (top && maxA >= 0.25 && (maxA >= ep.peak * 0.9 || !ep.edgeId)) {
    ep.edgeId = top.id
    ep.source = top.source
    ep.target = top.target
    ep.signals = top.signals
    if (top.attackClass !== 'normal') ep.attackClass = top.attackClass
  }
  ep.peak = Math.max(ep.peak, maxA)
  ep.peakAttention = Math.max(ep.peakAttention, top && maxA >= 0.25 ? top.attention : 0)
  ep.flows += analyzed.length
  for (const f of analyzed) {
    if (f.detection.anomaly_probability >= thr) {
      ep.suspicious++
      ep.peakConfidence = Math.max(ep.peakConfidence, f.detection.confidence)
    }
  }

  const tick = s.metrics[s.metrics.length - 1]
  if (tick && (tick.flows > baselineFlows * 1.3 || tick.packets > 3000)) addEvent('SPIKE', 'Traffic spike observed')

  if (maxA >= 0.45 && top && !ep.stages.has('ANOMALY')) {
    if (!ep.stages.has('SPIKE')) addEvent('SPIKE', 'Traffic pattern shift')
    addEvent('ANOMALY', `Anomalous edge ${top.source} → ${top.target}`)
    incidents = [makeIncident('WARNING', warningTitle(top), top, now), ...incidents]
    ep.warnedEdges.add(top.id)
  }

  ep.aboveTicks = maxA >= thr ? ep.aboveTicks + 1 : 0
  if (ep.aboveTicks >= 2 && top && !ep.detectedAt) {
    ep.detectedAt = now
    const cls = top.attackClass !== 'normal' ? top.attackClass : ep.attackClass
    ep.attackClass = cls
    addEvent('DETECTED', `${SCENARIOS[cls].name} classified`)
    const inc = makeIncident('CRITICAL', `${SCENARIOS[cls].name} detected`, top, now)
    ep.primaryIncident = inc.id
    ep.warnedEdges.add(top.id)
    incidents = [inc, ...incidents]
    markers = [...markers, { t: now, label: 'Attack detected', kind: 'detect' as const }].slice(-6)
    patch.alertIncidentId = inc.id
  }

  // keep the primary incident's numbers fresh while active
  if (ep.primaryIncident && top) {
    incidents = incidents.map((i) =>
      i.id === ep.primaryIncident && i.status === 'ACTIVE'
        ? { ...i, risk: Math.max(i.risk, top.anomaly), attention: Math.max(i.attention, top.attention), flowsObserved: ep.suspicious, signals: top.anomaly >= i.risk ? top.signals : i.signals }
        : i,
    )
  }

  // other anomalous relationships (DDoS bots, sweep targets…) become warnings
  if (ep.detectedAt) {
    for (const e of edges) {
      if (e.anomaly >= thr && !ep.warnedEdges.has(e.id) && ep.warnedEdges.size < 7) {
        ep.warnedEdges.add(e.id)
        incidents = [makeIncident('WARNING', `Additional flagged source ${e.source}`, e, now), ...incidents]
      }
    }
  }

  if (level === 'CRITICAL') addEvent('CRITICAL', 'Threat level critical')

  // detection-driven "stop" for replay
  if (!ep.operator && ep.detectedAt && !ep.stoppedAt && maxA < thr - 0.1) {
    ep.stoppedAt = now
    addEvent('STOPPED', 'Anomalous activity subsiding')
  }

  // recovery
  if (ep.stoppedAt) {
    ep.calmTicks = maxA < 0.3 ? ep.calmTicks + 1 : 0
    if (ep.calmTicks >= 3) {
      addEvent('RECOVERED', 'Traffic normalized')
      incidents = incidents.map((i) => (i.status === 'ACTIVE' ? { ...i, status: 'CONTAINED' as const } : i))
      if (ep.detectedAt) patch.summary = summarise(ep, now)
      patch.alertIncidentId = null
      episode = null
    }
  } else if (!ep.operator && !ep.detectedAt && maxA < 0.3) {
    // a blip that never crossed the threshold
    ep.calmTicks++
    if (ep.calmTicks > 6) episode = null
  }

  const networkStatus = !episode ? 'NORMAL' : ep.stoppedAt ? 'RECOVERING' : ep.detectedAt ? 'UNDER ATTACK' : 'ELEVATED'
  const story = !episode
    ? patch.summary ? 'RECOVER' : 'OBSERVE'
    : ep.stoppedAt ? 'RECOVER' : s.investigated ? 'INVESTIGATE' : ep.detectedAt ? 'DETECT' : 'ATTACK'

  return {
    ...patch,
    timeline: timeline.slice(-14),
    incidents: incidents.slice(0, 60),
    markers,
    networkStatus,
    story,
    episodeActive: !!episode,
  } as const
}

function startEpisode(now: number, operator: boolean) {
  episode = {
    id: uid('e'),
    startedAt: now,
    stages: new Set(['NORMAL']),
    flows: 0,
    suspicious: 0,
    peak: 0,
    peakAttention: 0,
    peakConfidence: 0,
    attackClass: operator ? get().scenario.attack : 'normal',
    edgeId: '',
    source: '',
    target: '',
    detectedAt: null,
    stoppedAt: null,
    aboveTicks: 0,
    calmTicks: 0,
    primaryIncident: null,
    warnedEdges: new Set(),
    signals: [],
    operator,
  }
  const ev: TimelineEvent = { id: uid('t'), ts: now - 2000, stage: 'NORMAL', label: 'Normal operations' }
  set({ timeline: [ev], summary: null, investigated: false, episodeActive: true })
}

function warningTitle(e: EdgeState): string {
  const top = e.signals[0]?.key
  switch (top) {
    case 'portDiversity': return 'Unusual port diversity'
    case 'packetRate': return 'Abnormal packet rate'
    case 'failedAttempts': return 'Repeated failed connections'
    case 'externalBeacon': return 'Unusual external communication'
    case 'sourceFanIn': return 'Converging high-rate sources'
    default: return 'Abnormal connection rate'
  }
}

function makeIncident(severity: Severity, title: string, e: EdgeState, now: number): Incident {
  return {
    id: uid('i'),
    severity,
    title,
    attackClass: e.attackClass,
    source: e.source,
    target: e.target,
    risk: e.anomaly,
    attention: e.attention,
    ts: now,
    edgeId: e.id,
    signals: e.signals,
    flowsObserved: e.flows,
    status: 'ACTIVE',
  }
}

function summarise(ep: Episode, now: number): EpisodeSummary {
  return {
    id: ep.id,
    attackClass: ep.attackClass,
    source: ep.attackClass === 'ddos' ? `${ep.source} +${Math.max(0, ep.warnedEdges.size - 1)}` : ep.source,
    target: ep.target,
    flowsAnalyzed: ep.flows,
    suspiciousFlows: ep.suspicious,
    peakAnomaly: ep.peak,
    peakAttention: ep.peakAttention,
    confidence: ep.peakConfidence || confidenceFor(ep.peak, get().threshold),
    detectedAt: ep.detectedAt,
    startedAt: ep.startedAt,
    endedAt: now,
    edgeId: ep.edgeId,
    signals: ep.signals,
    incidentId: ep.primaryIncident,
  }
}

function onAttackStopped(reason: string) {
  if (!episode) return
  if (!episode.stoppedAt) {
    episode.stoppedAt = Date.now()
    const ev: TimelineEvent = { id: uid('t'), ts: episode.stoppedAt, stage: 'STOPPED', label: reason }
    episode.stages.add('STOPPED')
    set((s) => ({
      timeline: [...s.timeline, ev],
      markers: [...s.markers, { t: ev.ts, label: 'Stopped', kind: 'stop' as const }].slice(-6),
    }))
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Public actions (called by UI)
// ─────────────────────────────────────────────────────────────────────────────
export function setScenario(patch: Partial<ScenarioConfig>) {
  set((s) => ({ scenario: { ...s.scenario, ...patch } }))
}

export function launchAttack(config?: Partial<ScenarioConfig>, rampSec = 5) {
  if (source !== sim) switchToSimulation()
  const scenario = { ...get().scenario, ...config }
  set({ scenario, summary: null })
  if (scenario.attack === 'normal') {
    stopAttack()
    return
  }
  if (episode && !episode.stoppedAt) onAttackStopped('Superseded by new simulation')
  episode = null
  sim.start(scenario, Date.now(), rampSec)
  startEpisode(Date.now(), true)
  set({ simPhase: sim.phase, activeAttack: sim.attack, alertIncidentId: null, selection: null })
}

export function stopAttack() {
  if (sim.running) {
    sim.stop(Date.now())
    onAttackStopped('Attack stopped by operator')
  }
  set({ simPhase: sim.phase })
}

export function setLoad(x: number) {
  sim.setLoad(x)
}

export function setEngineMode(mode: 'simulation' | 'model', url?: string) {
  if (mode === 'model') {
    const modelUrl = url ?? get().modelUrl
    modelDetector = new ModelApiDetectionEngine(modelUrl)
    modelRetryAt = 0
    set({ engineMode: 'model', modelUrl, modelStatus: 'connecting' })
  } else {
    modelDetector = null
    graph.threshold = simDetector.threshold
    set({ engineMode: 'simulation', modelStatus: 'simulation' })
  }
}

function resetPipeline(hosts = SIM_HOSTS, maxNodes = 40) {
  graph.reset(hosts, maxNodes)
  simDetector.reset()
  episode = null
  threat = 0
  protoWindow.length = 0
  set({ alertIncidentId: null, selection: null, summary: null, markers: [], episodeActive: false, investigated: false })
}

export function switchToSimulation() {
  if (source === sim) return
  replay.playing = false
  source = sim
  resetPipeline(SIM_HOSTS)
  set((s) => ({ source: 'simulation', replay: { ...s.replay, playing: false } }))
}

export function switchToReplay() {
  if (source === replay) return
  sim.reset()
  source = replay
  resetPipeline(replay.hosts(), 36)
  set({ source: 'replay', simPhase: 'idle', activeAttack: 'normal' })
}

export function startReplay(speed?: ReplaySpeed) {
  switchToReplay()
  if (speed) replay.speed = speed
  if (replay.done) replay.cursor = 0
  replay.playing = true
  set((s) => ({ replay: { ...s.replay, playing: true, speed: replay.speed, info: replay.info } }))
}

export function pauseReplay() {
  replay.playing = false
  set((s) => ({ replay: { ...s.replay, playing: false } }))
}

export function setReplaySpeed(speed: ReplaySpeed) {
  replay.speed = speed
  set((s) => ({ replay: { ...s.replay, speed } }))
}

export function skipReplayToAttack() {
  replay.skipToNextAttack()
  set((s) => ({ replay: { ...s.replay, cursor: replay.cursor } }))
}

export function restartReplay() {
  replay.cursor = 0
  set((s) => ({ replay: { ...s.replay, cursor: 0, tp: 0, fp: 0, tn: 0, fn: 0 } }))
}

export async function loadCsv(file: File): Promise<string | null> {
  const text = await file.text()
  const { rows, missing } = parseCicidsCsv(text)
  if (missing.length) return `Missing columns: ${missing.join(', ')}`
  if (!rows.length) return 'No rows found'
  replay.playing = false
  replay.useCsv(file.name, rows)
  if (source === replay) resetPipeline([], 36)
  set((s) => ({ replay: { ...s.replay, info: replay.info, cursor: 0, playing: false, tp: 0, fp: 0, tn: 0, fn: 0 } }))
  return null
}

export function selectMockDataset() {
  replay.playing = false
  replay.useMock()
  if (source === replay) resetPipeline(MOCK_HOSTS, 36)
  set((s) => ({ replay: { ...s.replay, info: replay.info, cursor: 0, playing: false, tp: 0, fp: 0, tn: 0, fn: 0 } }))
}

export function setView(view: View) {
  set({ view })
}

export function select(selection: Selection) {
  set({ selection })
}

export function focusOn(ids: string[]) {
  set((s) => ({ focus: { ids, nonce: s.focus.nonce + 1 } }))
}

export function investigate(opts: { incidentId?: string | null; edgeId?: string } = {}) {
  const s = get()
  const inc = s.incidents.find((i) => i.id === (opts.incidentId ?? s.alertIncidentId))
  const selected = s.selection?.kind === 'edge' ? s.selection.id : undefined
  const edgeId = opts.edgeId ?? inc?.edgeId ?? selected ?? s.summary?.edgeId ?? s.topEdgeId
  if (!edgeId) return
  const [src, dst] = edgeId.split('->')
  set((st) => ({
    selection: { kind: 'edge', id: edgeId },
    investigated: true,
    alertIncidentId: null,
    explainPulse: st.explainPulse + 1,
    view: st.view === 'incidents' || st.view === 'simulator' ? 'overview' : st.view,
  }))
  focusOn([src, dst])
}

export function dismissAlert() {
  set({ alertIncidentId: null })
}

export function dismissSummary() {
  set({ summary: null })
}

export function togglePresentation(on?: boolean) {
  set((s) => ({ presentation: on ?? !s.presentation, view: 'overview' }))
}

export function clearIncidents() {
  set({ incidents: [] })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Full demo — a scripted 10-phase story (~40 s)
// ─────────────────────────────────────────────────────────────────────────────
let demoToken = 0

export const DEMO_PHASES = [
  ['Normal traffic', '24 hosts are communicating normally. Every connection is an edge in the graph, and each edge is scored as it happens.'],
  ['Traffic gradually increases', 'Load rises across the network. More traffic alone is not an attack, so the anomaly scores stay low.'],
  ['Suspicious behaviour appears', 'Workstation 10.0.0.15 starts touching ports on 10.0.0.24 that it has never used before.'],
  ['Attack begins', 'The probing turns into a full port scan: hundreds of short, rejected connections from a single source.'],
  ['GNN detects anomaly', 'GATv2 combines each edge’s flow features with its neighbours in the graph. The scan edge crosses the 0.65 threshold.'],
  ['Suspicious connection highlighted', 'The graph isolates the relationship that matters: 10.0.0.15 → 10.0.0.24.'],
  ['Incident generated', 'A critical incident is raised with the source, the target and the risk score.'],
  ['Model explanation', 'Attention concentrates on the scan edge. Port diversity and bursts of short flows drive the score.'],
  ['Attack stops', 'The simulated attacker is stopped. No real traffic was ever generated.'],
  ['Network recovers', 'Edge scores decay and the threat level falls. The incident stays in the history.'],
] as const

function demoPhase(phase: number) {
  const [title, caption] = DEMO_PHASES[phase - 1]
  set({ demo: { running: true, phase, title, caption } })
}

export async function runDemo() {
  const token = ++demoToken
  const alive = () => token === demoToken
  const wait = (ms: number) => new Promise<boolean>((r) => setTimeout(() => r(alive()), ms))
  const waitFor = async (cond: () => boolean, timeout: number) => {
    const t0 = Date.now()
    while (alive() && !cond() && Date.now() - t0 < timeout) await wait(200)
    return alive()
  }

  // reset to a calm network
  switchToSimulation()
  sim.reset()
  episode = null
  set({ view: 'overview', selection: null, alertIncidentId: null, summary: null, investigated: false, timeline: [] })
  focusOn([])

  demoPhase(1)
  if (!(await wait(5000))) return
  demoPhase(2)
  setLoad(1.7)
  if (!(await wait(5000))) return
  demoPhase(3)
  launchAttack({ attack: 'portscan', intensity: 'HIGH', durationSec: 20 }, 8)
  focusOn(['10.0.0.15', '10.0.0.24'])
  if (!(await wait(4000))) return
  demoPhase(4)
  if (!(await waitFor(() => get().alertIncidentId !== null, 12000))) return
  demoPhase(5)
  if (!(await wait(3000))) return
  demoPhase(6)
  const edge = get().incidents[0]?.edgeId ?? '10.0.0.15->10.0.0.24'
  set({ selection: { kind: 'edge', id: edge } })
  focusOn(edge.split('->'))
  if (!(await wait(3500))) return
  demoPhase(7)
  if (!(await wait(3500))) return
  demoPhase(8)
  investigate()
  if (!(await wait(6000))) return
  demoPhase(9)
  stopAttack()
  setLoad(1)
  set({ alertIncidentId: null })
  if (!(await wait(2500))) return
  demoPhase(10)
  set({ selection: null })
  focusOn([])
  await waitFor(() => get().summary !== null, 14000)
  if (!(await wait(4000))) return
  set((s) => ({ demo: { ...s.demo, running: false } }))
}

export function stopDemo() {
  demoToken++
  set({ demo: { running: false, phase: 0, title: '', caption: '' } })
  stopAttack()
  setLoad(1)
}

export const engines = { sim, replay, graph, simDetector }

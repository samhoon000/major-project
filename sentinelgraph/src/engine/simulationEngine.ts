import { chance, clamp, logRand, pick, rand, randInt, uid, weightedPick } from '../lib/random'
import { EXTERNAL_HOSTS, IOT, NORMAL_PATTERNS, SERVICES, SIM_HOSTS, type Service } from './topology'
import type { AttackType, Flow, Host, Intensity, Protocol, ScenarioConfig } from './types'

/**
 * A FlowSource produces network flows. Simulation Mode and Dataset Replay both implement it,
 * and a live capture/collector could implement it later (e.g. a WebSocket fed by CICFlowMeter).
 */
export interface FlowSource {
  readonly kind: 'simulation' | 'replay'
  hosts(): Host[]
  tick(now: number, dtMs: number): Flow[]
}

export type AttackPhase = 'idle' | 'ramp' | 'active' | 'decay'

const INTENSITY_SCALE: Record<Intensity, number> = { LOW: 0.45, MEDIUM: 0.72, HIGH: 1 }

const BASE_FLOWS_PER_SEC = 20

function makeFlow(
  now: number,
  src: string,
  dst: string,
  sport: number,
  dport: number,
  protocol: Protocol,
  fwd: number,
  bwd: number,
  bytes: number,
  durationMs: number,
  failed: boolean,
  truth: string,
): Flow {
  const packets = fwd + bwd
  const dur = Math.max(durationMs, 0.05)
  return {
    id: uid(),
    ts: now,
    source_ip: src,
    destination_ip: dst,
    source_port: sport,
    destination_port: dport,
    protocol,
    packet_count: packets,
    fwd_packets: fwd,
    bwd_packets: bwd,
    bytes: Math.round(bytes),
    flow_duration: dur,
    packet_rate: packets / (dur / 1000),
    byte_rate: bytes / (dur / 1000),
    failed,
    truth,
  }
}

function serviceFlow(now: number, src: string, dst: string, svc: Service): Flow {
  const packets = randInt(svc.packets[0], svc.packets[1])
  const fwd = Math.max(1, Math.round(packets * rand(0.4, 0.6)))
  const bwd = svc.protocol === 'ICMP' || svc.protocol === 'UDP' ? packets - fwd : Math.max(1, packets - fwd)
  const bytes = packets * rand(svc.size[0], svc.size[1])
  return makeFlow(
    now, src, dst, randInt(49152, 65535), svc.port, svc.protocol,
    fwd, bwd, bytes, logRand(svc.duration[0], svc.duration[1]), chance(0.01), 'BENIGN',
  )
}

/** Browser-side generator of realistic-looking network flows. No packets are ever sent. */
export class SimulationEngine implements FlowSource {
  readonly kind = 'simulation' as const
  config: ScenarioConfig = { attack: 'portscan', intensity: 'MEDIUM', durationSec: 10 }
  phase: AttackPhase = 'idle'
  /** attack envelope 0..1 — rises during ramp, falls during decay */
  level = 0
  /** background load multiplier (the full demo raises it before the attack) */
  load = 1
  private targetLoad = 1
  rampSec = 3.5
  decaySec = 5
  private startedAt = 0
  private stopRequestedAt = 0
  private levelAtStop = 0
  private scanCursor = 0
  private scanPorts: number[] = []
  private c2Next = 0
  private activeAttack: AttackType = 'normal'
  onAutoStop?: () => void

  hosts(): Host[] {
    return SIM_HOSTS
  }

  get attack(): AttackType {
    return this.activeAttack
  }

  get running() {
    return this.phase === 'ramp' || this.phase === 'active'
  }

  setLoad(target: number) {
    this.targetLoad = target
  }

  start(config: ScenarioConfig, now: number, rampSec = 3.5) {
    this.config = config
    this.activeAttack = config.attack
    this.phase = config.attack === 'normal' ? 'idle' : 'ramp'
    this.startedAt = now
    this.rampSec = rampSec
    this.level = 0
    this.scanCursor = 0
    this.scanPorts = shuffledPorts()
  }

  stop(now: number) {
    if (this.phase === 'ramp' || this.phase === 'active') {
      this.phase = 'decay'
      this.stopRequestedAt = now
      this.levelAtStop = this.level
    }
  }

  reset() {
    this.phase = 'idle'
    this.level = 0
    this.load = 1
    this.targetLoad = 1
    this.activeAttack = 'normal'
  }

  tick(now: number, dtMs: number): Flow[] {
    const dt = dtMs / 1000
    this.load += (this.targetLoad - this.load) * clamp(dt * 0.6)
    this.updateEnvelope(now)

    const flows: Flow[] = []
    // ---- background traffic -------------------------------------------------
    const mean = BASE_FLOWS_PER_SEC * this.load * dt
    const n = Math.max(0, Math.round(mean + (Math.random() - 0.5) * Math.sqrt(mean) * 2))
    for (let i = 0; i < n; i++) {
      const p = weightedPick(NORMAL_PATTERNS)
      const src = Array.isArray(p.src) ? pick(p.src) : p.src
      const dst = Array.isArray(p.dst) ? pick(p.dst) : p.dst
      if (src === dst) continue
      flows.push(serviceFlow(now, src, dst, SERVICES[p.service]))
    }

    // ---- attack traffic -----------------------------------------------------
    if (this.level > 0.01 && this.activeAttack !== 'normal') {
      const k = INTENSITY_SCALE[this.config.intensity] * this.level
      flows.push(...this.attackFlows(now, dt, k))
    }
    // spread flow start times across the tick so inter-arrival statistics look natural
    for (const f of flows) if (f.truth !== 'Bot') f.ts = now - Math.random() * dtMs
    return flows
  }

  private updateEnvelope(now: number) {
    const t = (now - this.startedAt) / 1000
    if (this.phase === 'ramp') {
      this.level = easeInOut(clamp(t / this.rampSec))
      if (t >= this.rampSec) this.phase = 'active'
    } else if (this.phase === 'active') {
      this.level = 1
    }
    if ((this.phase === 'ramp' || this.phase === 'active') && t >= this.config.durationSec + this.rampSec) {
      this.stop(now)
      this.onAutoStop?.()
    }
    if (this.phase === 'decay') {
      const d = (now - this.stopRequestedAt) / 1000
      this.level = this.levelAtStop * (1 - easeInOut(clamp(d / this.decaySec)))
      if (d >= this.decaySec || this.level < 0.01) {
        this.level = 0
        this.phase = 'idle'
        this.activeAttack = 'normal'
      }
    }
  }

  private attackFlows(now: number, dt: number, k: number): Flow[] {
    const out: Flow[] = []
    const src = '10.0.0.15'
    const target = '10.0.0.24'
    const count = (perSec: number) => Math.round(perSec * k * dt + Math.random() * 0.8)

    switch (this.activeAttack) {
      case 'portscan': {
        const n = count(50)
        for (let i = 0; i < n; i++) {
          const port = this.scanPorts[this.scanCursor++ % this.scanPorts.length]
          const open = chance(0.04)
          out.push(makeFlow(now, src, target, randInt(40000, 65535), port, 'TCP',
            randInt(1, 2), open ? 1 : randInt(0, 1), rand(40, 120), rand(0.05, 3), !open, 'PortScan'))
        }
        // light horizontal sweep of neighbours once the scan is in full swing
        if (k > 0.5 && chance(0.6)) {
          const other = pick(['10.0.0.11', '10.0.0.12', '10.0.0.13', '10.0.0.25', '10.0.0.10'])
          out.push(makeFlow(now, src, other, randInt(40000, 65535), pick([22, 80, 443, 445, 3389, 8080]), 'TCP',
            1, randInt(0, 1), rand(40, 100), rand(0.05, 2), true, 'PortScan'))
        }
        break
      }
      case 'dos': {
        const n = count(22)
        for (let i = 0; i < n; i++) {
          const fwd = Math.round(logRand(400, 4000) * (0.4 + k * 0.6))
          out.push(makeFlow(now, src, target, randInt(1024, 65535), 80, 'TCP',
            fwd, randInt(0, 3), fwd * rand(60, 120), rand(40, 350), chance(0.7), 'DoS'))
        }
        break
      }
      case 'ddos': {
        const bots = [...EXTERNAL_HOSTS.filter((h) => h.label === 'botnet').map((h) => h.ip), IOT[0], IOT[1]]
        for (const bot of bots) {
          const n = count(5)
          for (let i = 0; i < n; i++) {
            const fwd = Math.round(logRand(250, 2200) * (0.4 + k * 0.6))
            const udp = chance(0.35)
            out.push(makeFlow(now, bot, target, randInt(1024, 65535), udp ? 53 : 443, udp ? 'UDP' : 'TCP',
              fwd, randInt(0, 2), fwd * rand(60, 900), rand(30, 300), chance(0.5), 'DDoS'))
          }
        }
        break
      }
      case 'bruteforce': {
        const n = count(26)
        for (let i = 0; i < n; i++) {
          const ok = chance(0.02)
          const packets = randInt(12, 28)
          out.push(makeFlow(now, src, target, randInt(40000, 65535), 22, 'TCP',
            Math.ceil(packets / 2), Math.floor(packets / 2), packets * rand(90, 170), rand(180, 1400), !ok, 'SSH-Patator'))
        }
        break
      }
      case 'c2': {
        const c2 = '198.51.100.66'
        if (this.c2Next < now - 5000) this.c2Next = now
        while (this.c2Next <= now) {
          // periodic beacon with very low jitter
          const at = this.c2Next
          this.c2Next = at + 900 + rand(-25, 25)
          out.push(makeFlow(at, src, c2, randInt(49152, 65535), 4444, 'TCP', randInt(3, 5), randInt(3, 5), rand(300, 520), rand(60, 120), false, 'Bot'))
        }
        if (chance(0.3 * k)) {
          const packets = randInt(1500, 6000)
          out.push(makeFlow(now, src, c2, randInt(49152, 65535), 8443, 'TCP',
            packets, Math.round(packets * 0.1), packets * rand(1100, 1400), rand(2000, 9000), false, 'Bot'))
        }
        break
      }
    }
    return out
  }
}

function easeInOut(t: number) {
  return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2
}

function shuffledPorts() {
  const common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
  const rest = Array.from({ length: 1024 }, (_, i) => i + 1).filter((p) => !common.includes(p))
  for (let i = rest.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[rest[i], rest[j]] = [rest[j], rest[i]]
  }
  return [...common, ...rest]
}

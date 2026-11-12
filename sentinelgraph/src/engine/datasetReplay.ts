import { chance, logRand, pick, rand, randInt, uid } from '../lib/random'
import type { FlowSource } from './simulationEngine'
import type { Flow, Host, Protocol } from './types'

/**
 * Dataset Replay — re-plays recorded flows (CICIDS2017 column names) through the same
 * graph + detection pipeline as the simulator.
 *
 * Two inputs are supported:
 *   • a built-in representative mock of CICIDS2017 (generated on the fly, 50,000 rows)
 *   • a real CSV chosen by the user — parsed locally in the browser, never uploaded
 */

/** One CICIDS2017 row, after header whitespace is stripped. */
export type CicidsRow = Record<string, string>

export const REQUIRED_COLUMNS = [
  'Source IP',
  'Destination IP',
  'Flow Duration',
  'Total Fwd Packets',
  'Total Backward Packets',
  'Flow Bytes/s',
  'Flow Packets/s',
  'Label',
] as const

export interface DatasetInfo {
  name: string
  rows: number
  origin: 'mock' | 'csv'
  labels: Record<string, number>
}

const num = (v: string | undefined, d = 0) => {
  const x = Number(v)
  return Number.isFinite(x) ? x : d
}

function protoFrom(v: string | undefined): Protocol {
  if (v === '6' || v === 'TCP') return 'TCP'
  if (v === '17' || v === 'UDP') return 'UDP'
  if (v === '1' || v === 'ICMP') return 'ICMP'
  return v === undefined ? 'TCP' : 'OTHER'
}

function normaliseLabel(v: string | undefined) {
  const s = (v ?? '').trim()
  if (s === '0' || s.toUpperCase() === 'BENIGN') return 'BENIGN'
  if (s === '1') return 'ATTACK'
  return s || 'UNKNOWN'
}

/** Map a CICIDS2017 row to the app's Flow shape. */
export function rowToFlow(r: CicidsRow, ts: number): Flow {
  const fwd = num(r['Total Fwd Packets'])
  const bwd = num(r['Total Backward Packets'])
  const durationMs = Math.max(num(r['Flow Duration']) / 1000, 0.001) // CICIDS stores µs
  const byteRate = num(r['Flow Bytes/s'])
  const lenF = r['Total Length of Fwd Packets']
  const lenB = r['Total Length of Bwd Packets']
  const bytes = lenF !== undefined ? num(lenF) + num(lenB) : byteRate * (durationMs / 1000)
  return {
    id: uid(),
    ts,
    source_ip: r['Source IP'],
    destination_ip: r['Destination IP'],
    source_port: num(r['Source Port'], randInt(49152, 65535)),
    destination_port: num(r['Destination Port'], 0),
    protocol: protoFrom(r['Protocol']),
    packet_count: fwd + bwd,
    fwd_packets: fwd,
    bwd_packets: bwd,
    bytes: Math.round(bytes),
    flow_duration: durationMs,
    packet_rate: num(r['Flow Packets/s']),
    byte_rate: byteRate,
    failed: bwd === 0 && fwd <= 2,
    truth: normaliseLabel(r['Label']),
  }
}

/** Minimal CSV parser for CICIDS-style files (no quoted commas). */
export function parseCicidsCsv(text: string, limit = 50000): { rows: CicidsRow[]; missing: string[] } {
  const lines = text.split(/\r?\n/)
  const header = lines[0].split(',').map((h) => h.trim())
  const missing = REQUIRED_COLUMNS.filter((c) => !header.includes(c))
  const rows: CicidsRow[] = []
  for (let i = 1; i < lines.length && rows.length < limit; i++) {
    if (!lines[i]) continue
    const cells = lines[i].split(',')
    const row: CicidsRow = {}
    for (let j = 0; j < header.length; j++) row[header[j]] = cells[j]?.trim()
    rows.push(row)
  }
  return { rows, missing }
}

// ── Representative mock of CICIDS2017 ────────────────────────────────────────
// Lab addresses mirror the CICIDS2017 testbed (192.168.10.0/24 victim network,
// 172.16.0.1 attacker NAT). Benign "internet" peers use RFC 5737 documentation addresses.

const VICTIM_WEB = '192.168.10.50'
const DC_DNS = '192.168.10.3'
const ATTACKER = '172.16.0.1'
const CLIENTS = ['5', '8', '9', '12', '14', '15', '16', '17', '19', '25', '51'].map((n) => `192.168.10.${n}`)
const INTERNET = ['203.0.113.80', '203.0.113.91', '198.51.100.120', '198.51.100.7']

const MOCK_SEGMENTS: { from: number; to: number; label: string }[] = [
  { from: 3000, to: 6500, label: 'PortScan' },
  { from: 14000, to: 18000, label: 'DDoS' },
  { from: 26000, to: 29000, label: 'SSH-Patator' },
  { from: 37000, to: 40500, label: 'DoS Hulk' },
]

export const MOCK_INFO: DatasetInfo = {
  name: 'CICIDS2017',
  rows: 50000,
  origin: 'mock',
  labels: { BENIGN: 35500, PortScan: 3500, DDoS: 4000, 'SSH-Patator': 3000, 'DoS Hulk': 3500 },
}

function mockRow(i: number): CicidsRow {
  const seg = MOCK_SEGMENTS.find((s) => i >= s.from && i < s.to)
  // attacks are interleaved with background traffic, as in the real captures
  const label = seg && chance(0.72) ? seg.label : 'BENIGN'
  const row = (src: string, dst: string, dport: number, proto: string, fwd: number, bwd: number, durUs: number, bytes: number): CicidsRow => {
    const s = durUs / 1e6
    return {
      'Source IP': src,
      'Destination IP': dst,
      'Source Port': String(randInt(32768, 65535)),
      'Destination Port': String(dport),
      Protocol: proto,
      'Flow Duration': String(Math.round(durUs)),
      'Total Fwd Packets': String(fwd),
      'Total Backward Packets': String(bwd),
      'Flow Bytes/s': String(bytes / Math.max(s, 1e-6)),
      'Flow Packets/s': String((fwd + bwd) / Math.max(s, 1e-6)),
      Label: label,
    }
  }
  switch (label) {
    case 'PortScan':
      return row(ATTACKER, VICTIM_WEB, randInt(1, 1024), '6', 1, randInt(0, 1), rand(20, 3000), rand(0, 80))
    case 'DDoS': {
      const f = randInt(3, 9)
      return row(pick([ATTACKER, '205.174.165.73']), VICTIM_WEB, 80, '6', f, randInt(0, 6), logRand(1e3, 1e6), f * rand(20, 1400))
    }
    case 'SSH-Patator':
      return row(ATTACKER, VICTIM_WEB, 22, '6', randInt(11, 22), randInt(10, 33), rand(1e5, 9e6), rand(2000, 5500))
    case 'DoS Hulk': {
      const f = randInt(4, 8)
      return row(ATTACKER, VICTIM_WEB, 80, '6', f, randInt(0, 4), rand(500, 9e4), f * rand(300, 1400))
    }
  }
  const c = pick(CLIENTS)
  const r = Math.random()
  if (r < 0.35) return row(c, DC_DNS, 53, '17', 1, 1, rand(200, 9e4), rand(80, 300))
  if (r < 0.7) return row(c, pick(INTERNET), 443, '6', randInt(6, 40), randInt(4, 50), logRand(1e4, 2e7), randInt(800, 60000))
  if (r < 0.85) return row(c, VICTIM_WEB, 80, '6', randInt(3, 12), randInt(2, 14), logRand(5e3, 3e6), randInt(400, 12000))
  if (r < 0.95) return row(c, DC_DNS, pick([88, 389, 445]), '6', randInt(4, 18), randInt(3, 20), logRand(2e3, 2e6), randInt(500, 9000))
  return row(DC_DNS, pick(CLIENTS), 137, '17', 1, 0, rand(50, 500), 78)
}

export const MOCK_HOSTS: Host[] = [
  { id: VICTIM_WEB, ip: VICTIM_WEB, role: 'Web Server', zone: 'dmz', label: 'ubuntu-web' },
  { id: DC_DNS, ip: DC_DNS, role: 'DNS Server', zone: 'servers', label: 'win-dc' },
  ...CLIENTS.map((ip): Host => ({ id: ip, ip, role: 'Workstation', zone: 'office' })),
]

export type ReplaySpeed = 1 | 5 | 10

export class DatasetReplayEngine implements FlowSource {
  readonly kind = 'replay' as const
  info: DatasetInfo = MOCK_INFO
  speed: ReplaySpeed = 5
  cursor = 0
  playing = false
  private rows: CicidsRow[] | null = null // null → mock
  /** rows per second at 1x */
  static BASE_RATE = 20

  hosts(): Host[] {
    return this.rows ? [] : MOCK_HOSTS
  }

  useMock() {
    this.rows = null
    this.info = MOCK_INFO
    this.cursor = 0
  }

  useCsv(name: string, rows: CicidsRow[]) {
    this.rows = rows
    const labels: Record<string, number> = {}
    for (const r of rows) {
      const l = normaliseLabel(r['Label'])
      labels[l] = (labels[l] ?? 0) + 1
    }
    this.info = { name, rows: rows.length, origin: 'csv', labels }
    this.cursor = 0
  }

  get done() {
    return this.cursor >= this.info.rows
  }

  /** Jump to the start of the next labelled attack segment (mock only). */
  skipToNextAttack() {
    if (this.rows) return
    const next = MOCK_SEGMENTS.find((s) => s.from > this.cursor + 200)
    if (next) this.cursor = next.from - 120
  }

  tick(now: number, dtMs: number): Flow[] {
    if (!this.playing || this.done) return []
    const n = Math.round(DatasetReplayEngine.BASE_RATE * this.speed * (dtMs / 1000))
    const out: Flow[] = []
    for (let i = 0; i < n && !this.done; i++, this.cursor++) {
      const row = this.rows ? this.rows[this.cursor] : mockRow(this.cursor)
      if (!row['Source IP'] || !row['Destination IP']) continue
      out.push(rowToFlow(row, now - Math.random() * dtMs))
    }
    return out
  }
}

import type { AttackType } from './types'

export interface ScenarioMeta {
  id: AttackType
  name: string
  short: string
  tactic: string
  description: string
  behaviours: string[]
  source: string
  target: string
  /** what the detector is expected to key on */
  signature: string
  mitre?: string
}

export const SCENARIOS: Record<AttackType, ScenarioMeta> = {
  normal: {
    id: 'normal',
    name: 'Normal Traffic',
    short: 'Baseline',
    tactic: 'Baseline',
    description: 'Ordinary office traffic: DNS lookups, web browsing, file shares and database queries.',
    behaviours: ['Low, steady packet rates', 'Few ports per host', 'Mostly successful connections'],
    source: 'All hosts',
    target: 'All services',
    signature: 'Edges stay below the anomaly threshold',
  },
  portscan: {
    id: 'portscan',
    name: 'Port Scan',
    short: 'Port Scan',
    tactic: 'Reconnaissance',
    description: 'One host probes many services on a target to find open ports.',
    behaviours: ['Hundreds of destination ports', 'Very short, mostly rejected flows', 'One source, repeated connections'],
    source: '10.0.0.15',
    target: '10.0.0.24',
    signature: 'Port diversity on a single edge',
    mitre: 'T1046',
  },
  dos: {
    id: 'dos',
    name: 'DoS Simulation',
    short: 'DoS',
    tactic: 'Impact',
    description: 'A single host floods a web server with far more packets than it can serve.',
    behaviours: ['Extreme packet rate', 'Repeated flows to one destination', 'Abnormal flow frequency'],
    source: '10.0.0.15',
    target: '10.0.0.24',
    signature: 'Packet rate and flow frequency on one edge',
    mitre: 'T1498',
  },
  ddos: {
    id: 'ddos',
    name: 'DDoS Simulation',
    short: 'DDoS',
    tactic: 'Impact',
    description: 'Many sources — external bots and compromised IoT devices — flood one target together.',
    behaviours: ['Many high-rate sources', 'Converging on one destination', 'Inbound volume spike'],
    source: '8 sources',
    target: '10.0.0.24',
    signature: 'Many anomalous edges converging on one node',
    mitre: 'T1498',
  },
  bruteforce: {
    id: 'bruteforce',
    name: 'Brute Force',
    short: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Repeated SSH login attempts against the same service, most of them failing.',
    behaviours: ['Same service, again and again', 'High failure ratio', 'High connection frequency'],
    source: '10.0.0.15',
    target: '10.0.0.24',
    signature: 'Failed attempts and repetition on port 22',
    mitre: 'T1110',
  },
  c2: {
    id: 'c2',
    name: 'Suspicious Communication',
    short: 'C2 Beacon',
    tactic: 'Command & Control',
    description: 'A workstation beacons to an unknown external host on an unusual port and uploads data.',
    behaviours: ['Regular beacons', 'Unusual external port', 'Large outbound transfers'],
    source: '10.0.0.15',
    target: '198.51.100.66',
    signature: 'Rare external edge with periodic traffic',
    mitre: 'T1071',
  },
}

export const ATTACK_ORDER: AttackType[] = ['portscan', 'dos', 'ddos', 'bruteforce', 'c2', 'normal']

export const attackName = (a: AttackType) => SCENARIOS[a].name

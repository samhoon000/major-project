import type { Host, Protocol } from './types'

/** The protected network used by Simulation Mode: 24 internal hosts. */
export const SIM_HOSTS: Host[] = [
  { id: '10.0.0.1', ip: '10.0.0.1', role: 'Core Router', zone: 'core', label: 'core-rtr' },
  { id: '10.0.0.2', ip: '10.0.0.2', role: 'Firewall', zone: 'core', label: 'edge-fw' },

  { id: '10.0.0.24', ip: '10.0.0.24', role: 'Web Server', zone: 'dmz', label: 'web-01' },
  { id: '10.0.0.25', ip: '10.0.0.25', role: 'Mail Server', zone: 'dmz', label: 'mail-01' },

  { id: '10.0.0.10', ip: '10.0.0.10', role: 'DNS Server', zone: 'servers', label: 'dns-01' },
  { id: '10.0.0.11', ip: '10.0.0.11', role: 'Database', zone: 'servers', label: 'db-01' },
  { id: '10.0.0.12', ip: '10.0.0.12', role: 'File Server', zone: 'servers', label: 'fs-01' },
  { id: '10.0.0.13', ip: '10.0.0.13', role: 'Auth / SSH Server', zone: 'servers', label: 'auth-01' },

  ...['15', '16', '17', '18', '19', '20', '21', '22', '30', '31', '32', '33'].map(
    (n, i): Host => ({
      id: `10.0.0.${n}`,
      ip: `10.0.0.${n}`,
      role: 'Workstation',
      zone: 'office',
      label: `ws-${String(i + 1).padStart(2, '0')}`,
    }),
  ),

  { id: '10.0.0.40', ip: '10.0.0.40', role: 'IoT Device', zone: 'iot', label: 'cam-01' },
  { id: '10.0.0.41', ip: '10.0.0.41', role: 'IoT Device', zone: 'iot', label: 'hvac-01' },
  { id: '10.0.0.42', ip: '10.0.0.42', role: 'Printer', zone: 'iot', label: 'prn-01' },
  { id: '10.0.0.43', ip: '10.0.0.43', role: 'IoT Device', zone: 'iot', label: 'sensor-01' },
]

/**
 * External hosts that only appear when a scenario needs them.
 * Addresses come from the RFC 5737 documentation ranges, so they never refer to real machines.
 */
export const EXTERNAL_HOSTS: Host[] = [
  ...['203.0.113.11', '203.0.113.27', '203.0.113.45', '203.0.113.62', '198.51.100.14', '198.51.100.39'].map(
    (ip): Host => ({ id: ip, ip, role: 'External Host', zone: 'external', label: 'botnet', dynamic: true }),
  ),
  { id: '198.51.100.66', ip: '198.51.100.66', role: 'External Host', zone: 'external', label: 'unknown-c2', dynamic: true },
]

export const WORKSTATIONS = SIM_HOSTS.filter((h) => h.role === 'Workstation').map((h) => h.ip)
export const IOT = SIM_HOSTS.filter((h) => h.zone === 'iot').map((h) => h.ip)

export interface Service {
  port: number
  protocol: Protocol
  /** typical packets per flow */
  packets: [number, number]
  /** typical bytes per packet */
  size: [number, number]
  /** typical flow duration ms */
  duration: [number, number]
}

export const SERVICES: Record<string, Service> = {
  dns: { port: 53, protocol: 'UDP', packets: [2, 2], size: [70, 180], duration: [1, 40] },
  https: { port: 443, protocol: 'TCP', packets: [10, 60], size: [300, 1300], duration: [80, 4000] },
  http: { port: 80, protocol: 'TCP', packets: [6, 30], size: [200, 1200], duration: [50, 2000] },
  smb: { port: 445, protocol: 'TCP', packets: [12, 90], size: [400, 1400], duration: [200, 6000] },
  imap: { port: 993, protocol: 'TCP', packets: [8, 40], size: [200, 1200], duration: [100, 3000] },
  ldap: { port: 389, protocol: 'TCP', packets: [4, 12], size: [100, 500], duration: [10, 300] },
  kerberos: { port: 88, protocol: 'TCP', packets: [4, 8], size: [200, 900], duration: [5, 120] },
  postgres: { port: 5432, protocol: 'TCP', packets: [6, 30], size: [120, 900], duration: [5, 400] },
  ntp: { port: 123, protocol: 'UDP', packets: [2, 2], size: [76, 90], duration: [1, 30] },
  mqtt: { port: 8883, protocol: 'TCP', packets: [4, 14], size: [80, 400], duration: [50, 1500] },
  print: { port: 9100, protocol: 'TCP', packets: [20, 140], size: [800, 1400], duration: [500, 8000] },
  ssh: { port: 22, protocol: 'TCP', packets: [20, 200], size: [80, 600], duration: [2000, 30000] },
  icmp: { port: 0, protocol: 'ICMP', packets: [2, 2], size: [64, 98], duration: [1, 10] },
  syslog: { port: 514, protocol: 'UDP', packets: [1, 3], size: [120, 400], duration: [1, 20] },
}

/** Weighted list of "who normally talks to whom". */
export interface Pattern {
  src: string | string[]
  dst: string | string[]
  service: keyof typeof SERVICES
  weight: number
}

export const NORMAL_PATTERNS: Pattern[] = [
  { src: WORKSTATIONS, dst: '10.0.0.10', service: 'dns', weight: 16 },
  { src: WORKSTATIONS, dst: '10.0.0.24', service: 'https', weight: 12 },
  { src: WORKSTATIONS, dst: '10.0.0.1', service: 'https', weight: 12 },
  { src: WORKSTATIONS, dst: '10.0.0.12', service: 'smb', weight: 7 },
  { src: WORKSTATIONS, dst: '10.0.0.25', service: 'imap', weight: 6 },
  { src: WORKSTATIONS, dst: '10.0.0.13', service: 'kerberos', weight: 5 },
  { src: WORKSTATIONS, dst: '10.0.0.13', service: 'ldap', weight: 3 },
  { src: WORKSTATIONS, dst: '10.0.0.42', service: 'print', weight: 1.5 },
  { src: '10.0.0.16', dst: '10.0.0.13', service: 'ssh', weight: 1 },
  { src: '10.0.0.2', dst: '10.0.0.24', service: 'https', weight: 10 },
  { src: '10.0.0.2', dst: '10.0.0.25', service: 'imap', weight: 3 },
  { src: '10.0.0.24', dst: '10.0.0.11', service: 'postgres', weight: 8 },
  { src: '10.0.0.24', dst: '10.0.0.10', service: 'dns', weight: 2 },
  { src: '10.0.0.1', dst: '10.0.0.2', service: 'https', weight: 6 },
  { src: '10.0.0.1', dst: '10.0.0.10', service: 'dns', weight: 2 },
  { src: IOT, dst: '10.0.0.1', service: 'mqtt', weight: 4 },
  { src: IOT, dst: '10.0.0.1', service: 'ntp', weight: 1.5 },
  { src: ['10.0.0.24', '10.0.0.11', '10.0.0.12', '10.0.0.13'], dst: '10.0.0.12', service: 'syslog', weight: 2 },
  { src: '10.0.0.1', dst: ['10.0.0.24', '10.0.0.11', '10.0.0.12', '10.0.0.13', '10.0.0.10'], service: 'icmp', weight: 1.5 },
  { src: '10.0.0.12', dst: '10.0.0.11', service: 'postgres', weight: 1 },
]

export const INTERNAL_PREFIX = '10.0.0.'
export const isInternal = (ip: string) => ip.startsWith(INTERNAL_PREFIX) || ip.startsWith('192.168.')

import type { HostStatus, Severity, ThreatLevel } from '../engine/types'

export const fmtInt = (n: number) => Math.round(n).toLocaleString('en-US')
export const fmtPct = (p: number, d = 1) => `${(p * 100).toFixed(d)}%`
export const fmtTime = (ts: number) =>
  new Date(ts).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })

export function fmtCompact(n: number) {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
  if (n >= 1e4) return `${(n / 1e3).toFixed(1)}k`
  return fmtInt(n)
}

export function fmtBytes(b: number) {
  if (b >= 1e9) return `${(b / 1e9).toFixed(2)} GB`
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`
  return `${Math.round(b)} B`
}

export function fmtDuration(ms: number) {
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`
  if (ms < 1000) return `${ms.toFixed(ms < 10 ? 1 : 0)} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

/** semantic colours (CSS variables) */
export const C = {
  ai: 'var(--color-ai)',
  ok: 'var(--color-ok)',
  warn: 'var(--color-warn)',
  threat: 'var(--color-threat)',
  ink: 'var(--color-ink)',
  ink2: 'var(--color-ink-2)',
  ink3: 'var(--color-ink-3)',
}
export const HEX = { ai: '#56d9e6', ok: '#3fcf98', warn: '#f0b03f', threat: '#ff4f5e', ink2: '#9ba7ae', ink3: '#66727a' }

export function riskColor(p: number, threshold = 0.65) {
  if (p >= threshold) return HEX.threat
  if (p >= 0.4) return HEX.warn
  return HEX.ok
}

export function levelColor(l: ThreatLevel) {
  return l === 'CRITICAL' || l === 'HIGH' ? HEX.threat : l === 'ELEVATED' || l === 'GUARDED' ? HEX.warn : HEX.ok
}

export function statusColor(s: HostStatus) {
  return s === 'HEALTHY' ? HEX.ok : s === 'ELEVATED' ? HEX.warn : HEX.threat
}

export function severityColor(s: Severity) {
  return s === 'CRITICAL' ? HEX.threat : s === 'WARNING' ? HEX.warn : HEX.ai
}

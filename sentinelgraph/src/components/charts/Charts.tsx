import { useMemo } from 'react'
import {
  Area, AreaChart, CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import type { Protocol } from '../../engine/types'
import { HEX, fmtCompact, fmtPct, fmtTime, riskColor, statusColor } from '../../lib/format'
import { select, focusOn } from '../../store/runtime'
import { useSentinel } from '../../store/store'
import { Meter } from '../ui'

const tickTime = (t: number) => {
  const d = new Date(t)
  return `${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

interface TipEntry {
  dataKey?: unknown
  name?: unknown
  value?: unknown
  color?: string
}

function ChartTip({ active, payload, label, fmt }: { active?: boolean; payload?: readonly TipEntry[]; label?: unknown; fmt: (k: string, v: number) => string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-md border border-line-2 bg-s2/95 px-2.5 py-1.5 text-[11px] shadow-xl backdrop-blur">
      <div className="mono mb-1 text-ink-3">{fmtTime(Number(label))}</div>
      {payload.map((p) => (
        <div key={String(p.dataKey)} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 text-ink-2">
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: p.color }} />
            {String(p.name)}
          </span>
          <span className="mono text-ink">{fmt(String(p.dataKey), Number(p.value))}</span>
        </div>
      ))}
    </div>
  )
}

const axisProps = {
  tickLine: false,
  axisLine: false,
  tick: { fontSize: 9.5 },
} as const

/** Live anomaly score (max edge anomaly) with threshold and detection annotations. */
export function AnomalyChart({ height = 190 }: { height?: number }) {
  const metrics = useSentinel((s) => s.metrics)
  const markers = useSentinel((s) => s.markers)
  const thr = useSentinel((s) => s.threshold)
  const t0 = metrics[0]?.t ?? 0
  const visible = markers.filter((m) => m.t >= t0)
  const off = `${(1 - thr) * 100}%`

  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={metrics} margin={{ top: 18, right: 12, bottom: 0, left: -18 }}>
          <defs>
            <linearGradient id="anom-stroke" x1="0" y1="0" x2="0" y2="1">
              <stop offset={off} stopColor={HEX.threat} />
              <stop offset={off} stopColor={HEX.ai} />
            </linearGradient>
            <linearGradient id="anom-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={HEX.threat} stopOpacity={0.35} />
              <stop offset={off} stopColor={HEX.threat} stopOpacity={0.12} />
              <stop offset={off} stopColor={HEX.ai} stopOpacity={0.12} />
              <stop offset="100%" stopColor={HEX.ai} stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid vertical={false} />
          <XAxis dataKey="t" type="number" domain={['dataMin', 'dataMax']} tickFormatter={tickTime} minTickGap={48} {...axisProps} />
          <YAxis domain={[0, 1]} ticks={[0, 0.5, 1]} tickFormatter={(v) => v.toFixed(1)} {...axisProps} />
          <Tooltip
            content={(p) => <ChartTip active={p.active} payload={p.payload as readonly TipEntry[]} label={p.label} fmt={(_, v) => fmtPct(v)} />}
            cursor={{ stroke: 'rgba(255,255,255,0.18)', strokeWidth: 1 }}
          />
          <ReferenceLine
            y={thr}
            stroke={HEX.threat}
            strokeOpacity={0.55}
            strokeDasharray="3 4"
            label={{ value: `threshold ${thr.toFixed(2)}`, position: 'insideTopLeft', fill: HEX.threat, fontSize: 9.5, dy: -12, dx: 2 }}
          />
          {visible.map((m) => (
            <ReferenceLine
              key={m.t}
              x={m.t}
              stroke={m.kind === 'detect' ? HEX.threat : HEX.ok}
              strokeOpacity={0.8}
              label={{ value: m.label, position: 'insideTopRight', fill: m.kind === 'detect' ? '#ffb3ba' : HEX.ok, fontSize: 9.5, dy: -14 }}
            />
          ))}
          <Area
            type="monotone"
            dataKey="anomaly"
            name="Max edge anomaly"
            stroke="url(#anom-stroke)"
            strokeWidth={2}
            fill="url(#anom-fill)"
            isAnimationActive={false}
            dot={false}
            activeDot={{ r: 4, stroke: '#0b0f12', strokeWidth: 2, fill: HEX.ai }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

export function TrafficVolumeChart({ height = 150 }: { height?: number }) {
  const metrics = useSentinel((s) => s.metrics)
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={metrics} margin={{ top: 6, right: 8, bottom: 0, left: -14 }}>
          <CartesianGrid vertical={false} />
          <XAxis dataKey="t" type="number" domain={['dataMin', 'dataMax']} tickFormatter={tickTime} minTickGap={48} {...axisProps} />
          <YAxis tickFormatter={(v) => fmtCompact(v)} width={44} {...axisProps} />
          <Tooltip content={(p) => <ChartTip active={p.active} payload={p.payload as readonly TipEntry[]} label={p.label} fmt={(_, v) => `${v.toFixed(0)} flows/s`} />} cursor={{ stroke: 'rgba(255,255,255,0.18)' }} />
          <Line type="monotone" dataKey="flows" name="Flows/s" stroke={HEX.ai} strokeWidth={2} dot={false} isAnimationActive={false} activeDot={{ r: 4, stroke: '#0b0f12', strokeWidth: 2 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

export function NormalVsAnomalousChart({ height = 150 }: { height?: number }) {
  const metrics = useSentinel((s) => s.metrics)
  return (
    <div>
      <div className="mb-1 flex gap-4 text-[10.5px] text-ink-3">
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: HEX.ok }} />Normal</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: HEX.threat }} />Anomalous</span>
      </div>
      <div style={{ height }} className="w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={metrics} margin={{ top: 4, right: 8, bottom: 0, left: -14 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="t" type="number" domain={['dataMin', 'dataMax']} tickFormatter={tickTime} minTickGap={48} {...axisProps} />
            <YAxis tickFormatter={(v) => fmtCompact(v)} width={44} {...axisProps} />
            <Tooltip content={(p) => <ChartTip active={p.active} payload={p.payload as readonly TipEntry[]} label={p.label} fmt={(_, v) => `${v.toFixed(0)} flows/s`} />} cursor={{ stroke: 'rgba(255,255,255,0.18)' }} />
            <Area type="monotone" dataKey="normal" name="Normal" stackId="1" stroke={HEX.ok} strokeWidth={1.5} fill={HEX.ok} fillOpacity={0.14} isAnimationActive={false} />
            <Area type="monotone" dataKey="anomalous" name="Anomalous" stackId="1" stroke={HEX.threat} strokeWidth={1.5} fill={HEX.threat} fillOpacity={0.3} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

export function ProtocolBars() {
  const p = useSentinel((s) => s.protocols)
  const total = Object.values(p).reduce((a, b) => a + b, 0) || 1
  const rows: Protocol[] = ['TCP', 'UDP', 'ICMP', 'OTHER']
  return (
    <div className="space-y-2.5">
      {rows.map((k) => (
        <div key={k} className="grid grid-cols-[48px_1fr_48px] items-center gap-3">
          <span className="mono text-[11px] text-ink-2">{k === 'OTHER' ? 'Other' : k}</span>
          <Meter value={p[k] / total} color={HEX.ai} height={6} />
          <span className="mono text-right text-[11px] text-ink">{fmtPct(p[k] / total, 0)}</span>
        </div>
      ))}
    </div>
  )
}

export function TopHosts({ limit = 6 }: { limit?: number }) {
  const nodes = useSentinel((s) => s.graph.nodes)
  const thr = useSentinel((s) => s.threshold)
    // rank on rounded risk with a stable tie-break so low-risk noise doesn't reshuffle the list
  const top = useMemo(
    () => [...nodes].sort((a, b) => Math.round(b.risk * 50) - Math.round(a.risk * 50) || a.ip.localeCompare(b.ip)).slice(0, limit),
    [nodes, limit],
  )
  return (
    <ol className="space-y-1">
      {top.map((n, i) => (
        <li key={n.id}>
          <button
            onClick={() => {
              select({ kind: 'node', id: n.id })
              focusOn([n.id])
            }}
            className="btn-press grid w-full grid-cols-[16px_1fr_auto] items-center gap-2.5 rounded-md px-1.5 py-1.5 text-left hover:bg-white/[0.04]"
          >
            <span className="mono text-[10px] text-ink-4">{i + 1}</span>
            <span className="min-w-0">
              <span className="flex items-baseline justify-between gap-2">
                <span className="mono truncate text-[11.5px] text-ink">{n.ip}</span>
                <span className="truncate text-[10px] text-ink-3">{n.role}</span>
              </span>
              <span className="mt-1 block"><Meter value={n.risk} color={riskColor(n.risk, thr)} height={3} /></span>
            </span>
            <span className="mono w-10 text-right text-[11px]" style={{ color: n.risk >= 0.35 ? statusColor(n.status) : HEX.ink3 }}>
              {fmtPct(n.risk, 0)}
            </span>
          </button>
        </li>
      ))}
    </ol>
  )
}

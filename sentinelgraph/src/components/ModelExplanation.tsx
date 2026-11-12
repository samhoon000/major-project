import { motion, useAnimationControls } from 'framer-motion'
import { useEffect, useMemo, useRef } from 'react'
import { confidenceFor } from '../engine/detectionEngine'
import { SCENARIOS } from '../engine/scenarios'
import type { EdgeState, Signal } from '../engine/types'
import { HEX, fmtCompact, fmtPct, riskColor } from '../lib/format'
import { useSentinel } from '../store/store'
import { AnimatedNumber, Meter, Tag, cx } from './ui'

function useExplainedEdge(): EdgeState | null {
  return useSentinel((s) => {
    const ids = [
      s.selection?.kind === 'edge' ? s.selection.id : null,
      s.incidents.find((i) => i.id === s.alertIncidentId)?.edgeId ?? null,
      s.topEdgeId,
      s.summary?.edgeId ?? null,
    ]
    for (const id of ids) {
      if (!id) continue
      const e = s.graph.edges.find((x) => x.id === id)
      if (e) return e
    }
    return null
  })
}

function sentence(e: EdgeState, attnShare: number): string {
  const top = e.signals[0]?.key
  const who = `${e.source} → ${e.target}`
  const attn = `${Math.round(attnShare * 100)}% of ${e.target}'s attention`
  switch (top) {
    case 'portDiversity':
      return `${who} touched ${e.ports.length >= 64 ? '64+' : e.ports.length} different ports in seconds — classic probing. The attention layer put ${attn} on this edge.`
    case 'packetRate':
      return `${who} is pushing ${fmtCompact(e.pps)} packets/s, far above this host's normal neighbours. The attention layer put ${attn} on this edge.`
    case 'failedAttempts':
    case 'flowFrequency':
      return `${who} keeps opening short connections to the same service and most of them fail. The attention layer put ${attn} on this edge.`
    case 'sourceFanIn':
      return `Many high-rate sources are converging on ${e.target} at once. Together, flagged edges hold ${attn}.`
    case 'externalBeacon':
      return `${e.source} talks to an unknown external host on an unusual port with machine-like regularity. The attention layer put ${attn} on this edge.`
    default:
      return `${who} looks unlike its neighbourhood. The attention layer put ${attn} on this edge.`
  }
}

export function ModelExplanation({ variant = 'panel' }: { variant?: 'panel' | 'full' }) {
  const e = useExplainedEdge()
  const edges = useSentinel((s) => s.graph.edges)
  const threshold = useSentinel((s) => s.threshold)
  const pulse = useSentinel((s) => s.explainPulse)
  const engineMode = useSentinel((s) => s.engineMode)
  const ref = useRef<HTMLDivElement>(null)
  const controls = useAnimationControls()

  useEffect(() => {
    if (!pulse) return
    ref.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    void controls.start({
      boxShadow: ['0 0 0 1px rgba(86,217,230,0)', '0 0 0 1px rgba(86,217,230,0.7), 0 0 40px -6px rgba(86,217,230,0.35)', '0 0 0 1px rgba(86,217,230,0)'],
      transition: { duration: 1.8 },
    })
  }, [pulse, controls])

  const incoming = useMemo(() => {
    if (!e) return []
    return edges
      .filter((x) => x.target === e.target)
      .sort((a, b) => (b.id === e.id ? 1 : 0) - (a.id === e.id ? 1 : 0) || b.attention - a.attention)
      .slice(0, 7)
  }, [edges, e])

  const flaggedShare = useMemo(() => {
    if (!e) return 0
    const all = edges.filter((x) => x.target === e.target)
    const total = all.reduce((s, x) => s + x.attention, 0) || 1
    const flagged = all.filter((x) => x.anomaly >= threshold).reduce((s, x) => s + x.attention, 0)
    return e.anomaly >= threshold ? flagged / total : e.attention / total
  }, [edges, e, threshold])

  const flagged = !!e && e.anomaly >= threshold
  const color = e ? riskColor(e.anomaly, threshold) : HEX.ok
  const conf = e ? confidenceFor(e.anomaly, threshold) : 0

  return (
    <motion.div ref={ref} animate={controls} className="@container flex h-full flex-col rounded-[inherit]">
      <div className="flex items-start justify-between gap-2 px-4 pt-3.5">
        <div>
          <div className="eyebrow text-ink-2">Why did SentinelGraph flag this?</div>
          <div className="mt-0.5 text-[11px] text-ink-3">GAT attention over the target's neighbourhood</div>
        </div>
        {e && <Tag color={color}>{e.classification}</Tag>}
      </div>

      {!e ? (
        <div className="flex flex-1 flex-col items-center justify-center px-6 py-6 text-center">
          <AttentionIdle />
          <div className="mt-3 text-[12px] text-ink-2">Awaiting anomalous activity</div>
          <div className="mt-1 max-w-[260px] text-[11px] leading-snug text-ink-3">
            When an edge stands out, its attention weight, anomaly probability and the signals behind them appear here.
          </div>
        </div>
      ) : (
        <div className={cx('grid flex-1 gap-4 px-4 pt-2 pb-4', variant === 'full' ? '@[620px]:grid-cols-[1.1fr_1fr]' : '@[460px]:grid-cols-[1.05fr_1fr]')}>
          <div className="min-w-0">
            <AttentionMini e={e} incoming={incoming} threshold={threshold} />
            <div className="mt-3 flex items-end justify-between gap-3">
              <div>
                <div className="eyebrow">Anomaly probability</div>
                <AnimatedNumber
                  value={e.anomaly * 100}
                  format={(n) => `${n.toFixed(1)}%`}
                  className="mono mt-0.5 block text-[30px] leading-none font-medium"
                />
              </div>
              <div className="text-right">
                <div className="eyebrow">Confidence</div>
                <div className="mono mt-1 text-[14px] text-ink">{fmtPct(conf)}</div>
              </div>
            </div>
            <ThresholdBar value={e.anomaly} threshold={threshold} color={color} />
          </div>

          <div className="min-w-0">
            <div className="flex items-center justify-between">
              <div className="eyebrow">Contributing signals</div>
              {flagged && e.attackClass !== 'normal' && <span className="mono text-[10px] text-ink-3">pattern: {SCENARIOS[e.attackClass].short}</span>}
            </div>
            <Signals key={pulse + e.id} signals={e.signals} color={e.anomaly >= 0.4 ? color : '#56636b'} />
            <p className="mt-3 text-[11.5px] leading-relaxed text-ink-2">
              {flagged || e.anomaly >= 0.4 ? sentence(e, flaggedShare) : `Edge behaviour matches its neighbourhood; attention is spread evenly and the score stays below ${threshold.toFixed(2)}.`}
            </p>
            <div className="mt-2 text-[10px] leading-snug text-ink-4">
              {engineMode === 'simulation'
                ? 'Simulation Mode: scores and attention are simulated in-browser to illustrate GATv2 behaviour.'
                : 'Model Mode: probability and attention come from the GATv2 service.'}
            </div>
          </div>
        </div>
      )}
    </motion.div>
  )
}

function Signals({ signals, color }: { signals: Signal[]; color: string }) {
  return (
    <div className="mt-2 space-y-2.5">
      {signals.slice(0, 4).map((s, i) => (
        <div key={s.key}>
          <div className="mb-1 flex items-baseline justify-between text-[11.5px]">
            <span className="text-ink-2">{s.label}</span>
            <span className="mono text-ink">{fmtPct(s.value, 0)}</span>
          </div>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.08 }}>
            <Meter value={s.value} color={s.value >= 0.5 ? color : '#56636b'} height={5} delay={0.1 + i * 0.08} />
          </motion.div>
        </div>
      ))}
    </div>
  )
}

function ThresholdBar({ value, threshold, color }: { value: number; threshold: number; color: string }) {
  return (
    <div className="mt-3">
      <div className="relative h-[5px] rounded-full bg-white/[0.05]">
        <div className="absolute inset-y-0 rounded-r-full bg-threat/10" style={{ left: `${threshold * 100}%`, right: 0 }} />
        <motion.div
          className="absolute top-1/2 h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 bg-env"
          style={{ borderColor: color, boxShadow: `0 0 10px ${color}` }}
          initial={false}
          animate={{ left: `${value * 100}%` }}
          transition={{ duration: 0.6 }}
        />
        <div className="absolute -top-1 h-[13px] w-px bg-ink-2" style={{ left: `${threshold * 100}%` }} />
      </div>
      <div className="mono relative mt-1.5 h-3 text-[9.5px] text-ink-3">
        <span className="absolute left-0">0.00</span>
        <span className="absolute -translate-x-1/2 text-ink-2" style={{ left: `${threshold * 100}%` }}>threshold {threshold.toFixed(2)}</span>
        <span className="absolute right-0">1.00</span>
      </div>
    </div>
  )
}

/** Miniature graph: the target node, its incoming neighbours, edge width = attention. */
function AttentionMini({ e, incoming, threshold }: { e: EdgeState; incoming: EdgeState[]; threshold: number }) {
  const W = 320
  const H = 150
  const tx = W - 56
  const ty = H / 2
  const n = incoming.length
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 170 }} aria-label="Attention over incoming edges">
      <defs>
        <filter id="mini-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2.5" />
        </filter>
      </defs>
      {incoming.map((x, i) => {
        const isMain = x.id === e.id
        const sy = n === 1 ? ty : 18 + (i * (H - 36)) / Math.max(1, n - 1)
        const sx = isMain ? 92 : 112 + Math.abs(i - (n - 1) / 2) * 6
        const c = riskColor(x.anomaly, threshold)
        const w = 0.8 + x.attention * 7
        const d = `M${sx + 7} ${sy} C ${(sx + tx) / 2} ${sy}, ${(sx + tx) / 2} ${ty}, ${tx - 13} ${ty}`
        return (
          <g key={x.id} opacity={isMain ? 1 : 0.55}>
            {isMain && x.anomaly >= threshold && <path d={d} stroke={c} strokeWidth={w + 6} fill="none" opacity={0.25} filter="url(#mini-glow)" />}
            <motion.path
              d={d}
              stroke={isMain ? c : '#5e6b72'}
              fill="none"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 1, strokeWidth: w }}
              transition={{ duration: 0.8, delay: i * 0.05 }}
            />
            {isMain && (
              <path d={d} stroke="#fff" strokeOpacity={0.8} strokeWidth={2} strokeDasharray="0.1 10" strokeLinecap="round" fill="none" className="edge-flow" style={{ animationDuration: '0.7s' }} />
            )}
            <circle cx={sx} cy={sy} r={isMain ? 7 : 4.5} fill="#11171b" stroke={isMain ? c : '#5e6b72'} strokeWidth={1.4} />
            <text x={sx - (isMain ? 11 : 8)} y={sy + 3.5} textAnchor="end" fontSize={isMain ? 10 : 8.5} className="mono" fill={isMain ? '#e6ebed' : '#66727a'}>
              {isMain ? x.source : `.${x.source.split('.').pop()}`}
            </text>
            <text
              x={(sx + tx) / 2 + (isMain ? 0 : 18)}
              y={isMain ? (sy + ty) / 2 - 9 : (sy + ty) / 2 - 3}
              textAnchor="middle"
              fontSize={isMain ? 10.5 : 8}
              className="mono"
              fill={isMain ? HEX.ai : '#56636b'}
            >
              {isMain ? `α ${x.attention.toFixed(2)}` : x.attention.toFixed(2)}
            </text>
          </g>
        )
      })}
      <circle cx={tx} cy={ty} r={20} fill={riskColor(e.anomaly, threshold)} opacity={0.12} filter="url(#mini-glow)" />
      <circle cx={tx} cy={ty} r={11} fill="#11171b" stroke={riskColor(e.anomaly, threshold)} strokeWidth={1.8} />
      <circle cx={tx} cy={ty} r={3} fill={riskColor(e.anomaly, threshold)} />
      <text x={tx} y={ty + 27} textAnchor="middle" fontSize={10} className="mono" fill="#e6ebed">{e.target}</text>
      <text x={tx} y={ty - 19} textAnchor="middle" fontSize={8} letterSpacing="0.18em" fill="#66727a">TARGET</text>
    </svg>
  )
}

function AttentionIdle() {
  return (
    <svg width="120" height="64" viewBox="0 0 120 64" aria-hidden>
      {[10, 26, 42, 58].map((y, i) => (
        <g key={y} className="breathe" style={{ animationDelay: `${i * 0.4}s` }}>
          <path d={`M14 ${y - 4} C 50 ${y - 4}, 60 32, 96 32`} stroke="#3a454c" fill="none" strokeWidth={1.2} />
          <circle cx={10} cy={y - 4} r={3.5} fill="#11171b" stroke="#3fcf98" strokeOpacity={0.6} />
        </g>
      ))}
      <circle cx={102} cy={32} r={7} fill="#11171b" stroke="#3fcf98" strokeOpacity={0.7} />
    </svg>
  )
}

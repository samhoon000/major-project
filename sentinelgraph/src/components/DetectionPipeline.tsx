import { motion } from 'framer-motion'
import { confidenceFor } from '../engine/detectionEngine'
import { HEX, fmtCompact, fmtPct, riskColor } from '../lib/format'
import { useSentinel } from '../store/store'
import { AnimatedNumber, Tag, cx } from './ui'

function usePipelineStats() {
  const nodes = useSentinel((s) => s.graph.nodes.length)
  const edges = useSentinel((s) => s.graph.edges.length)
  const inf = useSentinel((s) => s.inference)
  const thr = useSentinel((s) => s.threshold)
  const top = useSentinel((s) => s.graph.edges.find((e) => e.id === s.topEdgeId))
  const engineMode = useSentinel((s) => s.engineMode)
  const modelStatus = useSentinel((s) => s.modelStatus)
  const p = top?.anomaly ?? useSentinel.getState().metrics.at(-1)?.meanAnomaly ?? 0
  const cls = p >= thr ? 'ANOMALOUS' : p >= 0.4 ? 'SUSPICIOUS' : 'NORMAL'
  return { nodes, edges, inf, thr, p, cls, conf: confidenceFor(p, thr), engineMode, modelStatus }
}

export function DetectionPipeline({ variant = 'compact' }: { variant?: 'compact' | 'full' }) {
  const { nodes, edges, inf, thr, p, cls, conf, engineMode, modelStatus } = usePipelineStats()
  const color = riskColor(p, thr)
  const hot = p >= thr

  const stages = [
    { k: 'Network flows', v: `${fmtCompact(inf.flowsPerSec)} /s` },
    { k: 'Graph construction', v: `${nodes} nodes · ${edges} edges` },
    { k: 'Node + edge features', v: '5 flow · 8 graph' },
    { k: 'GATv2', v: '2 layers · 4 heads' },
    { k: 'Anomaly score', v: p.toFixed(3) },
    { k: 'Classification', v: cls },
  ]

  return (
    <div className={cx('flex h-full flex-col', variant === 'full' ? 'gap-5' : '')}>
      <div className="flex items-start justify-between px-4 pt-3.5">
        <div>
          <div className="eyebrow text-ink-2">Detection engine</div>
          <div className="mt-0.5 text-[11px] text-ink-3">
            {engineMode === 'simulation' ? 'Simulated in browser' : modelStatus === 'online' ? 'GATv2 service · live' : 'GATv2 service unreachable · simulating'}
          </div>
        </div>
        <span className="mono flex items-center gap-1.5 text-[10px] tracking-[0.14em]" style={{ color: inf.active ? HEX.ok : HEX.ink3 }}>
          <span className={cx('h-1.5 w-1.5 rounded-full', inf.active && 'animate-blink')} style={{ background: inf.active ? HEX.ok : HEX.ink3 }} />
          {inf.active ? 'INFERENCE ACTIVE' : 'IDLE'}
        </span>
      </div>

      <div className={cx('flex-1 gap-4 px-4 pt-3 pb-4', variant === 'full' ? 'grid lg:grid-cols-[1fr_1fr]' : 'flex flex-col')}>
        {/* pipeline */}
        <div className="relative">
          <div className="absolute top-2 bottom-2 left-[5px] w-px bg-line-2" />
          <motion.div
            className="absolute left-[3px] h-[5px] w-[5px] rounded-full"
            style={{ background: hot ? HEX.threat : HEX.ai, boxShadow: `0 0 10px ${hot ? HEX.threat : HEX.ai}` }}
            animate={{ top: ['2%', '96%'] }}
            transition={{ duration: hot ? 0.9 : 1.8, repeat: Infinity, ease: 'linear' }}
          />
          <ol className={cx('relative', variant === 'full' ? 'space-y-3' : 'space-y-[7px]')}>
            {stages.map((s, i) => {
              const last = i === stages.length - 1
              const lit = inf.active && (inf.stage === i || (hot && i >= 4))
              const c = i >= 4 ? color : HEX.ai
              return (
                <li key={s.k} className="flex items-center gap-3 pl-0">
                  <span
                    className="relative z-10 h-[11px] w-[11px] shrink-0 rounded-full border-2 bg-s1 transition-colors duration-300"
                    style={{ borderColor: lit ? c : 'rgba(255,255,255,0.18)', boxShadow: lit ? `0 0 10px ${c}` : 'none' }}
                  />
                  <div className="flex min-w-0 flex-1 items-baseline justify-between gap-2">
                    <span className={cx('truncate text-[10.5px] font-semibold tracking-[0.12em] uppercase transition-colors', lit ? 'text-ink' : 'text-ink-3')}>
                      {s.k}
                    </span>
                    <span className="mono shrink-0 text-[10.5px]" style={{ color: last || i === 4 ? color : HEX.ink3 }}>
                      {s.v}
                    </span>
                  </div>
                </li>
              )
            })}
          </ol>
        </div>

        {variant === 'compact' && (
          <div className="mt-auto grid grid-cols-2 gap-x-4 gap-y-3 border-t border-line pt-3">
            <Stat k="Model" v="GATv2" small />
            <Stat k="Threshold" v={thr.toFixed(2)} small />
            <Stat k="Confidence" v={fmtPct(conf)} small color={HEX.ink2} />
            <Stat k="Batch latency" v={`${inf.latencyMs.toFixed(1)} ms`} small color={HEX.ink2} />
          </div>
        )}
        {variant === 'full' && (
          <div className="grid grid-cols-2 gap-x-6 gap-y-4 self-start">
            <Stat k="Model" v="GATv2" />
            <Stat k="Task" v="Flow classification" small />
            <Stat k="Current inference" v={inf.active ? 'ACTIVE' : 'IDLE'} color={inf.active ? HEX.ok : HEX.ink3} />
            <Stat k="Threshold" v={thr.toFixed(2)} />
            <div>
              <div className="eyebrow">Anomaly probability</div>
              <AnimatedNumber value={p * 100} format={(n) => `${n.toFixed(1)}%`} className="mono mt-1 block text-[22px]" />
            </div>
            <div>
              <div className="eyebrow">Classification</div>
              <div className="mt-1.5"><Tag color={color}>{cls}</Tag></div>
            </div>
            <Stat k="Confidence" v={fmtPct(conf)} />
            <Stat k="Batch latency" v={`${inf.latencyMs.toFixed(1)} ms`} />
          </div>
        )}
      </div>
    </div>
  )
}

function Stat({ k, v, color, small }: { k: string; v: string; color?: string; small?: boolean }) {
  return (
    <div>
      <div className="eyebrow">{k}</div>
      <div className={cx('mono mt-1', small ? 'text-[13px]' : 'text-[18px]')} style={{ color: color ?? HEX.ai }}>
        {v}
      </div>
    </div>
  )
}

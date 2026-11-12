import { AnimatePresence, motion } from 'framer-motion'
import { SCENARIOS } from '../engine/scenarios'
import type { EdgeState, NodeState } from '../engine/types'
import { HEX, fmtBytes, fmtCompact, fmtDuration, fmtInt, fmtPct, riskColor, statusColor } from '../lib/format'
import { focusOn, investigate, select } from '../store/runtime'
import { useSentinel } from '../store/store'
import { AnimatedNumber, KV, Meter, StatusDot, Tag } from './ui'

export function Inspector() {
  const selection = useSentinel((s) => s.selection)
  const node = useSentinel((s) => (s.selection?.kind === 'node' ? s.graph.nodes.find((n) => n.id === s.selection!.id) : undefined))
  const edge = useSentinel((s) => (s.selection?.kind === 'edge' ? s.graph.edges.find((e) => e.id === s.selection!.id) : undefined))
  const open = !!selection && (!!node || !!edge)

  return (
    <AnimatePresence>
      {open && (
        <motion.aside
          key="inspector"
          initial={{ x: 40, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 40, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 380, damping: 36 }}
          className="absolute top-3 right-3 bottom-14 z-20 flex w-[300px] flex-col overflow-hidden rounded-xl border border-line-2 bg-s1/92 shadow-[0_20px_60px_-10px_rgba(0,0,0,0.8)] backdrop-blur-md"
          aria-label="Inspector"
        >
          <div className="flex items-center justify-between px-4 pt-3.5">
            <span className="eyebrow">{node ? 'Host' : 'Flow relationship'}</span>
            <button
              onClick={() => select(null)}
              className="btn-press grid h-6 w-6 place-items-center rounded-md text-ink-3 hover:bg-white/5 hover:text-ink"
              aria-label="Close inspector"
            >
              <svg width="10" height="10" viewBox="0 0 10 10"><path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" strokeWidth="1.4" /></svg>
            </button>
          </div>
          <div className="scroll-thin flex-1 overflow-y-auto px-4 pb-4">
            {node && <NodePanel n={node} />}
            {edge && <EdgePanel e={edge} />}
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  )
}

function NodePanel({ n }: { n: NodeState }) {
  const threshold = useSentinel((s) => s.threshold)
  const edges = useSentinel((s) => s.graph.edges)
  const color = statusColor(n.status)
  const mine = edges
    .filter((e) => e.source === n.id || e.target === n.id)
    .sort((a, b) => b.anomaly - a.anomaly)
    .slice(0, 6)

  return (
    <div>
      <div className="mono mt-1 text-[22px] font-medium tracking-tight text-ink">{n.ip}</div>
      <div className="text-[12px] text-ink-3">
        {n.role}
        {n.label ? <span className="text-ink-4"> · {n.label}</span> : null}
      </div>

      <div className="mt-4 flex items-center justify-between">
        <div>
          <div className="eyebrow">Status</div>
          <div className="mt-1 flex items-center gap-2 text-[13px] font-semibold tracking-wide" style={{ color }}>
            <StatusDot color={color} pulse={n.risk >= threshold} /> {n.status}
          </div>
        </div>
        <div className="text-right">
          <div className="eyebrow">Risk score</div>
          <AnimatedNumber value={n.risk * 100} format={(v) => `${v.toFixed(0)}%`} className="mono text-[22px] font-medium" />
        </div>
      </div>
      <div className="mt-2">
        <Meter value={n.risk} color={riskColor(n.risk, threshold)} />
      </div>

      <div className="mt-4 divide-y divide-line border-y border-line">
        <KV k="Connections" v={n.connections} />
        <KV k="Packets" v={fmtInt(n.packets)} />
        <KV k="Outbound rate" v={`${fmtCompact(n.outRate)} pkt/s`} />
        <KV k="Inbound rate" v={`${fmtCompact(n.inRate)} pkt/s`} />
      </div>

      {n.behaviors.length > 0 && n.risk > 0.3 && (
        <div className="mt-4">
          <div className="eyebrow mb-2">Top behaviours</div>
          {n.behaviors.slice(0, 3).map((b, i) => (
            <div key={b.key} className="mb-2">
              <div className="mb-1 flex justify-between text-[11.5px]">
                <span className="text-ink-2">{b.label}</span>
                <span className="mono text-ink">{fmtPct(b.value, 0)}</span>
              </div>
              <Meter value={b.value} color={HEX.threat} height={3} delay={i * 0.06} />
            </div>
          ))}
        </div>
      )}

      <div className="mt-4">
        <div className="eyebrow mb-1.5">Relationships</div>
        {mine.map((e) => (
          <button
            key={e.id}
            onClick={() => select({ kind: 'edge', id: e.id })}
            className="btn-press flex w-full items-center justify-between rounded-md px-1.5 py-1.5 text-left text-[11.5px] hover:bg-white/[0.04]"
          >
            <span className="mono truncate text-ink-2">
              {e.source === n.id ? '→ ' + e.target : '← ' + e.source}
            </span>
            <span className="mono" style={{ color: riskColor(e.anomaly, threshold) }}>{fmtPct(e.anomaly, 0)}</span>
          </button>
        ))}
      </div>

      <button
        onClick={() => {
          const top = mine[0]
          if (top && top.anomaly >= 0.4) {
            investigate({ edgeId: top.id })
          } else {
            focusOn([n.id, ...mine.map((e) => (e.source === n.id ? e.target : e.source))])
          }
        }}
        className="btn-press mt-4 w-full rounded-lg border border-ai/30 bg-ai/10 py-2 text-[11.5px] font-semibold tracking-[0.14em] text-ai hover:bg-ai/15"
      >
        INVESTIGATE
      </button>
    </div>
  )
}

function EdgePanel({ e }: { e: EdgeState }) {
  const threshold = useSentinel((s) => s.threshold)
  const color = riskColor(e.anomaly, threshold)
  const cls = e.classification
  return (
    <div>
      <div className="mt-1 flex items-center gap-2 mono text-[14px] text-ink">
        <span>{e.source}</span>
        <svg width="18" height="8" viewBox="0 0 18 8"><path d="M0 4h15M12 1l3 3-3 3" stroke={color} strokeWidth="1.3" fill="none" /></svg>
        <span>{e.target}</span>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        <Tag color={color}>{cls}</Tag>
        {e.attackClass !== 'normal' && e.anomaly >= 0.4 && <Tag color={HEX.ai}>{SCENARIOS[e.attackClass].short}</Tag>}
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3">
        <div>
          <div className="eyebrow">Anomaly prob.</div>
          <AnimatedNumber value={e.anomaly * 100} format={(v) => `${v.toFixed(1)}%`} className="mono mt-1 block text-[22px] font-medium" />
          <div className="mt-1.5"><Meter value={e.anomaly} color={color} height={3} /></div>
        </div>
        <div>
          <div className="eyebrow">GAT attention</div>
          <AnimatedNumber value={e.attention} format={(v) => v.toFixed(2)} className="mono mt-1 block text-[22px] font-medium text-ai" />
          <div className="mt-1.5"><Meter value={e.attention} color={HEX.ai} height={3} /></div>
        </div>
      </div>

      <div className="mt-4 divide-y divide-line border-y border-line">
        <KV k="Protocol" v={e.protocol} />
        <KV k="Flows" v={fmtInt(e.flows)} />
        <KV k="Packets" v={fmtInt(e.packets)} />
        <KV k="Bytes" v={fmtBytes(e.bytes)} />
        <KV k="Avg flow duration" v={fmtDuration(e.avgDuration)} />
        <KV k="Packet rate" v={`${fmtCompact(e.pps)} pkt/s`} />
        <KV k="Dest. ports" v={e.ports.length > 6 ? `${e.ports.length}${e.ports.length >= 64 ? '+' : ''} distinct` : e.ports.join(', ')} />
        <KV k="Threshold" v={threshold.toFixed(2)} />
      </div>

      {e.signals.length > 0 && (
        <div className="mt-4">
          <div className="eyebrow mb-2">Contributing signals</div>
          {e.signals.slice(0, 4).map((s, i) => (
            <div key={s.key} className="mb-2">
              <div className="mb-1 flex justify-between text-[11.5px]">
                <span className="text-ink-2">{s.label}</span>
                <span className="mono text-ink">{fmtPct(s.value, 0)}</span>
              </div>
              <Meter value={s.value} color={s.value > 0.5 ? color : HEX.ink3} height={3} delay={i * 0.06} />
            </div>
          ))}
        </div>
      )}

      <button
        onClick={() => investigate({ edgeId: e.id })}
        className="btn-press mt-3 w-full rounded-lg border border-ai/30 bg-ai/10 py-2 text-[11.5px] font-semibold tracking-[0.14em] text-ai hover:bg-ai/15"
      >
        VIEW MODEL EXPLANATION
      </button>
    </div>
  )
}

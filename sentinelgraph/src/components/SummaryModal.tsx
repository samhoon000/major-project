import { AnimatePresence, motion } from 'framer-motion'
import { SCENARIOS } from '../engine/scenarios'
import { HEX, fmtInt, fmtTime } from '../lib/format'
import { dismissSummary, focusOn, investigate, select, setView } from '../store/runtime'
import { useSentinel } from '../store/store'
import { AnimatedNumber, StatusDot } from './ui'

export function SummaryModal() {
  const s = useSentinel((st) => st.summary)
  const demo = useSentinel((st) => st.demo.running)

  return (
    <AnimatePresence>
      {s && (
        <motion.div
          key={s.id}
          className="fixed inset-0 z-50 grid place-items-center bg-env/60 p-4 backdrop-blur-[3px]"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={dismissSummary}
        >
          <motion.div
            role="dialog"
            aria-label="Threat summary"
            onClick={(e) => e.stopPropagation()}
            initial={{ y: 24, scale: 0.97, opacity: 0 }}
            animate={{ y: 0, scale: 1, opacity: 1 }}
            exit={{ y: 12, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 260, damping: 28 }}
            className="relative w-full max-w-[560px] overflow-hidden rounded-2xl border border-line-2 bg-s1 shadow-[0_40px_120px_-30px_rgba(0,0,0,0.9)]"
          >
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(500px_200px_at_0%_0%,rgba(255,79,94,0.14),transparent),radial-gradient(400px_200px_at_100%_100%,rgba(86,217,230,0.08),transparent)]" />
            <div className="relative p-6">
              <div className="flex items-center justify-between">
                <div className="eyebrow">Incident report · {fmtTime(s.startedAt)} – {fmtTime(s.endedAt)}</div>
                <button onClick={dismissSummary} className="btn-press grid h-7 w-7 place-items-center rounded-md text-ink-3 hover:bg-white/5 hover:text-ink" aria-label="Close summary">
                  <svg width="10" height="10" viewBox="0 0 10 10"><path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" strokeWidth="1.4" /></svg>
                </button>
              </div>
              <h2 className="mt-3 text-[26px] font-semibold tracking-[0.08em] text-ink">THREAT DETECTED</h2>

              <div className="mt-5 grid grid-cols-3 gap-x-6 gap-y-4">
                <Field k="Attack" v={SCENARIOS[s.attackClass === 'normal' ? 'portscan' : s.attackClass].name} sans />
                <Field k="Source" v={s.source} />
                <Field k="Target" v={s.target} />
                <Field k="Flows analyzed" v={<AnimatedNumber value={s.flowsAnalyzed} format={fmtInt} duration={1.2} from={0} />} />
                <Field k="Suspicious flows" v={<AnimatedNumber value={s.suspiciousFlows} format={fmtInt} duration={1.2} from={0} />} color={HEX.threat} />
                <Field k="Time to detect" v={s.detectedAt ? `${((s.detectedAt - s.startedAt) / 1000).toFixed(1)} s` : '—'} />
              </div>

              <div className="mt-5 grid grid-cols-3 gap-3 rounded-xl border border-line bg-env/40 p-4">
                <Big k="Anomaly probability" v={s.peakAnomaly * 100} fmt={(n) => `${n.toFixed(1)}%`} color={HEX.threat} />
                <Big k="GAT attention" v={s.peakAttention} fmt={(n) => n.toFixed(2)} color={HEX.ai} />
                <Big k="Confidence" v={s.confidence * 100} fmt={(n) => `${n.toFixed(1)}%`} color={HEX.ink2} />
              </div>

              <div className="mt-5 flex items-center gap-2.5">
                <span className="eyebrow">Detection status</span>
                <span className="flex items-center gap-2 text-[12px] font-bold tracking-[0.16em] text-threat">
                  <StatusDot color={HEX.threat} pulse /> THREAT CONFIRMED
                </span>
                <span className="ml-auto text-[11px] font-semibold tracking-[0.14em] text-ok">CONTAINED</span>
              </div>

              <div className="mt-6 grid grid-cols-3 gap-2">
                <button
                  onClick={() => {
                    dismissSummary()
                    setView('graph')
                    select({ kind: 'edge', id: s.edgeId })
                    setTimeout(() => focusOn([s.source.split(' ')[0], s.target]), 250)
                  }}
                  className="btn-press rounded-lg border border-line-2 py-2.5 text-[10.5px] font-semibold tracking-[0.14em] text-ink hover:bg-white/5"
                >
                  VIEW NETWORK
                </button>
                <button
                  onClick={() => {
                    dismissSummary()
                    setView('overview')
                    investigate({ edgeId: s.edgeId })
                  }}
                  className="btn-press rounded-lg border border-ai/35 bg-ai/10 py-2.5 text-[10.5px] font-semibold tracking-[0.14em] text-ai hover:bg-ai/15"
                >
                  VIEW EXPLANATION
                </button>
                <button
                  disabled={demo}
                  onClick={() => {
                    dismissSummary()
                    select(null)
                    focusOn([])
                    setView('overview')
                  }}
                  className="btn-press rounded-lg bg-threat py-2.5 text-[10.5px] font-semibold tracking-[0.14em] text-white hover:brightness-110 disabled:opacity-50"
                >
                  RUN ANOTHER ATTACK
                </button>
              </div>
              <div className="mt-4 text-center text-[10.5px] text-ink-4">Simulated scenario · no real traffic was generated</div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

function Field({ k, v, color, sans }: { k: string; v: React.ReactNode; color?: string; sans?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="eyebrow">{k}</div>
      <div className={`${sans ? 'font-medium' : 'mono'} mt-1 truncate text-[14px] text-ink`} style={color ? { color } : undefined}>
        {v}
      </div>
    </div>
  )
}

function Big({ k, v, fmt, color }: { k: string; v: number; fmt: (n: number) => string; color: string }) {
  return (
    <div>
      <div className="eyebrow">{k}</div>
      <AnimatedNumber value={v} format={fmt} duration={1.2} from={0} className="mono mt-1 block text-[24px] font-medium" />
      <div className="mt-2 h-[2px] w-8 rounded-full" style={{ background: color }} />
    </div>
  )
}

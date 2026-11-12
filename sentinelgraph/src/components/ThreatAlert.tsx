import { AnimatePresence, motion } from 'framer-motion'
import { SCENARIOS } from '../engine/scenarios'
import { fmtTime } from '../lib/format'
import { dismissAlert, investigate } from '../store/runtime'
import { useSentinel } from '../store/store'
import { AnimatedNumber } from './ui'

export function ThreatAlert() {
  const inc = useSentinel((s) => s.incidents.find((i) => i.id === s.alertIncidentId))
  const presentation = useSentinel((s) => s.presentation)

  return (
    <AnimatePresence>
      {inc && (
        <motion.div
          key={inc.id}
          role="alert"
          initial={{ opacity: 0, y: -16, scale: 0.97, filter: 'blur(6px)' }}
          animate={{ opacity: 1, y: 0, scale: 1, filter: 'blur(0px)' }}
          exit={{ opacity: 0, y: -10, scale: 0.98, filter: 'blur(4px)' }}
          transition={{ type: 'spring', stiffness: 260, damping: 26 }}
          className={`absolute top-3 left-3 z-20 overflow-hidden rounded-xl border border-threat/40 bg-[#160b0e]/92 shadow-[0_30px_80px_-20px_rgba(255,79,94,0.45)] backdrop-blur-md ${presentation ? 'w-[380px]' : 'w-[330px]'}`}
        >
          <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(400px_160px_at_0%_0%,rgba(255,79,94,0.18),transparent)]" />
          <motion.div
            className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-threat to-transparent"
            animate={{ opacity: [0.4, 1, 0.4] }}
            transition={{ duration: 2, repeat: Infinity }}
          />
          <div className="relative p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="relative grid h-6 w-6 place-items-center">
                  <span className="absolute inset-0 animate-pulse-ring rounded-full border border-threat" />
                  <span className="absolute inset-[5px] rounded-full border-2 border-threat" />
                  <span className="h-1.5 w-1.5 rounded-full bg-threat" />
                </span>
                <span className="text-[11.5px] font-bold tracking-[0.2em] text-threat">THREAT DETECTED</span>
              </div>
              <button onClick={dismissAlert} className="btn-press grid h-6 w-6 place-items-center rounded-md text-ink-3 hover:bg-white/5 hover:text-ink" aria-label="Dismiss alert">
                <svg width="10" height="10" viewBox="0 0 10 10"><path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" strokeWidth="1.4" /></svg>
              </button>
            </div>

            <div className="mt-3 text-[20px] font-semibold tracking-wide text-ink">{SCENARIOS[inc.attackClass === 'normal' ? 'portscan' : inc.attackClass].name.toUpperCase()}</div>
            <div className="mono mt-1 text-[11.5px] text-ink-2">
              {inc.source} <span className="text-threat">→</span> {inc.target}
              <span className="ml-2 text-ink-3">{fmtTime(inc.ts)}</span>
            </div>

            <div className="mt-3 flex items-end gap-6">
              <div>
                <div className="eyebrow">Anomaly score</div>
                <AnimatedNumber value={inc.risk * 100} format={(n) => `${n.toFixed(1)}%`} className="mono mt-0.5 block text-[26px] font-medium text-threat" duration={1} />
              </div>
              <div>
                <div className="eyebrow">GAT attention</div>
                <AnimatedNumber value={inc.attention} format={(n) => n.toFixed(2)} className="mono mt-0.5 block text-[26px] font-medium text-ai" />
              </div>
            </div>

            <p className="mt-3 text-[12px] leading-relaxed text-ink-2">
              GAT attention identified a highly suspicious communication pattern between these hosts.
            </p>

            <button
              onClick={() => investigate({ incidentId: inc.id })}
              className="btn-press mt-3.5 w-full rounded-lg bg-threat py-2.5 text-[11.5px] font-bold tracking-[0.18em] text-white hover:brightness-110"
            >
              INVESTIGATE
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

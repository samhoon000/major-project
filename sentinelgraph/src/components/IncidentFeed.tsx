import { AnimatePresence, motion } from 'framer-motion'
import { useState } from 'react'
import type { Incident } from '../engine/types'
import { HEX, fmtPct, fmtTime, severityColor } from '../lib/format'
import { focusOn, investigate, select } from '../store/runtime'
import { useSentinel } from '../store/store'
import { Meter, StatusDot, cx } from './ui'

export function IncidentFeed({ limit = 40, dense = false }: { limit?: number; dense?: boolean }) {
  const incidents = useSentinel((s) => s.incidents)
  const [open, setOpen] = useState<string | null>(null)
  const list = incidents.slice(0, limit)

  if (!list.length) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 px-4 py-8 text-center">
        <div className="grid h-9 w-9 place-items-center rounded-full border border-line">
          <StatusDot color={HEX.ok} size={6} />
        </div>
        <div className="text-[12px] text-ink-2">No incidents</div>
        <div className="max-w-[220px] text-[11px] leading-snug text-ink-3">
          Every edge in the graph is below the anomaly threshold. Launch a simulation to see detection.
        </div>
      </div>
    )
  }

  return (
    <ul className="flex flex-col gap-1.5">
      <AnimatePresence initial={false}>
        {list.map((inc) => (
          <motion.li
            key={inc.id}
            layout
            initial={{ opacity: 0, x: -12, height: 0 }}
            animate={{ opacity: 1, x: 0, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ type: 'spring', stiffness: 400, damping: 36 }}
          >
            <IncidentRow
              inc={inc}
              dense={dense}
              open={open === inc.id}
              onToggle={() => {
                const next = open === inc.id ? null : inc.id
                setOpen(next)
                if (next) {
                  select({ kind: 'edge', id: inc.edgeId })
                  focusOn([inc.source, inc.target])
                }
              }}
            />
          </motion.li>
        ))}
      </AnimatePresence>
    </ul>
  )
}

function IncidentRow({ inc, open, onToggle, dense }: { inc: Incident; open: boolean; onToggle: () => void; dense: boolean }) {
  const color = severityColor(inc.severity)
  const contained = inc.status === 'CONTAINED'
  return (
    <div
      className={cx(
        'group relative overflow-hidden rounded-lg border transition-colors',
        open ? 'border-line-2 bg-s2' : 'border-line bg-s2/40 hover:border-line-2 hover:bg-s2/80',
      )}
    >
      <span className="absolute inset-y-0 left-0 w-[2px]" style={{ background: color, opacity: contained ? 0.4 : 1 }} />
      <button onClick={onToggle} className="w-full px-3 py-2.5 text-left" aria-expanded={open}>
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-1.5 text-[9.5px] font-bold tracking-[0.16em]" style={{ color }}>
            <StatusDot color={color} size={6} pulse={!contained && inc.severity === 'CRITICAL'} />
            {inc.severity}
          </span>
          <span className="mono text-[10px] text-ink-3">{fmtTime(inc.ts)}</span>
        </div>
        <div className={cx('mt-1 font-medium text-ink', dense ? 'text-[12px]' : 'text-[12.5px]')}>{inc.title}</div>
        <div className="mt-1 flex items-center justify-between gap-2">
          <span className="mono truncate text-[10.5px] text-ink-3">
            {inc.source} <span className="text-ink-4">→</span> {inc.target}
          </span>
          <span className="mono shrink-0 text-[11px]" style={{ color }}>
            {fmtPct(inc.risk, 0)}
          </span>
        </div>
        {contained && <div className="mt-1 text-[9.5px] font-semibold tracking-[0.16em] text-ok/80">CONTAINED</div>}
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22 }}
            className="overflow-hidden"
          >
            <div className="border-t border-line px-3 pt-2 pb-3">
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div>
                  <div className="text-ink-3">GAT attention</div>
                  <div className="mono text-ai">{inc.attention.toFixed(2)}</div>
                </div>
                <div>
                  <div className="text-ink-3">Suspicious flows</div>
                  <div className="mono text-ink">{inc.flowsObserved.toLocaleString()}</div>
                </div>
              </div>
              <div className="mt-2 space-y-1.5">
                {inc.signals.slice(0, 3).map((s) => (
                  <div key={s.key}>
                    <div className="mb-0.5 flex justify-between text-[10.5px]">
                      <span className="text-ink-3">{s.label}</span>
                      <span className="mono text-ink-2">{fmtPct(s.value, 0)}</span>
                    </div>
                    <Meter value={s.value} color={color} height={2} />
                  </div>
                ))}
              </div>
              <button
                onClick={() => investigate({ incidentId: inc.id })}
                className="btn-press mt-3 w-full rounded-md border border-ai/30 bg-ai/10 py-1.5 text-[10.5px] font-semibold tracking-[0.14em] text-ai hover:bg-ai/15"
              >
                INVESTIGATE
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

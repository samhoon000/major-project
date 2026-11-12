import { AnimatePresence, motion } from 'framer-motion'
import type { TimelineStage } from '../engine/types'
import { HEX, fmtTime } from '../lib/format'
import { useSentinel } from '../store/store'
import { cx } from './ui'

const GROUPS: { title: string; stages: TimelineStage[]; color: string }[] = [
  { title: 'Normal', stages: ['NORMAL'], color: HEX.ok },
  { title: 'Activity spike', stages: ['SPIKE'], color: HEX.warn },
  { title: 'Anomaly', stages: ['ANOMALY'], color: HEX.warn },
  { title: 'Attack detected', stages: ['DETECTED', 'CRITICAL'], color: HEX.threat },
  { title: 'Mitigation / recovery', stages: ['STOPPED', 'RECOVERED'], color: HEX.ok },
]

export function ThreatTimeline({ compact = false }: { compact?: boolean }) {
  const events = useSentinel((s) => s.timeline)
  const reached = GROUPS.map((g) => events.filter((e) => g.stages.includes(e.stage)))
  const lastIdx = reached.reduce((acc, r, i) => (r.length ? i : acc), 0)

  return (
    <div className="relative">
      <div className="grid grid-cols-5">
        {GROUPS.map((g, i) => {
          const evs = reached[i]
          const on = evs.length > 0 || (i === 0 && events.length === 0)
          const current = i === lastIdx
          return (
            <div key={g.title} className="relative min-w-0 pr-2">
              {/* connector */}
              {i < GROUPS.length - 1 && (
                <div className="absolute top-[5px] right-0 left-[14px] h-px bg-line-2">
                  <motion.div
                    className="h-full origin-left"
                    style={{ background: GROUPS[i + 1].color }}
                    initial={false}
                    animate={{ scaleX: reached[i + 1].length ? 1 : 0 }}
                    transition={{ duration: 0.6, ease: [0.2, 0.7, 0.2, 1] }}
                  />
                </div>
              )}
              <div className="relative flex items-center gap-2">
                <span className="relative grid h-[11px] w-[11px] place-items-center">
                  {current && on && i !== 0 && i !== 4 && (
                    <span className="absolute inset-0 animate-pulse-ring rounded-full" style={{ background: g.color }} />
                  )}
                  <span
                    className="relative h-[11px] w-[11px] rounded-full border-2 bg-env transition-colors duration-500"
                    style={{ borderColor: on ? g.color : 'rgba(255,255,255,0.15)', background: on && current ? g.color : undefined }}
                  />
                </span>
              </div>
              <div className={cx('mt-2 text-[10px] font-semibold tracking-[0.14em] uppercase transition-colors', on ? 'text-ink' : 'text-ink-4')}>
                {g.title}
              </div>
              {!compact && (
                <div className="mt-1 min-h-[30px] space-y-0.5">
                  {i === 0 && events.length === 0 && (
                    <div className="truncate text-[10.5px] text-ink-3">Monitoring · no anomalies</div>
                  )}
                  <AnimatePresence>
                    {evs.map((e) => (
                      <motion.div
                        key={e.id}
                        initial={{ opacity: 0, y: 4 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="truncate text-[10.5px]"
                        title={e.label}
                      >
                        <span className="mono text-ink-3">{fmtTime(e.ts)}</span>{' '}
                        <span className="text-ink-2">{e.label}</span>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

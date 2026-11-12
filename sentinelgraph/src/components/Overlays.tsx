import { AnimatePresence, motion } from 'framer-motion'
import { HEX, fmtCompact, fmtInt, levelColor } from '../lib/format'
import { DEMO_PHASES, stopDemo } from '../store/runtime'
import { useSentinel, type Story } from '../store/store'
import { AnimatedNumber, StatusDot, cx } from './ui'

/** Caption bar for the scripted full demo. */
export function DemoHud() {
  const demo = useSentinel((s) => s.demo)
  return (
    <AnimatePresence>
      {demo.running && demo.phase > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 16 }}
          className="pointer-events-auto absolute bottom-3 left-1/2 z-20 w-[min(640px,calc(100%-120px))] -translate-x-1/2 rounded-xl border border-line-2 bg-s1/90 px-4 py-3 shadow-2xl backdrop-blur-md"
        >
          <div className="flex items-center justify-between">
            <span className="mono text-[10px] tracking-[0.18em] text-ai">
              FULL DEMO · PHASE {demo.phase}/{DEMO_PHASES.length}
            </span>
            <button onClick={stopDemo} className="btn-press text-[10px] font-semibold tracking-[0.14em] text-ink-3 hover:text-ink">
              EXIT
            </button>
          </div>
          <div className="mt-2 flex gap-1">
            {DEMO_PHASES.map((_, i) => (
              <div key={i} className="h-[3px] flex-1 overflow-hidden rounded-full bg-white/[0.07]">
                <motion.div
                  className="h-full rounded-full"
                  style={{ background: i >= 3 && i <= 7 ? HEX.threat : HEX.ai }}
                  initial={false}
                  animate={{ width: i < demo.phase ? '100%' : '0%' }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            ))}
          </div>
          <AnimatePresence mode="wait">
            <motion.div
              key={demo.phase}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25 }}
            >
              <div className="mt-2.5 text-[15px] font-semibold text-ink">{demo.title}</div>
              <div className="mt-0.5 text-[12.5px] leading-snug text-ink-2">{demo.caption}</div>
            </motion.div>
          </AnimatePresence>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

const STORY: Story[] = ['OBSERVE', 'ATTACK', 'DETECT', 'INVESTIGATE', 'RECOVER']

/** Narrative stepper shown in presentation mode. */
export function StoryStepper() {
  const story = useSentinel((s) => s.story)
  const idx = STORY.indexOf(story)
  return (
    <div className="flex items-center gap-1.5" aria-label="Story progress">
      {STORY.map((s, i) => {
        const on = i <= idx
        const cur = i === idx
        const c = s === 'ATTACK' || s === 'DETECT' ? HEX.threat : s === 'INVESTIGATE' ? HEX.ai : HEX.ok
        return (
          <div key={s} className="flex items-center gap-1.5">
            <motion.div
              animate={{ opacity: on ? 1 : 0.35, scale: cur ? 1.04 : 1 }}
              className={cx('rounded-full px-3 py-1 text-[11px] font-semibold tracking-[0.18em]', cur ? 'text-env' : 'text-ink-2')}
              style={{ background: cur ? c : 'transparent', boxShadow: cur ? `0 0 24px ${c}55` : `inset 0 0 0 1px ${on ? c + '55' : 'rgba(255,255,255,0.1)'}` }}
            >
              {s}
            </motion.div>
            {i < STORY.length - 1 && <span className="text-[10px] text-ink-4">→</span>}
          </div>
        )
      })}
    </div>
  )
}

/** Inline KPI strip — typography, not boxes. */
export function KpiStrip({ large = false }: { large?: boolean }) {
  const status = useSentinel((s) => s.networkStatus)
  const hosts = useSentinel((s) => s.graph.nodes.length)
  const external = useSentinel((s) => s.graph.nodes.filter((n) => n.zone === 'external').length)
  const flows = useSentinel((s) => s.totals.flows)
  const rate = useSentinel((s) => s.inference.flowsPerSec)
  const level = useSentinel((s) => s.threatLevel)
  const score = useSentinel((s) => s.threatScore)

  const statusColor = status === 'UNDER ATTACK' ? HEX.threat : status === 'NORMAL' ? HEX.ok : HEX.warn
  const items = [
    {
      k: 'Network status',
      v: (
        <AnimatePresence mode="wait">
          <motion.span key={status} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} className="flex items-center gap-2" style={{ color: statusColor }}>
            <StatusDot color={statusColor} pulse={status === 'UNDER ATTACK'} size={7} />
            {status}
          </motion.span>
        </AnimatePresence>
      ),
      sub: status === 'NORMAL' ? 'All edges below threshold' : status === 'RECOVERING' ? 'Scores decaying' : 'Anomalous relationships present',
    },
    {
      k: 'Active hosts',
      v: <AnimatedNumber value={hosts} />,
      sub: external ? `${hosts - external} internal · ${external} external` : 'Internal network',
    },
    {
      k: 'Traffic flows',
      v: <AnimatedNumber value={flows} format={fmtInt} duration={0.45} />,
      sub: `${fmtCompact(rate)} flows/s analysed`,
    },
    {
      k: 'Threat level',
      v: <span style={{ color: levelColor(level) }}>{level}</span>,
      sub: `Score ${(score * 100).toFixed(0)} / 100`,
    },
  ]
  return (
    <div className="grid grid-cols-2 gap-y-3 md:grid-cols-4">
      {items.map((it, i) => (
        <div key={it.k} className={cx('min-w-0 px-4', i > 0 && 'md:border-l md:border-line')}>
          <div className="eyebrow">{it.k}</div>
          <div className={cx('mt-1 truncate font-semibold tracking-[0.02em] text-ink', large ? 'text-[24px]' : 'text-[19px]')}>{it.v}</div>
          <div className="mt-0.5 truncate text-[11px] text-ink-3">{it.sub}</div>
        </div>
      ))}
    </div>
  )
}

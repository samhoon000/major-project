import { AnimatePresence, motion } from 'framer-motion'
import { HEX, levelColor } from '../lib/format'
import { useSentinel } from '../store/store'
import { AnimatedNumber } from './ui'

const LEVELS = ['LOW', 'GUARDED', 'ELEVATED', 'HIGH', 'CRITICAL'] as const

/** 240° arc gauge for the overall threat score. */
export function ThreatGauge({ large = false }: { large?: boolean }) {
  const score = useSentinel((s) => s.threatScore)
  const level = useSentinel((s) => s.threatLevel)
  const status = useSentinel((s) => s.networkStatus)
  const color = levelColor(level)

  const size = large ? 200 : 168
  const r = size / 2 - 12
  const c = size / 2
  const start = 150
  const sweep = 240
  const arc = (from: number, to: number) => {
    const a0 = ((start + from * sweep) * Math.PI) / 180
    const a1 = ((start + to * sweep) * Math.PI) / 180
    const large = (to - from) * sweep > 180 ? 1 : 0
    return `M${c + r * Math.cos(a0)} ${c + r * Math.sin(a0)} A${r} ${r} 0 ${large} 1 ${c + r * Math.cos(a1)} ${c + r * Math.sin(a1)}`
  }
  const v = Math.max(0.002, Math.min(1, score))
  const tip = ((start + v * sweep) * Math.PI) / 180

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size * 0.82 }}>
        <svg width={size} height={size} className="absolute top-0 left-0" aria-hidden>
          {/* ticks */}
          {Array.from({ length: 41 }, (_, i) => {
            const a = ((start + (i / 40) * sweep) * Math.PI) / 180
            const major = i % 10 === 0
            const r0 = r + 5
            const r1 = r + (major ? 10 : 7)
            return (
              <line
                key={i}
                x1={c + r0 * Math.cos(a)}
                y1={c + r0 * Math.sin(a)}
                x2={c + r1 * Math.cos(a)}
                y2={c + r1 * Math.sin(a)}
                stroke={i / 40 <= v ? color : 'rgba(255,255,255,0.12)'}
                strokeOpacity={i / 40 <= v ? 0.8 : 1}
                strokeWidth={major ? 1.3 : 0.8}
                style={{ transition: 'stroke 400ms' }}
              />
            )
          })}
          <path d={arc(0, 1)} stroke="rgba(255,255,255,0.06)" strokeWidth={6} fill="none" strokeLinecap="round" />
          <motion.path
            d={arc(0, 1)}
            stroke={color}
            strokeWidth={6}
            fill="none"
            strokeLinecap="round"
            initial={false}
            animate={{ pathLength: v, stroke: color }}
            transition={{ duration: 0.8, ease: [0.2, 0.7, 0.2, 1] }}
            style={{ filter: `drop-shadow(0 0 8px ${color}80)` }}
          />
          <motion.circle
            r={4}
            fill="#fff"
            initial={false}
            animate={{ cx: c + r * Math.cos(tip), cy: c + r * Math.sin(tip) }}
            transition={{ duration: 0.8, ease: [0.2, 0.7, 0.2, 1] }}
            style={{ filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>
        <div className="absolute inset-x-0 flex flex-col items-center" style={{ top: size * 0.3 }}>
          <div className="eyebrow">Threat level</div>
          <AnimatePresence mode="wait">
            <motion.div
              key={level}
              initial={{ opacity: 0, y: 6, filter: 'blur(4px)' }}
              animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
              exit={{ opacity: 0, y: -6, filter: 'blur(4px)' }}
              transition={{ duration: 0.3 }}
              className="mt-1 font-semibold tracking-[0.06em]"
              style={{ color, fontSize: large ? 30 : 25 }}
            >
              {level}
            </motion.div>
          </AnimatePresence>
          <div className="mono mt-0.5 text-[11px] text-ink-3">
            score <AnimatedNumber value={score * 100} format={(n) => n.toFixed(0)} className="text-ink-2" />/100
          </div>
        </div>
      </div>
      <div className="mt-1 flex w-full items-center gap-1 px-2" aria-hidden>
        {LEVELS.map((l) => {
          const on = LEVELS.indexOf(l) <= LEVELS.indexOf(level)
          return (
            <div key={l} className="flex-1">
              <div
                className="h-[3px] rounded-full transition-colors duration-500"
                style={{ background: on ? levelColor(l) : 'rgba(255,255,255,0.07)' }}
              />
            </div>
          )
        })}
      </div>
      <div className="mt-2.5 flex w-full items-center justify-between px-2 text-[11px]">
        <span className="text-ink-3">Network</span>
        <span
          className="font-semibold tracking-[0.12em]"
          style={{ color: status === 'UNDER ATTACK' ? HEX.threat : status === 'NORMAL' ? HEX.ok : HEX.warn }}
        >
          {status}
        </span>
      </div>
    </div>
  )
}

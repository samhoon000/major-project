import { AnimatePresence, motion } from 'framer-motion'
import { ATTACK_ORDER, SCENARIOS } from '../engine/scenarios'
import type { AttackType } from '../engine/types'
import { HEX } from '../lib/format'
import { launchAttack, setScenario, setView, stopAttack } from '../store/runtime'
import { useSentinel } from '../store/store'
import { Segmented, cx } from './ui'

function useSimState() {
  const phase = useSentinel((s) => s.simPhase)
  const level = useSentinel((s) => s.attackLevel)
  const active = useSentinel((s) => s.activeAttack)
  const source = useSentinel((s) => s.source)
  const running = phase === 'ramp' || phase === 'active'
  return { phase, level, active, running, replay: source === 'replay' }
}

export function TacticIcon({ attack, size = 16, color = 'currentColor' }: { attack: AttackType; size?: number; color?: string }) {
  const p = { fill: 'none', stroke: color, strokeWidth: 1.3, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const }
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden>
      {attack === 'portscan' && (
        <>
          <circle cx="8" cy="8" r="6" {...p} opacity={0.5} />
          <circle cx="8" cy="8" r="3" {...p} opacity={0.7} />
          <path d="M8 8 L13 4" {...p} />
        </>
      )}
      {attack === 'dos' && <path d="M2 8h8M7 4l4 4-4 4M13 3v10" {...p} />}
      {attack === 'ddos' && <path d="M2 3l6 5M2 8h6M2 13l6-5M10 8h4M12 6l2 2-2 2" {...p} />}
      {attack === 'bruteforce' && (
        <>
          <rect x="3" y="7" width="10" height="7" rx="1.5" {...p} />
          <path d="M5.5 7V5a2.5 2.5 0 015 0v2" {...p} />
        </>
      )}
      {attack === 'c2' && <path d="M3 13c3-1 4-6 10-10M10 3h3v3M4 6.5a1.5 1.5 0 100-.01" {...p} />}
      {attack === 'normal' && <path d="M1.5 8h3l1.5-3 2 6 1.5-3h5" {...p} />}
    </svg>
  )
}

/** Compact console for the command-centre rail. */
export function SimulatorConsole({ minimal = false }: { minimal?: boolean }) {
  const scenario = useSentinel((s) => s.scenario)
  const demo = useSentinel((s) => s.demo.running)
  const { phase, level, running, active } = useSimState()
  const meta = SCENARIOS[scenario.attack]
  const isNormal = scenario.attack === 'normal'

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <div className="eyebrow text-ink-2">Attack simulator</div>
        <PhaseBadge />
      </div>

      {!minimal && (
        <div className="grid grid-cols-2 gap-1.5" role="radiogroup" aria-label="Attack type">
          {ATTACK_ORDER.map((a) => {
            const on = scenario.attack === a
            const isActive = running && active === a
            return (
              <button
                key={a}
                role="radio"
                aria-checked={on}
                disabled={demo}
                onClick={() => setScenario({ attack: a })}
                className={cx(
                  'btn-press group relative flex items-center gap-2 overflow-hidden rounded-lg border px-2.5 py-2 text-left',
                  on
                    ? a === 'normal'
                      ? 'border-ok/40 bg-ok/[0.06]'
                      : 'border-threat/45 bg-threat/[0.07]'
                    : 'border-line bg-s2/50 hover:border-line-2 hover:bg-s2',
                )}
              >
                <span className={cx('shrink-0', on ? (a === 'normal' ? 'text-ok' : 'text-threat') : 'text-ink-3 group-hover:text-ink-2')}>
                  <TacticIcon attack={a} size={14} />
                </span>
                <span className="min-w-0">
                  <span className={cx('block truncate text-[11.5px] font-medium', on ? 'text-ink' : 'text-ink-2')}>{SCENARIOS[a].short}</span>
                  <span className="block truncate text-[9.5px] tracking-wide text-ink-3 uppercase">{SCENARIOS[a].tactic}</span>
                </span>
                {isActive && <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 animate-blink rounded-full bg-threat" />}
              </button>
            )
          })}
        </div>
      )}

      <AnimatePresence mode="wait">
        <motion.div
          key={scenario.attack}
          initial={{ opacity: 0, y: 4 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          transition={{ duration: 0.18 }}
          className="rounded-lg border border-line bg-s2/40 px-3 py-2.5"
        >
          <div className="flex items-baseline justify-between">
            <span className="text-[13px] font-semibold text-ink">{meta.name}</span>
            {meta.mitre && <span className="mono text-[10px] text-ink-3">MITRE {meta.mitre}</span>}
          </div>
          <p className="mt-1 text-[11.5px] leading-snug text-ink-3">{meta.description}</p>
          {!isNormal && (
            <div className="mt-2.5 grid grid-cols-2 gap-2">
              <div>
                <div className="eyebrow text-[9.5px]">Source</div>
                <div className="mono mt-0.5 text-[11.5px] text-ink">{meta.source}</div>
              </div>
              <div>
                <div className="eyebrow text-[9.5px]">Target</div>
                <div className="mono mt-0.5 text-[11.5px] text-ink">{meta.target}</div>
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>

      {!isNormal && (
        <div className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-2">
          <span className="eyebrow text-[9.5px]">Intensity</span>
          <Segmented
            label="intensity"
            size="sm"
            tone="threat"
            disabled={running || demo}
            value={scenario.intensity}
            onChange={(v) => setScenario({ intensity: v })}
            options={[
              { value: 'LOW', label: 'LOW' },
              { value: 'MEDIUM', label: 'MED' },
              { value: 'HIGH', label: 'HIGH' },
            ]}
          />
          <span className="eyebrow text-[9.5px]">Duration</span>
          <Segmented
            label="duration"
            size="sm"
            disabled={running || demo}
            value={scenario.durationSec}
            onChange={(v) => setScenario({ durationSec: v })}
            options={[
              { value: 5, label: '5s' },
              { value: 10, label: '10s' },
              { value: 20, label: '20s' },
            ]}
          />
        </div>
      )}

      <LaunchControls running={running} phase={phase} level={level} disabled={demo} isNormal={isNormal} />
    </div>
  )
}

export function PhaseBadge() {
  const { phase, running } = useSimState()
  const label = phase === 'ramp' ? 'ESCALATING' : phase === 'active' ? 'ACTIVE' : phase === 'decay' ? 'STOPPING' : 'STANDBY'
  const color = running ? HEX.threat : phase === 'decay' ? HEX.warn : HEX.ink3
  return (
    <span className="mono flex items-center gap-1.5 text-[10px] tracking-[0.14em]" style={{ color }}>
      <span className={cx('h-1.5 w-1.5 rounded-full', running && 'animate-blink')} style={{ background: color }} />
      {label}
    </span>
  )
}

export function LaunchControls({
  running, phase, level, disabled, isNormal, big = false,
}: {
  running: boolean
  phase: string
  level: number
  disabled?: boolean
  isNormal: boolean
  big?: boolean
}) {
  return (
    <div className="flex gap-2">
      <button
        disabled={disabled || running}
        onClick={() => {
          launchAttack()
          if (big) setView('overview')
        }}
        className={cx(
          'btn-press relative flex-1 overflow-hidden rounded-lg font-semibold tracking-[0.14em]',
          big ? 'py-3 text-[12.5px]' : 'py-2.5 text-[11.5px]',
          running
            ? 'sweep cursor-default bg-threat/15 text-threat ring-1 ring-threat/50'
            : isNormal
              ? 'bg-ok/12 text-ok ring-1 ring-ok/40 hover:bg-ok/20'
              : 'bg-threat text-white shadow-[0_8px_30px_-8px_rgba(255,79,94,0.6)] hover:brightness-110',
          disabled && !running && 'opacity-40',
        )}
      >
        {running && (
          <motion.span
            className="absolute inset-y-0 left-0 bg-threat/20"
            initial={false}
            animate={{ width: `${level * 100}%` }}
            transition={{ duration: 0.5 }}
          />
        )}
        <span className="relative">
          {running ? (phase === 'ramp' ? 'SIMULATION ESCALATING' : 'SIMULATION ACTIVE') : isNormal ? 'RUN NORMAL TRAFFIC' : 'LAUNCH SIMULATION'}
        </span>
      </button>
      <button
        disabled={!running || disabled}
        onClick={() => stopAttack()}
        className={cx(
          'btn-press rounded-lg px-4 font-semibold tracking-[0.14em] ring-1',
          big ? 'text-[12.5px]' : 'text-[11.5px]',
          running ? 'bg-s3 text-ink ring-line-2 hover:bg-s4' : 'text-ink-4 ring-line',
        )}
      >
        STOP
      </button>
    </div>
  )
}

/** Large scenario card used on the Attack Simulator page. */
export function ScenarioCard({ attack, index }: { attack: AttackType; index: number }) {
  const scenario = useSentinel((s) => s.scenario)
  const { running, active } = useSimState()
  const demo = useSentinel((s) => s.demo.running)
  const meta = SCENARIOS[attack]
  const on = scenario.attack === attack
  const live = running && active === attack
  const accent = attack === 'normal' ? HEX.ok : HEX.threat

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      whileHover={{ y: -3 }}
      onClick={() => !demo && setScenario({ attack })}
      className={cx(
        'group relative flex cursor-pointer flex-col overflow-hidden rounded-xl border p-4 transition-colors',
        on ? 'bg-s2' : 'border-line bg-s1 hover:border-line-2',
      )}
      style={on ? { borderColor: `${accent}66`, boxShadow: `0 0 0 1px ${accent}22, 0 20px 50px -25px ${accent}55` } : undefined}
    >
      <div
        className="pointer-events-none absolute -top-16 -right-16 h-40 w-40 rounded-full opacity-0 blur-3xl transition-opacity duration-500 group-hover:opacity-100"
        style={{ background: `${accent}22`, opacity: on ? 1 : undefined }}
      />
      <div className="relative flex items-start justify-between">
        <div className="grid h-9 w-9 place-items-center rounded-lg border border-line bg-env/60" style={{ color: on ? accent : HEX.ink3 }}>
          <TacticIcon attack={attack} size={18} />
        </div>
        {live ? (
          <span className="mono flex items-center gap-1.5 text-[10px] tracking-[0.16em] text-threat">
            <span className="h-1.5 w-1.5 animate-blink rounded-full bg-threat" /> LIVE
          </span>
        ) : (
          meta.mitre && <span className="mono text-[10px] text-ink-4">{meta.mitre}</span>
        )}
      </div>
      <div className="relative mt-4 text-[15px] font-semibold tracking-wide text-ink">{meta.name.toUpperCase()}</div>
      <div className="relative eyebrow mt-1" style={{ color: on ? accent : undefined }}>{meta.tactic}</div>
      <p className="relative mt-3 text-[12.5px] leading-relaxed text-ink-2">{meta.description}</p>
      <ul className="relative mt-3 space-y-1">
        {meta.behaviours.map((b) => (
          <li key={b} className="flex items-center gap-2 text-[11.5px] text-ink-3">
            <span className="h-px w-2.5" style={{ background: on ? accent : 'rgba(255,255,255,0.2)' }} />
            {b}
          </li>
        ))}
      </ul>
      <div className="relative mt-4 grid grid-cols-2 gap-2 border-t border-line pt-3">
        <div>
          <div className="eyebrow text-[9.5px]">Source</div>
          <div className="mono mt-0.5 text-[11.5px] text-ink">{meta.source}</div>
        </div>
        <div>
          <div className="eyebrow text-[9.5px]">Target</div>
          <div className="mono mt-0.5 text-[11.5px] text-ink">{meta.target}</div>
        </div>
      </div>
      <div className="relative mt-3 text-[11px] text-ink-3">
        <span className="text-ink-4">Detector keys on · </span>
        {meta.signature}
      </div>
      <div className="relative mt-auto pt-4">
        <button
          disabled={running || demo}
          onClick={(e) => {
            e.stopPropagation()
            launchAttack({ attack })
            setView('overview')
          }}
          className={cx(
            'btn-press w-full rounded-lg py-2 text-[11px] font-semibold tracking-[0.16em] ring-1 disabled:opacity-40',
            on ? 'text-white' : 'text-ink-2 ring-line-2 hover:text-ink',
          )}
          style={on ? { background: attack === 'normal' ? `${HEX.ok}30` : HEX.threat, boxShadow: 'none' } : undefined}
        >
          {live ? 'RUNNING…' : 'SIMULATE'}
        </button>
      </div>
    </motion.div>
  )
}

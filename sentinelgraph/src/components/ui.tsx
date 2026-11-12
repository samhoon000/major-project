import { animate, motion } from 'framer-motion'
import { useEffect, useRef, type ReactNode } from 'react'

export function cx(...xs: (string | false | null | undefined)[]) {
  return xs.filter(Boolean).join(' ')
}

/** Smoothly counts between values instead of snapping. */
export function AnimatedNumber({
  value,
  format = (n) => Math.round(n).toLocaleString('en-US'),
  duration = 0.6,
  className,
  from,
}: {
  value: number
  format?: (n: number) => string
  duration?: number
  className?: string
  /** start value for the first count-up (defaults to no initial animation) */
  from?: number
}) {
  const ref = useRef<HTMLSpanElement>(null)
  const prev = useRef(from ?? value)
  useEffect(() => {
    const from = prev.current
    prev.current = value
    const c = animate(from, value, {
      duration,
      ease: [0.2, 0.7, 0.2, 1],
      onUpdate: (v) => {
        if (ref.current) ref.current.textContent = format(v)
      },
    })
    return () => c.stop()
  }, [value, duration, format])
  return (
    <span ref={ref} className={className}>
      {format(from ?? value)}
    </span>
  )
}

export function StatusDot({ color, pulse = false, size = 7 }: { color: string; pulse?: boolean; size?: number }) {
  return (
    <span className="relative inline-flex shrink-0" style={{ width: size, height: size }}>
      {pulse && (
        <span className="absolute inset-0 rounded-full animate-pulse-ring" style={{ background: color }} />
      )}
      <span className="relative inline-flex rounded-full" style={{ width: size, height: size, background: color, boxShadow: `0 0 10px ${color}66` }} />
    </span>
  )
}

export function Eyebrow({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx('eyebrow', className)}>{children}</div>
}

export function PanelHeader({ title, right, sub }: { title: ReactNode; right?: ReactNode; sub?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 px-4 pt-3.5 pb-2.5">
      <div className="min-w-0">
        <div className="eyebrow text-ink-2">{title}</div>
        {sub && <div className="mt-0.5 text-[11px] text-ink-3">{sub}</div>}
      </div>
      {right}
    </div>
  )
}

export function Segmented<T extends string | number>({
  options,
  value,
  onChange,
  size = 'md',
  tone = 'ai',
  disabled,
  label,
}: {
  options: { value: T; label: ReactNode }[]
  value: T
  onChange: (v: T) => void
  size?: 'sm' | 'md'
  tone?: 'ai' | 'threat'
  disabled?: boolean
  label?: string
}) {
  const active = tone === 'threat' ? 'var(--color-threat)' : 'var(--color-ai)'
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cx('relative flex rounded-lg border border-line bg-s2 p-0.5', disabled && 'opacity-50 pointer-events-none')}
    >
      {options.map((o) => {
        const on = o.value === value
        return (
          <button
            key={String(o.value)}
            role="radio"
            aria-checked={on}
            onClick={() => onChange(o.value)}
            className={cx(
              'btn-press relative flex-1 rounded-md font-medium tracking-wide',
              size === 'sm' ? 'px-2 py-1 text-[10.5px]' : 'px-2.5 py-1.5 text-[11.5px]',
              on ? 'text-ink' : 'text-ink-3 hover:text-ink-2',
            )}
          >
            {on && (
              <motion.span
                layoutId={`seg-${label}`}
                className="absolute inset-0 rounded-md bg-s4"
                style={{ boxShadow: `inset 0 0 0 1px ${active}40` }}
                transition={{ type: 'spring', stiffness: 500, damping: 38 }}
              />
            )}
            <span className="relative">{o.label}</span>
          </button>
        )
      })}
    </div>
  )
}

/** Horizontal meter with animated fill. */
export function Meter({ value, color, height = 4, delay = 0 }: { value: number; color: string; height?: number; delay?: number }) {
  return (
    <div className="relative w-full overflow-hidden rounded-full bg-white/[0.05]" style={{ height }}>
      <motion.div
        className="absolute inset-y-0 left-0 rounded-full"
        style={{ background: color, boxShadow: `0 0 12px ${color}55` }}
        initial={false}
        animate={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }}
        transition={{ duration: 0.7, ease: [0.2, 0.7, 0.2, 1], delay }}
      />
    </div>
  )
}

export function Tag({ children, color }: { children: ReactNode; color: string }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 text-[10px] font-semibold tracking-[0.12em] uppercase"
      style={{ color, background: `${color}14`, boxShadow: `inset 0 0 0 1px ${color}30` }}
    >
      {children}
    </span>
  )
}

export function KV({ k, v, mono = true, color }: { k: ReactNode; v: ReactNode; mono?: boolean; color?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5 text-[12px]">
      <span className="text-ink-3">{k}</span>
      <span className={cx('text-right text-ink', mono && 'mono tnum')} style={color ? { color } : undefined}>
        {v}
      </span>
    </div>
  )
}

export function IconButton({ children, onClick, label, active }: { children: ReactNode; onClick: () => void; label: string; active?: boolean }) {
  return (
    <button
      aria-label={label}
      title={label}
      onClick={onClick}
      className={cx(
        'btn-press grid h-7 w-7 place-items-center rounded-md border text-ink-2 hover:text-ink',
        active ? 'border-ai/40 bg-ai/10 text-ai' : 'border-line bg-s2/80 hover:border-line-2',
      )}
    >
      {children}
    </button>
  )
}

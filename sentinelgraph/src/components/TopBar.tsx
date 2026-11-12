import { AnimatePresence, motion } from 'framer-motion'
import { useState } from 'react'
import { HEX } from '../lib/format'
import { runDemo, setEngineMode, setView, stopDemo, togglePresentation } from '../store/runtime'
import { useSentinel, type View } from '../store/store'
import { StatusDot, cx } from './ui'

const NAV: { id: View; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'simulator', label: 'Attack Simulator' },
  { id: 'graph', label: 'Network Graph' },
  { id: 'engine', label: 'Detection Engine' },
  { id: 'incidents', label: 'Incidents' },
]

export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <g fill="none" stroke={HEX.ai} strokeWidth="1.4">
        <path d="M16 3.5 27 9.8v12.4L16 28.5 5 22.2V9.8Z" opacity=".45" />
        <path d="M16 9v7l6 3.5M16 16l-6 3.5" opacity=".9" />
      </g>
      <circle cx="16" cy="16" r="2.6" fill={HEX.ai} />
      <circle cx="16" cy="9" r="1.7" fill="#e6ebed" />
      <circle cx="22" cy="19.5" r="1.7" fill="#e6ebed" />
      <circle cx="10" cy="19.5" r="1.7" fill={HEX.threat} />
    </svg>
  )
}

export function TopBar() {
  const status = useSentinel((s) => s.networkStatus)
  const presentation = useSentinel((s) => s.presentation)
  const demo = useSentinel((s) => s.demo.running)

  const threat = status === 'UNDER ATTACK'
  const netColor = threat ? HEX.threat : status === 'ELEVATED' || status === 'RECOVERING' ? HEX.warn : HEX.ok
  const netLabel = threat ? 'THREAT ACTIVE' : status === 'RECOVERING' ? 'RECOVERING' : status === 'ELEVATED' ? 'ELEVATED' : 'SYSTEM SECURE'

  return (
    <>
    <header className="relative z-30 flex h-14 shrink-0 items-center gap-4 border-b border-line bg-env/80 px-4 backdrop-blur-xl lg:px-5">
      <button onClick={() => setView('overview')} className="flex shrink-0 items-center gap-2.5" aria-label="SentinelGraph home">
        <Logo />
        <div className="text-left leading-none">
          <div className="text-[13.5px] font-semibold tracking-[0.24em] text-ink">SENTINELGRAPH</div>
          <div className="mt-1 hidden text-[10px] tracking-[0.08em] text-ink-3 min-[1700px]:block">Graph-Based Network Intrusion Detection</div>
        </div>
      </button>

      {!presentation && <NavTabs id="nav-inline" className="ml-2 hidden min-[1600px]:flex" />}

      <div className="ml-auto flex shrink-0 items-center gap-2.5">
        <EngineSwitch />

        <motion.div
          layout
          className="flex items-center gap-2 rounded-full px-3 py-1.5"
          style={{ background: `${netColor}12`, boxShadow: `inset 0 0 0 1px ${netColor}38` }}
        >
          <span className="hidden items-center gap-2 border-r border-line-2 pr-2.5 min-[1600px]:flex" style={presentation ? { display: 'flex' } : undefined}>
            <StatusDot color={HEX.ok} size={6} />
            <span className="text-[10.5px] font-semibold tracking-[0.16em] text-ink-2">SYSTEM ONLINE</span>
          </span>
          <StatusDot color={netColor} pulse={threat} size={6} />
          <AnimatePresence mode="wait">
            <motion.span
              key={netLabel}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              className="text-[10.5px] font-semibold tracking-[0.16em]"
              style={{ color: netColor }}
            >
              {netLabel}
            </motion.span>
          </AnimatePresence>
        </motion.div>

        <button
          onClick={() => togglePresentation()}
          className={cx(
            'btn-press hidden rounded-lg border px-3 py-1.5 text-[11px] font-semibold tracking-[0.12em] md:block',
            presentation ? 'border-ai/40 bg-ai/10 text-ai' : 'border-line text-ink-2 hover:border-line-2 hover:text-ink',
          )}
          title="Presentation mode (P)"
        >
          {presentation ? 'EXIT PRESENTATION' : 'PRESENTATION'}
        </button>

        <button
          onClick={() => (demo ? stopDemo() : void runDemo())}
          className={cx(
            'btn-press group relative overflow-hidden rounded-lg px-3.5 py-1.5 text-[11px] font-semibold tracking-[0.12em]',
            demo ? 'bg-threat/15 text-threat ring-1 ring-threat/40' : 'bg-ai text-env hover:brightness-110',
          )}
          title="Run the scripted 10-phase demo (D)"
        >
          {demo ? '■ STOP DEMO' : '▶ RUN FULL DEMO'}
        </button>
      </div>
    </header>
    {!presentation && (
      <div className="relative z-20 flex items-center border-b border-line bg-env/80 px-3 py-1.5 backdrop-blur-xl min-[1600px]:hidden">
        <NavTabs id="nav-row" className="flex" />
        <span className="ml-auto hidden shrink-0 items-center gap-2 pr-2 sm:flex">
          <StatusDot color={HEX.ok} size={6} />
          <span className="text-[10.5px] font-semibold tracking-[0.16em] text-ink-2">SYSTEM ONLINE</span>
        </span>
      </div>
    )}
    </>
  )
}

function NavTabs({ id, className }: { id: string; className?: string }) {
  const view = useSentinel((s) => s.view)
  const incidents = useSentinel((s) => s.incidents.filter((i) => i.status === 'ACTIVE').length)
  return (
    <nav className={cx('scroll-thin min-w-0 items-center gap-0.5 overflow-x-auto', className)} aria-label="Primary">
      {NAV.map((n) => (
        <button
          key={n.id}
          onClick={() => setView(n.id)}
          className={cx(
            'btn-press relative shrink-0 rounded-md px-3 py-1.5 text-[12.5px] font-medium',
            view === n.id ? 'text-ink' : 'text-ink-3 hover:text-ink-2',
          )}
          aria-current={view === n.id ? 'page' : undefined}
        >
          {view === n.id && (
            <motion.span layoutId={id} className="absolute inset-0 rounded-md bg-white/[0.06]" transition={{ type: 'spring', stiffness: 500, damping: 40 }} />
          )}
          <span className="relative flex items-center gap-1.5">
            {n.label}
            {n.id === 'incidents' && incidents > 0 && <span className="mono rounded bg-threat/15 px-1 text-[10px] text-threat">{incidents}</span>}
          </span>
        </button>
      ))}
    </nav>
  )
}

function EngineSwitch() {
  const mode = useSentinel((s) => s.engineMode)
  const status = useSentinel((s) => s.modelStatus)
  const url = useSentinel((s) => s.modelUrl)
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState(url)

  const label = mode === 'simulation' ? 'SIMULATION MODE' : status === 'online' ? 'MODEL MODE' : status === 'offline' ? 'MODEL OFFLINE' : 'CONNECTING'
  const color = mode === 'simulation' ? HEX.ai : status === 'online' ? HEX.ok : status === 'offline' ? HEX.warn : HEX.ai

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="btn-press flex items-center gap-2 rounded-lg border border-line px-2.5 py-1.5 hover:border-line-2"
        aria-expanded={open}
      >
        <span className="h-1.5 w-1.5 rounded-sm" style={{ background: color }} />
        <span className="text-[10.5px] font-semibold tracking-[0.14em]" style={{ color }}>{label}</span>
        <svg width="8" height="8" viewBox="0 0 8 8" className="text-ink-3"><path d="M1 2.5l3 3 3-3" stroke="currentColor" fill="none" strokeWidth="1.2" /></svg>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.15 }}
            className="absolute right-0 top-10 w-[340px] rounded-xl border border-line-2 bg-s2 p-3 shadow-2xl"
          >
            <div className="eyebrow mb-2">Detection backend</div>
            <button
              onClick={() => {
                setEngineMode('simulation')
                setOpen(false)
              }}
              className={cx('btn-press mb-1.5 w-full rounded-lg border p-2.5 text-left', mode === 'simulation' ? 'border-ai/40 bg-ai/[0.07]' : 'border-line hover:border-line-2')}
            >
              <div className="text-[12px] font-semibold text-ink">Simulation Mode</div>
              <div className="mt-0.5 text-[11px] leading-snug text-ink-3">
                Inference is simulated in the browser using feature heuristics and GAT-style attention. It does not run the trained PyTorch model.
              </div>
            </button>
            <div className={cx('rounded-lg border p-2.5', mode === 'model' ? 'border-ok/40 bg-ok/[0.06]' : 'border-line')}>
              <div className="text-[12px] font-semibold text-ink">Model Mode</div>
              <div className="mt-0.5 text-[11px] leading-snug text-ink-3">
                Sends each batch of flows to your GATv2 service (<span className="mono">POST /api/analyze</span>). Falls back to simulation while the service is unreachable.
              </div>
              <div className="mt-2 flex gap-1.5">
                <input
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  className="mono min-w-0 flex-1 rounded-md border border-line bg-env px-2 py-1 text-[11px] text-ink outline-none focus:border-ai/50"
                  aria-label="Model API URL"
                />
                <button
                  onClick={() => {
                    setEngineMode('model', draft)
                    setOpen(false)
                  }}
                  className="btn-press rounded-md bg-ok/15 px-2.5 text-[11px] font-semibold text-ok ring-1 ring-ok/30"
                >
                  Connect
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

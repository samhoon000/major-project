import { AnimatePresence, motion } from 'framer-motion'
import { useEffect } from 'react'
import { Logo, TopBar } from './components/TopBar'
import { ATTACK_ORDER } from './engine/scenarios'
import { boot, dismissAlert, launchAttack, runDemo, select, setScenario, stopAttack, stopDemo, togglePresentation } from './store/runtime'
import { get, useSentinel } from './store/store'
import { EngineView } from './views/EngineView'
import { GraphView } from './views/GraphView'
import { IncidentsView } from './views/IncidentsView'
import { OverviewView } from './views/OverviewView'
import { SimulatorView } from './views/SimulatorView'

export default function App() {
  const ready = useSentinel((s) => s.ready)
  const view = useSentinel((s) => s.view)
  const threat = useSentinel((s) => s.networkStatus === 'UNDER ATTACK')

  useEffect(() => {
    void boot()
  }, [])

  // Keyboard: D demo · P presentation · Space launch/stop · 1–6 scenario · Esc close
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement
      if (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || e.metaKey || e.ctrlKey || e.altKey) return
      const s = get()
      if (e.key === 'Escape') {
        if (s.selection) select(null)
        else dismissAlert()
      } else if (e.key === 'd' || e.key === 'D') {
        if (s.demo.running) stopDemo()
        else void runDemo()
      } else if (e.key === 'p' || e.key === 'P') {
        togglePresentation()
      } else if (e.key === ' ' && t.tagName !== 'BUTTON') {
        e.preventDefault()
        if (s.demo.running) return
        if (s.simPhase === 'ramp' || s.simPhase === 'active') stopAttack()
        else launchAttack()
      } else if (/^[1-6]$/.test(e.key) && !s.demo.running) {
        setScenario({ attack: ATTACK_ORDER[Number(e.key) - 1] })
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="relative min-h-full">
      <div className={`atmosphere ${threat ? 'alert' : ''}`} />
      <TopBar />
      <AnimatePresence mode="wait">
        {!ready ? (
          <motion.div key="boot" exit={{ opacity: 0 }} className="relative z-10 grid h-[calc(100vh-56px)] place-items-center">
            <div className="flex flex-col items-center gap-3">
              <motion.div animate={{ rotate: 360 }} transition={{ duration: 6, repeat: Infinity, ease: 'linear' }}>
                <Logo size={44} />
              </motion.div>
              <div className="eyebrow">Building network graph…</div>
            </div>
          </motion.div>
        ) : (
          <motion.div
            key={view}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.25, ease: [0.2, 0.7, 0.2, 1] }}
          >
            {view === 'overview' && <OverviewView />}
            {view === 'simulator' && <SimulatorView />}
            {view === 'graph' && <GraphView />}
            {view === 'engine' && <EngineView />}
            {view === 'incidents' && <IncidentsView />}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

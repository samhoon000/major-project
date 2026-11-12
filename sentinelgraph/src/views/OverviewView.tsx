import { motion } from 'framer-motion'
import { AnomalyChart } from '../components/charts/Charts'
import { DetectionPipeline } from '../components/DetectionPipeline'
import { GraphStage } from '../components/graph/GraphStage'
import { IncidentFeed } from '../components/IncidentFeed'
import { ModelExplanation } from '../components/ModelExplanation'
import { KpiStrip, StoryStepper } from '../components/Overlays'
import { SimulatorConsole } from '../components/Simulator'
import { ThreatGauge } from '../components/ThreatGauge'
import { ThreatTimeline } from '../components/ThreatTimeline'
import { cx } from '../components/ui'
import { HEX } from '../lib/format'
import { clearIncidents } from '../store/runtime'
import { useSentinel } from '../store/store'

export function OverviewView() {
  const presentation = useSentinel((s) => s.presentation)
  const incidents = useSentinel((s) => s.incidents.length)

  return (
    <div className={cx('relative z-10 grid min-h-[calc(100vh-56px)] grid-cols-1', presentation ? 'lg:grid-cols-[280px_minmax(0,1fr)]' : 'lg:grid-cols-[304px_minmax(0,1fr)]')}>
      {/* ── left rail: control + result ───────────────────────────── */}
      <aside className="flex min-w-0 flex-col border-line md:grid md:grid-cols-2 lg:flex lg:border-r">
        <section className="px-5 pt-5 pb-4">
          <ThreatGauge large={presentation} />
        </section>
        <section className="border-t border-line px-5 py-4 md:border-t-0 md:border-l lg:border-t lg:border-l-0">
          <SimulatorConsole />
        </section>
        {!presentation && (
          <section className="flex min-h-[260px] flex-1 flex-col border-t border-line md:col-span-2 lg:min-h-0">
            <div className="flex items-center justify-between px-5 pt-4 pb-2.5">
              <div className="eyebrow text-ink-2">
                Incidents <span className="mono ml-1 text-ink-3">{incidents}</span>
              </div>
              {incidents > 0 && (
                <button onClick={clearIncidents} className="btn-press text-[10px] tracking-[0.14em] text-ink-4 hover:text-ink-2">
                  CLEAR
                </button>
              )}
            </div>
            <div className="scroll-thin max-h-[320px] flex-1 overflow-y-auto px-4 pb-4 lg:max-h-[calc(100vh-56px-560px)] lg:min-h-[180px]">
              <IncidentFeed />
            </div>
          </section>
        )}
      </aside>

      {/* ── main: graph is the hero ───────────────────────────────── */}
      <main className="flex min-w-0 flex-col">
        <div className="flex flex-wrap items-end justify-between gap-x-8 gap-y-3 px-6 pt-5 pb-4">
          <div className="min-w-0">
            <div className="eyebrow flex items-center gap-2">
              <span className="h-px w-5 bg-ai/60" /> See the network. Understand the threat.
            </div>
            <h1 className={cx('mt-2 font-semibold tracking-[-0.01em] text-ink', presentation ? 'text-[30px] leading-tight' : 'text-[21px] leading-snug')}>
              Model network communication as a graph.{' '}
              <span className="text-ink-3">Detect the relationships that look dangerous.</span>
            </h1>
          </div>
          {presentation ? <StoryStepper /> : <PipelineChips />}
        </div>

        <div className="px-2 pb-4">
          <KpiStrip large={presentation} />
        </div>

        <div className={cx('relative mx-4', presentation ? 'h-[clamp(480px,66vh,860px)]' : 'h-[clamp(440px,58vh,720px)]')}>
          <GraphStage />
        </div>

        <div className="panel mx-4 mt-3 px-4 pt-3 pb-2.5">
          <ThreatTimeline compact={presentation} />
        </div>

        <div className={cx('mx-4 mt-3 mb-5 grid gap-3', presentation ? 'xl:grid-cols-[1fr_1.35fr]' : 'xl:grid-cols-[1fr_1.35fr_0.8fr]')}>
          <div className="panel flex flex-col">
            <div className="flex items-start justify-between px-4 pt-3.5">
              <div>
                <div className="eyebrow text-ink-2">Anomaly signal</div>
                <div className="mt-0.5 text-[11px] text-ink-3">Highest edge anomaly probability · last 60 s</div>
              </div>
            </div>
            <div className="flex-1 px-1 pt-1 pb-2">
              <AnomalyChart height={presentation ? 260 : 220} />
            </div>
          </div>
          <div className="panel">
            <ModelExplanation />
          </div>
          {!presentation && (
            <div className="panel">
              <DetectionPipeline />
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

/** NETWORK → GRAPH → AI DETECTION → THREAT, lit according to live state. */
function PipelineChips() {
  const status = useSentinel((s) => s.networkStatus)
  const active = useSentinel((s) => s.inference.active)
  const threat = status === 'UNDER ATTACK'
  const chips = [
    { k: 'Network', c: HEX.ok, on: true },
    { k: 'Graph', c: HEX.ok, on: true },
    { k: 'AI detection', c: HEX.ai, on: active },
    { k: 'Threat', c: HEX.threat, on: threat },
  ]
  return (
    <div className="flex items-center gap-1.5" aria-label="Pipeline">
      {chips.map((ch, i) => (
        <div key={ch.k} className="flex items-center gap-1.5">
          <motion.span
            animate={{ opacity: ch.on ? 1 : 0.35 }}
            className="rounded-md px-2.5 py-1 text-[10px] font-semibold tracking-[0.16em] uppercase"
            style={{ color: ch.on ? ch.c : HEX.ink3, boxShadow: `inset 0 0 0 1px ${ch.on ? ch.c + '40' : 'rgba(255,255,255,0.08)'}`, background: ch.on ? ch.c + '0d' : 'transparent' }}
          >
            {ch.k}
          </motion.span>
          {i < chips.length - 1 && (
            <svg width="16" height="6" viewBox="0 0 16 6" aria-hidden>
              <path d="M0 3h13M11 1l2 2-2 2" stroke="rgba(255,255,255,0.25)" fill="none" strokeWidth="1" />
            </svg>
          )}
        </div>
      ))}
    </div>
  )
}

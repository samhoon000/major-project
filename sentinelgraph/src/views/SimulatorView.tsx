import { DatasetReplay } from '../components/DatasetReplay'
import { LaunchControls, PhaseBadge, ScenarioCard } from '../components/Simulator'
import { ThreatGauge } from '../components/ThreatGauge'
import { Segmented } from '../components/ui'
import { ATTACK_ORDER, SCENARIOS } from '../engine/scenarios'
import { setScenario } from '../store/runtime'
import { useSentinel } from '../store/store'

export function SimulatorView() {
  const scenario = useSentinel((s) => s.scenario)
  const phase = useSentinel((s) => s.simPhase)
  const level = useSentinel((s) => s.attackLevel)
  const demo = useSentinel((s) => s.demo.running)
  const running = phase === 'ramp' || phase === 'active'
  const meta = SCENARIOS[scenario.attack]

  return (
    <div className="relative z-10 mx-auto grid max-w-[1600px] gap-5 p-5 xl:grid-cols-[minmax(0,1fr)_380px]">
      <section>
        <div className="mb-5">
          <div className="eyebrow">Attack simulator</div>
          <h1 className="mt-2 text-[24px] font-semibold text-ink">Choose a scenario. Watch the graph react.</h1>
          <p className="mt-1 max-w-[680px] text-[13px] leading-relaxed text-ink-3">
            Every scenario is generated inside your browser as synthetic flow records. Nothing is sent on the network and no machine is
            attacked. The detector only sees flow statistics, as it would from a flow collector.
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 2xl:grid-cols-3">
          {ATTACK_ORDER.map((a, i) => (
            <ScenarioCard key={a} attack={a} index={i} />
          ))}
        </div>
      </section>

      <aside className="flex flex-col gap-4">
        <div className="panel p-4">
          <div className="flex items-center justify-between">
            <div className="eyebrow text-ink-2">Control console</div>
            <PhaseBadge />
          </div>
          <div className="mt-3 text-[15px] font-semibold text-ink">{meta.name}</div>
          <div className="mono text-[11px] text-ink-3">
            {meta.source} → {meta.target}
          </div>
          <div className="mt-4 grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-2.5">
            <span className="eyebrow">Intensity</span>
            <Segmented
              label="intensity-page"
              tone="threat"
              disabled={running || demo}
              value={scenario.intensity}
              onChange={(v) => setScenario({ intensity: v })}
              options={[
                { value: 'LOW', label: 'LOW' },
                { value: 'MEDIUM', label: 'MEDIUM' },
                { value: 'HIGH', label: 'HIGH' },
              ]}
            />
            <span className="eyebrow">Duration</span>
            <Segmented
              label="duration-page"
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
          <div className="mt-4">
            <LaunchControls running={running} phase={phase} level={level} disabled={demo} isNormal={scenario.attack === 'normal'} big />
          </div>
          <div className="mt-5 border-t border-line pt-4">
            <ThreatGauge />
          </div>
        </div>
        <div className="panel p-4">
          <DatasetReplay />
        </div>
      </aside>
    </div>
  )
}

import { HEX } from '../../lib/format'
import { useSentinel } from '../../store/store'
import { Inspector } from '../Inspector'
import { DemoHud } from '../Overlays'
import { SummaryModal } from '../SummaryModal'
import { ThreatAlert } from '../ThreatAlert'
import { cx } from '../ui'
import { NetworkGraph } from './NetworkGraph'

/** The graph plus everything that floats over it. */
export function GraphStage({ className }: { className?: string }) {
  const threat = useSentinel((s) => s.networkStatus === 'UNDER ATTACK')
  const source = useSentinel((s) => s.source)
  const replay = useSentinel((s) => s.replay)
  const demo = useSentinel((s) => s.demo.running)

  return (
    <div
      className={cx(
        'relative h-full w-full overflow-hidden rounded-2xl border bg-[radial-gradient(ellipse_at_50%_45%,#0e1418_0%,#090c0e_70%)] transition-[border-color,box-shadow] duration-700',
        threat ? 'border-threat/30 shadow-[0_0_80px_-30px_rgba(255,79,94,0.35)_inset]' : 'border-line',
        className,
      )}
    >
      <NetworkGraph />

      {/* corner readouts */}
      <div className="pointer-events-none absolute top-3 right-4 z-10 flex items-center gap-3 text-[10px] tracking-[0.16em] text-ink-3">
        <span className="mono">{source === 'replay' ? `REPLAY · ${replay.info.name.toUpperCase()} · ${replay.speed}×` : 'LIVE · SIMULATED TRAFFIC'}</span>
        <span className="mono text-ink-4">WINDOW 8s</span>
      </div>

      {!demo && <Legend />}
      <ThreatAlert />
      <Inspector />
      <DemoHud />
      <SummaryModal />
    </div>
  )
}

function Legend() {
  const items = [
    { c: '#8fa3ad', label: 'Normal flow', w: 1, o: 0.5 },
    { c: HEX.warn, label: 'Suspicious', w: 2, o: 0.9 },
    { c: HEX.threat, label: 'Anomalous', w: 3.5, o: 1 },
  ]
  return (
    <div className="pointer-events-none absolute bottom-3 left-4 z-10 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10.5px] text-ink-3">
      {items.map((i) => (
        <span key={i.label} className="flex items-center gap-1.5">
          <svg width="20" height="6" aria-hidden><line x1="0" y1="3" x2="20" y2="3" stroke={i.c} strokeWidth={i.w} strokeOpacity={i.o} /></svg>
          {i.label}
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <svg width="12" height="12" aria-hidden><circle cx="6" cy="6" r="4.5" fill="none" stroke={HEX.ok} strokeOpacity={0.7} /></svg>
        Host
      </span>
      <span className="text-ink-4">Edge width = traffic · scroll to zoom · drag to pan</span>
    </div>
  )
}

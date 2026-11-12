import { TopHosts } from '../components/charts/Charts'
import { GraphStage } from '../components/graph/GraphStage'
import { ThreatTimeline } from '../components/ThreatTimeline'
import { fmtCompact, fmtPct, riskColor } from '../lib/format'
import { focusOn, select } from '../store/runtime'
import { useSentinel } from '../store/store'

export function GraphView() {
  const edges = useSentinel((s) => s.graph.edges)
  const thr = useSentinel((s) => s.threshold)
  const flagged = edges.filter((e) => e.anomaly >= 0.4).sort((a, b) => b.anomaly - a.anomaly).slice(0, 8)

  return (
    <div className="relative z-10 grid gap-4 p-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div className="flex min-w-0 flex-col gap-3">
        <div className="h-[calc(100vh-56px-150px)] min-h-[520px]">
          <GraphStage />
        </div>
        <div className="panel px-4 pt-3 pb-2.5">
          <ThreatTimeline compact />
        </div>
      </div>
      <aside className="flex flex-col gap-4">
        <div className="panel p-4">
          <div className="eyebrow mb-3 text-ink-2">Top suspicious hosts</div>
          <TopHosts limit={8} />
        </div>
        <div className="panel p-4">
          <div className="eyebrow mb-3 text-ink-2">Flagged relationships</div>
          {flagged.length === 0 ? (
            <div className="text-[11.5px] text-ink-3">No edge is above 0.40. Launch a simulation to populate this list.</div>
          ) : (
            <ul className="space-y-1">
              {flagged.map((e) => (
                <li key={e.id}>
                  <button
                    onClick={() => {
                      select({ kind: 'edge', id: e.id })
                      focusOn([e.source, e.target])
                    }}
                    className="btn-press w-full rounded-md px-2 py-1.5 text-left hover:bg-white/[0.04]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="mono truncate text-[11px] text-ink">
                        {e.source} → {e.target}
                      </span>
                      <span className="mono text-[11px]" style={{ color: riskColor(e.anomaly, thr) }}>
                        {fmtPct(e.anomaly, 0)}
                      </span>
                    </div>
                    <div className="mono text-[10px] text-ink-3">
                      {e.protocol} · {fmtCompact(e.pps)} pkt/s · α {e.attention.toFixed(2)}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="panel p-4 text-[11.5px] leading-relaxed text-ink-3">
          <div className="eyebrow mb-2 text-ink-2">Reading the graph</div>
          Nodes are hosts and edges are flows aggregated over the last 8 seconds. Edge colour is the anomaly probability, width is
          traffic volume, and the moving dots show direction. Click any host or edge to inspect it.
        </div>
      </aside>
    </div>
  )
}

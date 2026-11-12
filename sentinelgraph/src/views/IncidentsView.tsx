import { IncidentFeed } from '../components/IncidentFeed'
import { ThreatTimeline } from '../components/ThreatTimeline'
import { SCENARIOS } from '../engine/scenarios'
import { HEX, fmtPct, fmtTime, severityColor } from '../lib/format'
import { clearIncidents, investigate } from '../store/runtime'
import { useSentinel } from '../store/store'

export function IncidentsView() {
  const incidents = useSentinel((s) => s.incidents)
  const critical = incidents.filter((i) => i.severity === 'CRITICAL').length
  const active = incidents.filter((i) => i.status === 'ACTIVE').length

  return (
    <div className="relative z-10 mx-auto grid max-w-[1500px] gap-4 p-4 lg:grid-cols-[380px_minmax(0,1fr)]">
      <aside className="panel flex max-h-[calc(100vh-56px-32px)] flex-col">
        <div className="flex items-center justify-between px-4 pt-4 pb-3">
          <div>
            <div className="eyebrow text-ink-2">Incident feed</div>
            <div className="mt-0.5 text-[11px] text-ink-3">
              {incidents.length} total · {critical} critical · {active} active
            </div>
          </div>
          {incidents.length > 0 && (
            <button onClick={clearIncidents} className="btn-press text-[10px] tracking-[0.14em] text-ink-4 hover:text-ink-2">
              CLEAR
            </button>
          )}
        </div>
        <div className="scroll-thin flex-1 overflow-y-auto px-3 pb-3">
          <IncidentFeed limit={60} />
        </div>
      </aside>
      <section className="flex min-w-0 flex-col gap-4">
        <div className="panel px-5 pt-4 pb-3">
          <div className="eyebrow mb-3 text-ink-2">Threat timeline · current episode</div>
          <ThreatTimeline />
        </div>
        <div className="panel overflow-hidden">
          <div className="eyebrow px-5 pt-4 pb-3 text-ink-2">Incident history</div>
          <div className="scroll-thin overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-[12px]">
              <thead>
                <tr className="border-y border-line text-[10px] tracking-[0.14em] text-ink-3 uppercase">
                  {['Time', 'Severity', 'Detection', 'Source', 'Target', 'Risk', 'Attention', 'Status', ''].map((h) => (
                    <th key={h} className="px-4 py-2 font-semibold">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {incidents.length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-4 py-8 text-center text-ink-3">
                      No incidents recorded yet.
                    </td>
                  </tr>
                )}
                {incidents.map((i) => (
                  <tr key={i.id} className="border-b border-line hover:bg-white/[0.02]">
                    <td className="mono px-4 py-2.5 text-ink-3">{fmtTime(i.ts)}</td>
                    <td className="px-4 py-2.5 text-[10.5px] font-bold tracking-[0.12em]" style={{ color: severityColor(i.severity) }}>
                      {i.severity}
                    </td>
                    <td className="px-4 py-2.5 text-ink">
                      {i.title}
                      {i.attackClass !== 'normal' && <span className="ml-2 text-[10.5px] text-ink-3">{SCENARIOS[i.attackClass].tactic}</span>}
                    </td>
                    <td className="mono px-4 py-2.5 text-ink-2">{i.source}</td>
                    <td className="mono px-4 py-2.5 text-ink-2">{i.target}</td>
                    <td className="mono px-4 py-2.5" style={{ color: severityColor(i.severity) }}>
                      {fmtPct(i.risk, 1)}
                    </td>
                    <td className="mono px-4 py-2.5 text-ai">{i.attention.toFixed(2)}</td>
                    <td
                      className="px-4 py-2.5 text-[10.5px] font-semibold tracking-[0.12em]"
                      style={{ color: i.status === 'ACTIVE' ? HEX.threat : HEX.ok }}
                    >
                      {i.status}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        onClick={() => investigate({ incidentId: i.id })}
                        className="btn-press text-[10.5px] font-semibold tracking-[0.12em] text-ai hover:underline"
                      >
                        INVESTIGATE
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  )
}

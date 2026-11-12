import { useRef, useState } from 'react'
import { HEX, fmtInt, fmtPct } from '../lib/format'
import {
  loadCsv, pauseReplay, restartReplay, setReplaySpeed, skipReplayToAttack, startReplay, selectMockDataset, switchToSimulation,
} from '../store/runtime'
import { useSentinel } from '../store/store'
import { Meter, Segmented, Tag, cx } from './ui'

export function DatasetReplay() {
  const r = useSentinel((s) => s.replay)
  const source = useSentinel((s) => s.source)
  const demo = useSentinel((s) => s.demo.running)
  const fileRef = useRef<HTMLInputElement>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const active = source === 'replay'
  const progress = r.info.rows ? r.cursor / r.info.rows : 0
  const precision = r.tp + r.fp ? r.tp / (r.tp + r.fp) : 0
  const recall = r.tp + r.fn ? r.tp / (r.tp + r.fn) : 0
  const accuracy = r.tp + r.tn + r.fp + r.fn ? (r.tp + r.tn) / (r.tp + r.tn + r.fp + r.fn) : 0
  const labels = Object.entries(r.info.labels).sort((a, b) => b[1] - a[1]).slice(0, 6)
  const labelTotal = labels.reduce((a, [, n]) => a + n, 0) || 1

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="eyebrow text-ink-2">Dataset replay</div>
          <div className="mt-0.5 text-[11px] text-ink-3">Replay recorded flows through the same graph + detection pipeline</div>
        </div>
        {active ? <Tag color={HEX.ai}>Replay source</Tag> : <Tag color={HEX.ink3}>Inactive</Tag>}
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="eyebrow">Dataset</div>
          <div className="mt-1 truncate text-[15px] font-semibold text-ink" title={r.info.name}>{r.info.name}</div>
          <div className="text-[10.5px] text-ink-3">{r.info.origin === 'mock' ? 'Representative mock rows' : 'Local CSV · parsed in browser'}</div>
        </div>
        <div>
          <div className="eyebrow">Flows</div>
          <div className="mono mt-1 text-[15px] text-ink">{fmtInt(r.info.rows)}</div>
          <div className="text-[10.5px] text-ink-3">{fmtInt(r.cursor)} replayed</div>
        </div>
      </div>

      <div>
        <Meter value={progress} color={HEX.ai} height={4} />
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
          {labels.map(([l, n]) => (
            <span key={l} className="text-[10.5px] text-ink-3">
              <span className={cx('mono', l === 'BENIGN' ? 'text-ok' : 'text-threat')}>{l}</span> {fmtPct(n / labelTotal, 0)}
            </span>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-[auto_1fr] items-center gap-3">
        <span className="eyebrow">Replay speed</span>
        <Segmented
          label="replay-speed"
          size="sm"
          value={r.speed}
          onChange={(v) => setReplaySpeed(v)}
          options={[
            { value: 1, label: '1×' },
            { value: 5, label: '5×' },
            { value: 10, label: '10×' },
          ]}
        />
      </div>

      <div className="flex gap-2">
        <button
          disabled={demo}
          onClick={() => (r.playing ? pauseReplay() : startReplay())}
          className={cx(
            'btn-press flex-1 rounded-lg py-2.5 text-[11.5px] font-semibold tracking-[0.14em] disabled:opacity-40',
            r.playing ? 'sweep relative overflow-hidden bg-ai/15 text-ai ring-1 ring-ai/40' : 'bg-ai text-env hover:brightness-110',
          )}
        >
          {r.playing ? 'PAUSE REPLAY' : r.cursor > 0 && r.cursor < r.info.rows ? 'RESUME REPLAY' : 'START REPLAY'}
        </button>
        <button
          onClick={skipReplayToAttack}
          disabled={!active || r.info.origin !== 'mock'}
          title="Jump to the next labelled attack segment"
          className="btn-press rounded-lg px-3 text-[10.5px] font-semibold tracking-[0.12em] text-ink-2 ring-1 ring-line-2 hover:text-ink disabled:opacity-35"
        >
          SKIP →
        </button>
        <button
          onClick={restartReplay}
          className="btn-press rounded-lg px-3 text-[10.5px] font-semibold tracking-[0.12em] text-ink-2 ring-1 ring-line-2 hover:text-ink"
        >
          ↺
        </button>
      </div>

      {active && (
        <div className="grid grid-cols-4 gap-2 rounded-lg border border-line bg-s2/40 p-3">
          <Metric k="Ground truth" v={r.lastTruth} color={r.lastTruth === 'BENIGN' ? HEX.ok : HEX.threat} small />
          <Metric k="Precision" v={fmtPct(precision)} />
          <Metric k="Recall" v={fmtPct(recall)} />
          <Metric k="Accuracy" v={fmtPct(accuracy)} />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
        <input
          ref={fileRef}
          type="file"
          accept=".csv,text/csv"
          className="hidden"
          onChange={async (e) => {
            const f = e.target.files?.[0]
            if (!f) return
            setLoading(true)
            setError(await loadCsv(f))
            setLoading(false)
            e.target.value = ''
          }}
        />
        <button
          onClick={() => fileRef.current?.click()}
          className="btn-press rounded-md px-2.5 py-1.5 text-[11px] font-medium text-ink-2 ring-1 ring-line-2 hover:text-ink"
        >
          {loading ? 'Parsing…' : 'Load CICIDS CSV…'}
        </button>
        {r.info.origin === 'csv' && (
          <button onClick={selectMockDataset} className="btn-press rounded-md px-2.5 py-1.5 text-[11px] text-ink-3 hover:text-ink">
            Use built-in sample
          </button>
        )}
        {active && (
          <button onClick={switchToSimulation} className="btn-press ml-auto rounded-md px-2.5 py-1.5 text-[11px] text-ink-3 hover:text-ink">
            ← Back to simulator
          </button>
        )}
      </div>
      {error && <div className="text-[11px] text-warn">{error}</div>}
      <div className="text-[10.5px] leading-snug text-ink-4">
        Needs the CICIDS2017 columns: Source IP, Destination IP, Flow Duration, Total Fwd/Backward Packets, Flow Bytes/s, Flow Packets/s, Label. Up to 50,000 rows are read locally; nothing is uploaded.
      </div>
    </div>
  )
}

function Metric({ k, v, color, small }: { k: string; v: string; color?: string; small?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="eyebrow text-[9px]">{k}</div>
      <div className={cx('mono mt-1 truncate', small ? 'text-[11px]' : 'text-[13px]')} style={{ color: color ?? '#e6ebed' }}>{v}</div>
    </div>
  )
}

import type { ReactNode } from 'react'
import { Architecture } from '../components/Architecture'
import { AnomalyChart, NormalVsAnomalousChart, ProtocolBars, TopHosts, TrafficVolumeChart } from '../components/charts/Charts'
import { DetectionPipeline } from '../components/DetectionPipeline'
import { ModelExplanation } from '../components/ModelExplanation'
import { Tag } from '../components/ui'
import { HEX } from '../lib/format'
import { setEngineMode } from '../store/runtime'
import { useSentinel } from '../store/store'

function Block({ title, sub, children, className = '' }: { title: string; sub?: string; children: ReactNode; className?: string }) {
  return (
    <div className={`panel flex flex-col ${className}`}>
      <div className="px-4 pt-3.5 pb-2">
        <div className="eyebrow text-ink-2">{title}</div>
        {sub && <div className="mt-0.5 text-[11px] text-ink-3">{sub}</div>}
      </div>
      <div className="flex-1 px-3 pb-3">{children}</div>
    </div>
  )
}

export function EngineView() {
  const mode = useSentinel((s) => s.engineMode)
  const status = useSentinel((s) => s.modelStatus)
  const url = useSentinel((s) => s.modelUrl)

  return (
    <div className="relative z-10 mx-auto flex max-w-[1600px] flex-col gap-4 p-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="eyebrow">Detection engine</div>
          <h1 className="mt-2 text-[24px] font-semibold text-ink">From flows to an explainable verdict.</h1>
          <p className="mt-1 max-w-[760px] text-[13px] leading-relaxed text-ink-3">
            Flows become a graph, the graph is scored edge by edge, and attention shows which neighbours drove the decision.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {mode === 'simulation' ? (
            <Tag color={HEX.ai}>Simulation mode</Tag>
          ) : (
            <Tag color={status === 'online' ? HEX.ok : HEX.warn}>{status === 'online' ? 'Model mode · online' : 'Model mode · offline'}</Tag>
          )}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_1.2fr]">
        <div className="panel">
          <DetectionPipeline variant="full" />
        </div>
        <div className="panel">
          <ModelExplanation variant="full" />
        </div>
      </div>

      <div className="panel p-4">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <div>
            <div className="eyebrow text-ink-2">How it works</div>
            <div className="mt-0.5 text-[11px] text-ink-3">Click a stage to see where it lives in this prototype and in your Python project</div>
          </div>
        </div>
        <Architecture />
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <Block title="Traffic volume" sub="Flows per second">
          <TrafficVolumeChart height={170} />
        </Block>
        <Block title="Normal vs anomalous" sub="Flows per second by verdict">
          <NormalVsAnomalousChart height={150} />
        </Block>
        <Block title="Anomaly score" sub="Highest edge anomaly probability">
          <AnomalyChart height={180} />
        </Block>
        <Block title="Protocol distribution" sub="Last 10 seconds">
          <div className="px-1 pt-2">
            <ProtocolBars />
          </div>
        </Block>
        <Block title="Top suspicious hosts" sub="Ranked by node risk" className="xl:col-span-2">
          <TopHosts limit={6} />
        </Block>
      </div>

      <div className="panel grid gap-6 p-5 lg:grid-cols-[1fr_1.2fr]">
        <div>
          <div className="eyebrow text-ink-2">Connect the real GATv2 model</div>
          <p className="mt-2 text-[12.5px] leading-relaxed text-ink-2">
            The UI only depends on the <span className="mono text-ai">DetectionEngine</span> interface. In Simulation Mode it is backed by
            browser heuristics. Switch to Model Mode and every tick's flows are POSTed to your Python service, which builds the graph and
            runs <span className="mono">GNNAnomalyDetector</span> from <span className="mono">model.py</span>.
          </p>
          <ol className="mt-3 space-y-1.5 text-[12px] text-ink-3">
            <li>1. Add <span className="mono text-ink-2">POST /api/analyze</span> to <span className="mono text-ink-2">app.py</span> (contract on the right).</li>
            <li>2. Start it: <span className="mono text-ink-2">uvicorn app:app --port 8000</span></li>
            <li>3. Choose Model Mode in the header and connect to <span className="mono text-ink-2">{url}</span>.</li>
          </ol>
          <div className="mt-4 flex gap-2">
            <button
              onClick={() => setEngineMode(mode === 'model' ? 'simulation' : 'model')}
              className="btn-press rounded-lg border border-line-2 px-3 py-2 text-[11px] font-semibold tracking-[0.12em] text-ink hover:bg-white/5"
            >
              {mode === 'model' ? 'SWITCH TO SIMULATION MODE' : 'TRY MODEL MODE'}
            </button>
          </div>
        </div>
        <pre className="mono scroll-thin overflow-x-auto rounded-xl border border-line bg-env/70 p-4 text-[11px] leading-relaxed text-ink-2">
{`POST /api/analyze
{
  "flows": [{
    "flow_id": "f1a",
    "Source IP": "10.0.0.15",
    "Destination IP": "10.0.0.24",
    "Destination Port": 443,
    "Protocol": "6",
    "Flow Duration": 1200,          // µs
    "Total Fwd Packets": 2,
    "Total Backward Packets": 1,
    "Flow Bytes/s": 98000.0,
    "Flow Packets/s": 2500.0
  }]
}

→ 200 OK
{
  "threshold": 0.65,
  "results": [{
    "flow_id": "f1a",
    "anomaly_probability": 0.947,
    "attention": 0.91,                // optional
    "attack_class": "portscan",       // optional
    "signals": { "packetRate": 0.91 } // optional
  }]
}`}
        </pre>
      </div>
    </div>
  )
}

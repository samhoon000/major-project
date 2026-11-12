import { AnimatePresence, motion } from 'framer-motion'
import { useState } from 'react'
import { HEX } from '../lib/format'
import { useSentinel } from '../store/store'
import { cx } from './ui'

interface Box {
  id: string
  x: number
  y: number
  title: string
  sub: string
  simulated?: boolean
  detail: string
  browser: string
  python: string
}

const BOXES: Box[] = [
  { id: 'traffic', x: 70, y: 150, title: 'NETWORK TRAFFIC', sub: 'flows / CSV replay', detail: 'Raw network activity summarised as flows. In this prototype flows are synthesised or replayed from CICIDS2017-style rows — no packets are captured or sent.', browser: 'engine/simulationEngine.ts · engine/datasetReplay.ts', python: 'CICIDS2017 CSV · preprocess.py' },
  { id: 'features', x: 205, y: 150, title: 'FLOW FEATURES', sub: '5 numeric features', detail: 'Flow Duration, Total Fwd/Bwd Packets, Flow Bytes/s and Flow Packets/s — the same columns your preprocessing keeps.', browser: 'engine/types.ts (Flow)', python: 'preprocess.py' },
  { id: 'builder', x: 340, y: 150, title: 'GRAPH BUILDER', sub: 'hosts → nodes, flows → edges', detail: 'IPs become nodes, flows become directed edges. A sliding 8-second window adds graph context: fan-in, fan-out, port diversity, pair frequency.', browser: 'engine/graphEngine.ts', python: 'graph_builder.py' },
  { id: 'node', x: 475, y: 85, title: 'NODE FEATURES', sub: 'mean flow stats per host', detail: 'Each host is described by the average behaviour of the flows it sends and receives (standard-scaled).', browser: 'graphEngine.observe()', python: 'graph_builder.py · node_df' },
  { id: 'edge', x: 475, y: 215, title: 'EDGE FEATURES', sub: 'per-flow, scaled', detail: 'Each edge carries its own scaled flow features, passed into GATv2Conv as edge_attr.', browser: 'graphEngine.observe()', python: 'graph_builder.py · edge_attr' },
  { id: 'gat', x: 610, y: 150, title: 'GATv2', sub: '2 × GATv2Conv · 4 heads', simulated: true, detail: 'Two GATv2Conv layers (64 hidden, 4 heads then 1) learn node embeddings using attention over neighbours and edge features.', browser: 'SimulatedDetectionEngine (heuristic stand-in)', python: 'model.py · GNNAnomalyDetector' },
  { id: 'attn', x: 745, y: 150, title: 'ATTENTION LAYER', sub: 'α per incoming edge', simulated: true, detail: 'Attention weights show which neighbours a node relied on. In Model Mode these come from return_attention_weights=True.', browser: 'softmax over incoming edge scores', python: 'model.forward(return_attention=True)' },
  { id: 'score', x: 880, y: 150, title: 'ANOMALY SCORE', sub: 'edge MLP → softmax', simulated: true, detail: 'Source embedding + target embedding + edge features go through an MLP to produce P(anomalous) per flow.', browser: 'analyzeBatch() → anomaly_probability', python: 'model.edge_mlp' },
  { id: 'cls', x: 1015, y: 150, title: 'THREAT CLASSIFIER', sub: 'threshold 0.65', detail: 'Flows above the recall-constrained threshold are ANOMALOUS. A pattern classifier names the likely attack family from the dominant signals.', browser: 'patternClassifier() · classify()', python: 'train.py · best_threshold' },
  { id: 'soc', x: 1155, y: 85, title: 'SOC DASHBOARD', sub: 'incidents · timeline', detail: 'Incidents, threat level and the timeline are derived from detections over time.', browser: 'store/runtime.ts', python: '—' },
  { id: 'graph', x: 1155, y: 215, title: 'NETWORK GRAPH', sub: 'live, explainable', detail: 'The graph re-colours edges by anomaly probability and widens them by traffic volume.', browser: 'components/graph/NetworkGraph.tsx', python: 'visualize_graph.py' },
]

const LINKS: [string, string][] = [
  ['traffic', 'features'], ['features', 'builder'], ['builder', 'node'], ['builder', 'edge'], ['node', 'gat'], ['edge', 'gat'],
  ['gat', 'attn'], ['attn', 'score'], ['score', 'cls'], ['cls', 'soc'], ['cls', 'graph'],
]

const BW = 118
const BH = 50

export function Architecture() {
  const [sel, setSel] = useState<string>('gat')
  const engineMode = useSentinel((s) => s.engineMode)
  const hot = useSentinel((s) => s.networkStatus === 'UNDER ATTACK')
  const by = Object.fromEntries(BOXES.map((b) => [b.id, b]))
  const box = by[sel]

  return (
    <div>
      <div className="scroll-thin overflow-x-auto">
        <svg viewBox="0 40 1230 230" className="min-w-[860px]" role="img" aria-label="SentinelGraph architecture">
          {LINKS.map(([a, b], i) => {
            const A = by[a]
            const B = by[b]
            const x0 = A.x + BW / 2
            const x1 = B.x - BW / 2
            const mx = (x0 + x1) / 2
            const d = `M${x0} ${A.y} C ${mx} ${A.y}, ${mx} ${B.y}, ${x1} ${B.y}`
            const id = `arch-${a}-${b}`
            const c = i >= 8 && hot ? HEX.threat : HEX.ai
            return (
              <g key={id}>
                <path id={id} d={d} stroke="rgba(255,255,255,0.14)" fill="none" />
                <circle r={2.6} fill={c} style={{ filter: `drop-shadow(0 0 4px ${c})` }}>
                  <animateMotion dur={hot ? '1.1s' : '2.2s'} repeatCount="indefinite" begin={`${(i % 4) * 0.35}s`}>
                    <mpath href={`#${id}`} />
                  </animateMotion>
                </circle>
              </g>
            )
          })}
          {BOXES.map((b) => {
            const on = sel === b.id
            const sim = b.simulated && engineMode === 'simulation'
            return (
              <g key={b.id} transform={`translate(${b.x - BW / 2} ${b.y - BH / 2})`} onClick={() => setSel(b.id)} className="cursor-pointer" role="button" aria-label={b.title}>
                <rect width={BW} height={BH} rx={9} fill={on ? '#141c21' : '#0e1317'} stroke={on ? HEX.ai : 'rgba(255,255,255,0.1)'} strokeOpacity={on ? 0.7 : 1} />
                <text x={BW / 2} y={21} textAnchor="middle" fontSize={10} fontWeight={600} letterSpacing="0.12em" fill={on ? '#e6ebed' : '#b8c3c8'}>
                  {b.title}
                </text>
                <text x={BW / 2} y={36} textAnchor="middle" fontSize={8.5} fill="#66727a" className="mono">
                  {b.sub}
                </text>
                {sim && (
                  <g transform={`translate(${BW / 2 - 30} ${-8})`}>
                    <rect width={60} height={14} rx={7} fill="#0b0f12" stroke={HEX.warn} strokeOpacity={0.5} />
                    <text x={30} y={10} textAnchor="middle" fontSize={7.5} letterSpacing="0.12em" fill={HEX.warn}>SIMULATED</text>
                  </g>
                )}
              </g>
            )
          })}
        </svg>
      </div>
      <AnimatePresence mode="wait">
        <motion.div
          key={sel}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.18 }}
          className="mt-3 grid gap-4 rounded-xl border border-line bg-s2/40 p-4 md:grid-cols-[1.4fr_1fr_1fr]"
        >
          <div>
            <div className="text-[13px] font-semibold tracking-wide text-ink">{box.title}</div>
            <p className="mt-1 text-[12px] leading-relaxed text-ink-2">{box.detail}</p>
          </div>
          <div>
            <div className="eyebrow">In this prototype</div>
            <div className={cx('mono mt-1 text-[11.5px]', box.simulated && engineMode === 'simulation' ? 'text-warn' : 'text-ai')}>{box.browser}</div>
          </div>
          <div>
            <div className="eyebrow">In your Python project</div>
            <div className="mono mt-1 text-[11.5px] text-ok">{box.python}</div>
          </div>
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

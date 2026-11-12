import { forceCollide, forceManyBody, forceSimulation, forceX, forceY, type Simulation, type SimulationNodeDatum } from 'd3-force'
import { select as d3select } from 'd3-selection'
import 'd3-transition'
import { zoom as d3zoom, zoomIdentity, type ZoomBehavior } from 'd3-zoom'
import { AnimatePresence, motion } from 'framer-motion'
import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { EdgeState, HostRole, NodeState } from '../../engine/types'
import { HEX, fmtCompact, fmtPct, riskColor, statusColor } from '../../lib/format'
import { select } from '../../store/runtime'
import { useSentinel } from '../../store/store'
import { IconButton, cx } from '../ui'

const W = 1240
const H = 620

const ZONE_LABELS: { zone: NodeState['zone']; text: string; x: number; y: number }[] = [
  { zone: 'office', text: 'OFFICE LAN', x: 280, y: 92 },
  { zone: 'dmz', text: 'DMZ', x: 935, y: 62 },
  { zone: 'core', text: 'CORE', x: 610, y: 262 },
  { zone: 'servers', text: 'SERVERS', x: 860, y: 590 },
  { zone: 'iot', text: 'IoT / DEVICES', x: 440, y: 598 },
  { zone: 'external', text: 'INTERNET', x: 1150, y: 598 },
]

const ROLE_ORDER: HostRole[] = [
  'Core Router', 'Firewall', 'Web Server', 'Mail Server', 'DNS Server', 'Auth / SSH Server', 'Database', 'File Server',
  'Workstation', 'IoT Device', 'Printer', 'External Host',
]
const ipKey = (ip: string) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0)

/** Deterministic, readable slot for the i-th host of a zone (n = hosts in that zone). */
function slotFor(zone: NodeState['zone'], i: number, n: number): [number, number] {
  switch (zone) {
    case 'office': {
      const cols = Math.max(3, Math.ceil(n / 4))
      const r = Math.floor(i / cols)
      const c = i % cols
      return [300 + c * 95 + (r % 2) * 46, 150 + r * 92]
    }
    case 'core':
      return [[640, 320], [790, 225], [700, 420], [560, 420]][i % 4] as [number, number]
    case 'dmz':
      return [[960, 115], [1085, 175], [1070, 70], [840, 120]][i % 4] as [number, number]
    case 'servers': {
      const pts: [number, number][] = [[930, 375], [1065, 345], [960, 500], [1095, 470], [830, 470], [1180, 400]]
      return pts[i % pts.length]
    }
    case 'iot':
      return [470 + i * 95, 545 - (i % 2) * 30]
    case 'external':
      return [1190 - (i % 2) * 42, 70 + i * Math.min(72, 480 / Math.max(1, n - 1))]
  }
}

interface SimNode extends SimulationNodeDatum {
  id: string
  zone: NodeState['zone']
  phase: number
  tx: number
  ty: number
}

export function nodeRadius(role: HostRole) {
  switch (role) {
    case 'Core Router':
    case 'Firewall':
      return 12
    case 'Web Server':
    case 'Database':
    case 'DNS Server':
    case 'Auth / SSH Server':
    case 'File Server':
    case 'Mail Server':
      return 10.5
    case 'External Host':
      return 8
    case 'Workstation':
      return 7.5
    default:
      return 6.5
  }
}

/** Tiny role glyphs drawn inside each node (unit box −1..1). */
function glyph(role: HostRole): string {
  switch (role) {
    case 'Core Router':
      return 'M0 -0.55 L0.55 0 L0 0.55 L-0.55 0 Z'
    case 'Firewall':
      return 'M-0.55 -0.3 H0.55 M-0.55 0.05 H0.55 M-0.55 0.4 H0.55 M-0.15 -0.3 V0.05 M0.2 0.05 V0.4'
    case 'Workstation':
      return 'M-0.5 -0.35 H0.5 V0.2 H-0.5 Z M-0.2 0.45 H0.2'
    case 'External Host':
      return 'M-0.5 0 A0.5 0.5 0 1 0 0.5 0 A0.5 0.5 0 1 0 -0.5 0 M-0.5 0 H0.5 M0 -0.5 C-0.25 -0.2 -0.25 0.2 0 0.5 C0.25 0.2 0.25 -0.2 0 -0.5'
    case 'IoT Device':
    case 'Printer':
      return 'M-0.25 0 A0.25 0.25 0 1 0 0.25 0 A0.25 0.25 0 1 0 -0.25 0'
    default:
      return 'M-0.5 -0.4 H0.5 M-0.5 0 H0.5 M-0.5 0.4 H0.5'
  }
}

interface Hover {
  kind: 'node' | 'edge'
  id: string
  x: number
  y: number
}

export const NetworkGraph = memo(function NetworkGraph({ compact = false }: { compact?: boolean }) {
  const nodes = useSentinel((s) => s.graph.nodes)
  const edges = useSentinel((s) => s.graph.edges)
  const selection = useSentinel((s) => s.selection)
  const focus = useSentinel((s) => s.focus)
  const threshold = useSentinel((s) => s.threshold)

  const wrapRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const layerRef = useRef<SVGGElement>(null)
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null)
  const simRef = useRef<Simulation<SimNode, undefined> | null>(null)
  const simNodes = useRef(new Map<string, SimNode>())
  const drawPos = useRef(new Map<string, { x: number; y: number }>())
  const nodeEls = useRef(new Map<string, SVGGElement>())
  const edgeEls = useRef(new Map<string, SVGPathElement[]>())
  const edgeMeta = useRef(new Map<string, { s: string; t: string; rs: number; rt: number; bend: number }>())
  const [hover, setHover] = useState<Hover | null>(null)
  const [zoomK, setZoomK] = useState(1)

  // ── force layout (zone-anchored, so the picture stays readable and stable) ──
  useEffect(() => {
    const sim = forceSimulation<SimNode>([])
      .force('charge', forceManyBody<SimNode>().strength(-30).distanceMax(90))
      .force('collide', forceCollide<SimNode>(22))
      .force('x', forceX<SimNode>((d) => d.tx).strength(0.3))
      .force('y', forceY<SimNode>((d) => d.ty).strength(0.3))
      .alphaDecay(0.04)
    simRef.current = sim
    return () => {
      sim.stop()
    }
  }, [])

  useEffect(() => {
    const sim = simRef.current
    if (!sim) return
    const map = simNodes.current
    let changed = false
    const ids = new Set(nodes.map((n) => n.id))
    // assign each host a slot within its zone
    const byZone = new Map<NodeState['zone'], NodeState[]>()
    for (const n of nodes) {
      const z = byZone.get(n.zone)
      if (z) z.push(n)
      else byZone.set(n.zone, [n])
    }
    for (const [zone, list] of byZone) {
      list.sort((a, b) => ROLE_ORDER.indexOf(a.role) - ROLE_ORDER.indexOf(b.role) || ipKey(a.ip) - ipKey(b.ip))
      list.forEach((n, i) => {
        const [tx, ty] = slotFor(zone, i, list.length)
        const existing = map.get(n.id)
        if (!existing) {
          map.set(n.id, {
            id: n.id,
            zone: n.zone,
            phase: Math.random() * Math.PI * 2,
            tx,
            ty,
            x: tx + (Math.random() - 0.5) * 30 + (zone === 'external' ? 60 : 0),
            y: ty + (Math.random() - 0.5) * 30,
          })
          changed = true
        } else if (existing.tx !== tx || existing.ty !== ty) {
          existing.tx = tx
          existing.ty = ty
          changed = true
        }
      })
    }
    for (const id of [...map.keys()]) {
      if (!ids.has(id)) {
        map.delete(id)
        changed = true
      }
    }
    if (changed) {
      sim.nodes([...map.values()])
      // re-read slot targets (d3 caches them on initialise)
      ;(sim.force('x') as ReturnType<typeof forceX<SimNode>>).x((d) => d.tx)
      ;(sim.force('y') as ReturnType<typeof forceY<SimNode>>).y((d) => d.ty)
      sim.alpha(0.5).restart()
    }
  }, [nodes])

  // ── zoom & pan ──
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const z = d3zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.55, 4])
      .extent([[0, 0], [W, H]])
      .on('zoom', (ev) => {
        layerRef.current?.setAttribute('transform', ev.transform.toString())
        setZoomK((k) => (Math.abs(k - ev.transform.k) > 0.05 ? ev.transform.k : k))
      })
    zoomRef.current = z
    d3select(svg).call(z).on('dblclick.zoom', null)
    return () => {
      d3select(svg).on('.zoom', null)
    }
  }, [])

  const zoomBy = (f: number) => {
    const svg = svgRef.current
    if (svg && zoomRef.current) d3select(svg).transition().duration(350).call(zoomRef.current.scaleBy, f)
  }
  const fit = useCallback(() => {
    const svg = svgRef.current
    if (svg && zoomRef.current) d3select(svg).transition().duration(800).call(zoomRef.current.transform, zoomIdentity)
  }, [])

  // ── focus on nodes (from incidents / investigate) ──
  useEffect(() => {
    const svg = svgRef.current
    if (!svg || !zoomRef.current || focus.nonce === 0) return
    if (!focus.ids.length) {
      fit()
      return
    }
    const pts = focus.ids.map((id) => drawPos.current.get(id)).filter(Boolean) as { x: number; y: number }[]
    if (!pts.length) return
    const xs = pts.map((p) => p.x)
    const ys = pts.map((p) => p.y)
    const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)]
    const k = Math.max(1, Math.min(2.1, Math.min(W / (x1 - x0 + 380), H / (y1 - y0 + 300))))
    const cx = (x0 + x1) / 2
    const cy = (y0 + y1) / 2
    d3select(svg)
      .transition()
      .duration(1000)
      .call(zoomRef.current.transform, zoomIdentity.translate(W / 2, H / 2).scale(k).translate(-cx, -cy))
  }, [focus, fit])

  // ── animation loop: gentle drift + edge geometry, written straight to the DOM ──
  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    let raf = 0
    const loop = () => {
      const t = performance.now() / 1000
      const amp = reduce ? 0 : 2.6
      for (const [id, n] of simNodes.current) {
        const x = (n.x ?? 0) + Math.sin(t * 0.35 + n.phase) * amp
        const y = (n.y ?? 0) + Math.cos(t * 0.29 + n.phase * 1.3) * amp
        drawPos.current.set(id, { x, y })
        nodeEls.current.get(id)?.setAttribute('transform', `translate(${x.toFixed(1)},${y.toFixed(1)})`)
      }
      for (const [id, els] of edgeEls.current) {
        const m = edgeMeta.current.get(id)
        if (!m) continue
        const a = drawPos.current.get(m.s)
        const b = drawPos.current.get(m.t)
        if (!a || !b) continue
        const d = edgePath(a, b, m.rs, m.rt, m.bend)
        for (const el of els) el.setAttribute('d', d)
      }
      raf = requestAnimationFrame(loop)
    }
    raf = requestAnimationFrame(loop)
    return () => cancelAnimationFrame(raf)
  }, [])

  // ── derived view state ──
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes])
  const pairSet = useMemo(() => new Set(edges.map((e) => e.id)), [edges])
  const anyThreat = edges.some((e) => e.anomaly >= threshold)

  const related = useMemo(() => {
    if (!selection) return null
    const s = new Set<string>()
    if (selection.kind === 'node') {
      s.add(selection.id)
      for (const e of edges) {
        if (e.source === selection.id) s.add(e.target)
        if (e.target === selection.id) s.add(e.source)
      }
    } else {
      const [a, b] = selection.id.split('->')
      s.add(a)
      s.add(b)
    }
    return s
  }, [selection, edges])

  // draw normal edges first, threats last (on top)
  const sortedEdges = useMemo(() => [...edges].sort((a, b) => a.anomaly - b.anomaly), [edges])

  const relPos = (ev: React.MouseEvent) => {
    const r = wrapRef.current!.getBoundingClientRect()
    return { x: ev.clientX - r.left, y: ev.clientY - r.top }
  }

  const hoverNode = hover?.kind === 'node' ? nodeById.get(hover.id) : undefined
  const hoverEdge = hover?.kind === 'edge' ? edges.find((e) => e.id === hover.id) : undefined

  return (
    <div ref={wrapRef} className="absolute inset-0 overflow-hidden">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet"
        className="h-full w-full cursor-grab active:cursor-grabbing select-none"
        onClick={(e) => {
          if (e.target === svgRef.current) select(null)
        }}
        role="img"
        aria-label="Network communication graph"
      >
        <defs>
          <filter id="glow-threat" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3.2" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="glow-soft" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="6" />
          </filter>
          <marker id="arrow-threat" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" fill={HEX.threat} />
          </marker>
          <marker id="arrow-warn" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4.5" markerHeight="4.5" orient="auto-start-reverse">
            <path d="M0 0 L10 5 L0 10 z" fill={HEX.warn} />
          </marker>
          <radialGradient id="node-fill" cx="35%" cy="30%" r="80%">
            <stop offset="0%" stopColor="#1f272d" />
            <stop offset="100%" stopColor="#0d1215" />
          </radialGradient>
          <pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="0.8" fill="rgba(255,255,255,0.05)" />
          </pattern>
        </defs>

        <g ref={layerRef}>
          <rect x={-W} y={-H} width={W * 3} height={H * 3} fill="url(#dots)" pointerEvents="none" />

          {/* zone labels */}
          {!compact &&
            ZONE_LABELS.filter((z) => nodes.some((n) => n.zone === z.zone)).map((z) => (
              <text
                key={z.zone}
                x={z.x}
                y={z.y}
                className="mono"
                fontSize={9.5}
                letterSpacing="0.22em"
                fill="rgba(255,255,255,0.16)"
                pointerEvents="none"
              >
                {z.text}
              </text>
            ))}

          {/* edges */}
          <g>
            {sortedEdges.map((e) => {
              const s = nodeById.get(e.source)
              const t = nodeById.get(e.target)
              if (!s || !t) return null
              const sel = selection?.kind === 'edge' && selection.id === e.id
              const dim = related ? !(related.has(e.source) && related.has(e.target)) : false
              return (
                <EdgeView
                  key={e.id}
                  e={e}
                  threshold={threshold}
                  selected={sel}
                  dim={dim}
                  quiet={anyThreat && e.anomaly < 0.4}
                  register={(els) => {
                    if (els) {
                      edgeEls.current.set(e.id, els)
                      edgeMeta.current.set(e.id, {
                        s: e.source,
                        t: e.target,
                        rs: nodeRadius(s.role) + 2,
                        rt: nodeRadius(t.role) + 4,
                        bend: pairSet.has(`${e.target}->${e.source}`) ? 0.14 : 0.07,
                      })
                    } else {
                      edgeEls.current.delete(e.id)
                      edgeMeta.current.delete(e.id)
                    }
                  }}
                  onHover={(ev) => setHover(ev ? { kind: 'edge', id: e.id, ...relPos(ev) } : null)}
                  onClick={() => select({ kind: 'edge', id: e.id })}
                />
              )
            })}
          </g>

          {/* nodes */}
          <g>
            {nodes.map((n) => (
              <NodeView
                key={n.id}
                n={n}
                threshold={threshold}
                zoomK={zoomK}
                selected={selection?.kind === 'node' && selection.id === n.id}
                endpoint={selection?.kind === 'edge' && related?.has(n.id) === true}
                dim={related ? !related.has(n.id) : false}
                register={(el) => {
                  if (el) nodeEls.current.set(n.id, el)
                  else nodeEls.current.delete(n.id)
                }}
                onHover={(ev) => setHover(ev ? { kind: 'node', id: n.id, ...relPos(ev) } : null)}
                onClick={() => select({ kind: 'node', id: n.id })}
              />
            ))}
          </g>
        </g>
      </svg>

      {/* hover card */}
      <AnimatePresence>
        {hover && (hoverNode || hoverEdge) && (
          <motion.div
            key={hover.kind + hover.id}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.12 }}
            className="pointer-events-none absolute z-20 min-w-[180px] rounded-lg border border-line-2 bg-s2/95 px-3 py-2 text-[11.5px] shadow-2xl backdrop-blur"
            style={{
              left: Math.min(hover.x + 14, (wrapRef.current?.clientWidth ?? 800) - 220),
              top: Math.max(8, hover.y - 10),
            }}
          >
            {hoverNode && (
              <>
                <div className="mono text-[12.5px] text-ink">{hoverNode.ip}</div>
                <div className="text-ink-3">{hoverNode.role}{hoverNode.label ? ` · ${hoverNode.label}` : ''}</div>
                <div className="mt-1.5 flex items-center justify-between gap-4">
                  <span className="text-ink-3">Risk</span>
                  <span className="mono" style={{ color: statusColor(hoverNode.status) }}>{fmtPct(hoverNode.risk, 0)} · {hoverNode.status}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-ink-3">Peers</span>
                  <span className="mono text-ink-2">{hoverNode.connections}</span>
                </div>
              </>
            )}
            {hoverEdge && (
              <>
                <div className="mono text-[12px] text-ink">
                  {hoverEdge.source} <span className="text-ink-3">→</span> {hoverEdge.target}
                </div>
                <div className="text-ink-3">{hoverEdge.protocol} · {fmtCompact(hoverEdge.flows)} flows · {fmtCompact(hoverEdge.pps)} pkt/s</div>
                <div className="mt-1.5 flex items-center justify-between gap-4">
                  <span className="text-ink-3">Anomaly</span>
                  <span className="mono" style={{ color: riskColor(hoverEdge.anomaly, threshold) }}>{fmtPct(hoverEdge.anomaly)}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-ink-3">GAT attention</span>
                  <span className="mono text-ai">{hoverEdge.attention.toFixed(2)}</span>
                </div>
              </>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* controls */}
      <div className="absolute right-3 bottom-3 z-10 flex flex-col gap-1.5">
        <IconButton label="Zoom in" onClick={() => zoomBy(1.35)}>
          <svg width="12" height="12" viewBox="0 0 12 12"><path d="M6 1v10M1 6h10" stroke="currentColor" strokeWidth="1.4" /></svg>
        </IconButton>
        <IconButton label="Zoom out" onClick={() => zoomBy(1 / 1.35)}>
          <svg width="12" height="12" viewBox="0 0 12 12"><path d="M1 6h10" stroke="currentColor" strokeWidth="1.4" /></svg>
        </IconButton>
        <IconButton label="Fit network" onClick={fit}>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.3"><path d="M1 4V1h3M8 1h3v3M11 8v3H8M4 11H1V8" /></svg>
        </IconButton>
      </div>
    </div>
  )
})

function edgePath(a: { x: number; y: number }, b: { x: number; y: number }, rs: number, rt: number, bend: number) {
  const dx = b.x - a.x
  const dy = b.y - a.y
  const len = Math.hypot(dx, dy) || 1
  const ux = dx / len
  const uy = dy / len
  // control point offset perpendicular to the edge — keeps A→B and B→A apart
  const mx = (a.x + b.x) / 2 - uy * len * bend
  const my = (a.y + b.y) / 2 + ux * len * bend
  const sx = a.x + ux * rs
  const sy = a.y + uy * rs
  const tx = b.x - ux * rt
  const ty = b.y - uy * rt
  return `M${sx.toFixed(1)},${sy.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${tx.toFixed(1)},${ty.toFixed(1)}`
}

const EdgeView = memo(function EdgeView({
  e, threshold, selected, dim, quiet, register, onHover, onClick,
}: {
  e: EdgeState
  threshold: number
  selected: boolean
  dim: boolean
  quiet: boolean
  register: (els: SVGPathElement[] | null) => void
  onHover: (ev: React.MouseEvent | null) => void
  onClick: () => void
}) {
  const base = useRef<SVGPathElement>(null)
  const flow = useRef<SVGPathElement>(null)
  const hit = useRef<SVGPathElement>(null)
  const glow = useRef<SVGPathElement>(null)
  const ring = useRef<SVGPathElement>(null)
  useEffect(() => {
    register([base.current!, flow.current!, hit.current!, glow.current!, ring.current!])
    return () => register(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const threat = e.anomaly >= threshold
  const warn = !threat && e.anomaly >= 0.4
  const color = threat ? HEX.threat : warn ? HEX.warn : HEX.ok
  const intensity = Math.min(1, Math.log10(1 + e.pps) / 4)
  const width = threat ? 1.6 + intensity * 4.6 : warn ? 1.2 + intensity * 2 : 0.7 + Math.min(1, e.rate / 3) * 0.8
  const baseOpacity = threat ? 0.85 : warn ? 0.6 : 0.16 + Math.min(1, e.rate / 2) * 0.22
  const live = e.rate > 0.05
  // quantised so the CSS animation isn't restarted on every tiny change
  const speed = threat ? 0.45 : warn ? 0.9 : [2.8, 2.2, 1.6][Math.min(2, Math.floor(e.rate))]
  const fade = dim ? 0.12 : quiet ? 0.45 : 1

  return (
    <g
      style={{ opacity: fade, transition: 'opacity 400ms' }}
      onMouseEnter={(ev) => onHover(ev)}
      onMouseMove={(ev) => onHover(ev)}
      onMouseLeave={() => onHover(null)}
      onClick={(ev) => {
        ev.stopPropagation()
        onClick()
      }}
      className="cursor-pointer"
    >
      <path
        ref={glow}
        fill="none"
        stroke={color}
        strokeWidth={width * 3}
        strokeOpacity={threat ? 0.16 : 0}
        filter={threat ? 'url(#glow-soft)' : undefined}
        style={{ transition: 'stroke-opacity 500ms' }}
      />
      <path
        ref={ring}
        fill="none"
        stroke={HEX.ai}
        strokeWidth={width + 5}
        strokeOpacity={selected ? 0.35 : 0}
        strokeLinecap="round"
      />
      <path
        ref={base}
        fill="none"
        stroke={threat || warn ? color : '#8fa3ad'}
        strokeWidth={selected ? width + 1.2 : width}
        strokeOpacity={selected ? 1 : baseOpacity}
        markerEnd={threat ? 'url(#arrow-threat)' : warn ? 'url(#arrow-warn)' : undefined}
        style={{ transition: 'stroke 500ms, stroke-width 500ms, stroke-opacity 500ms' }}
      />
      <path
        ref={flow}
        fill="none"
        stroke={threat ? '#ffd0d4' : color}
        strokeWidth={threat ? Math.max(2.2, width * 0.7) : warn ? 2 : 1.8}
        strokeLinecap="round"
        strokeDasharray={threat ? '0.1 10' : '0.1 16'}
        strokeOpacity={live ? (threat ? 0.95 : warn ? 0.85 : 0.5) : 0}
        className="edge-flow"
        style={{ animationDuration: `${speed}s`, transition: 'stroke-opacity 600ms' }}
      />
      <path ref={hit} fill="none" stroke="transparent" strokeWidth={12} pointerEvents="stroke" />
    </g>
  )
})

const NodeView = memo(function NodeView({
  n, threshold, zoomK, selected, endpoint, dim, register, onHover, onClick,
}: {
  n: NodeState
  threshold: number
  zoomK: number
  selected: boolean
  endpoint: boolean
  dim: boolean
  register: (el: SVGGElement | null) => void
  onHover: (ev: React.MouseEvent | null) => void
  onClick: () => void
}) {
  const ref = useRef<SVGGElement>(null)
  useEffect(() => {
    register(ref.current)
    return () => register(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const r = nodeRadius(n.role)
  const color = statusColor(n.status)
  const hot = n.risk >= threshold
  const warm = !hot && n.risk >= 0.35
  const isTarget = n.status === 'TARGET'
  const isSource = n.status === 'SUSPICIOUS'
  const important = n.role !== 'Workstation' && n.role !== 'IoT Device' && n.role !== 'Printer'
  const showFull = hot || warm || selected || endpoint || zoomK > 1.5 || important
  const label = showFull ? n.ip : `.${n.ip.split('.').pop()}`

  return (
    <g
      ref={ref}
      style={{ opacity: dim ? 0.22 : 1, transition: 'opacity 400ms' }}
      className="cursor-pointer"
      onMouseEnter={(ev) => onHover(ev)}
      onMouseMove={(ev) => onHover(ev)}
      onMouseLeave={() => onHover(null)}
      onClick={(ev) => {
        ev.stopPropagation()
        onClick()
      }}
    >
      {/* halo */}
      <circle r={r * 2.6} fill={color} opacity={hot ? 0.16 : warm ? 0.08 : 0.035} filter="url(#glow-soft)" style={{ transition: 'opacity 600ms, fill 600ms' }} />

      {/* threat rings */}
      {hot && (
        <>
          <circle r={r + 2} fill="none" stroke={HEX.threat} strokeWidth={1.4} className="node-pulse" />
          <circle r={r + 2} fill="none" stroke={HEX.threat} strokeWidth={1} className="node-pulse" style={{ animationDelay: '1.2s' }} />
        </>
      )}
      {isTarget && (
        <g className="spin-slow">
          <circle r={r + 8} fill="none" stroke={HEX.threat} strokeWidth={1} strokeDasharray="3 5" opacity={0.85} />
        </g>
      )}
      {isTarget && (
        <text y={-r - 13} textAnchor="middle" fontSize={8.5} letterSpacing="0.2em" fill={HEX.threat} className="mono" fontWeight={600}>
          TARGET
        </text>
      )}
      {isSource && hot && (
        <text y={-r - 9} textAnchor="middle" fontSize={8.5} letterSpacing="0.2em" fill={HEX.threat} className="mono" fontWeight={600}>
          SOURCE
        </text>
      )}

      {/* selection ring */}
      {(selected || endpoint) && <circle r={r + 5} fill="none" stroke={HEX.ai} strokeWidth={1.3} />}

      {/* body */}
      <circle
        r={r}
        fill="url(#node-fill)"
        stroke={color}
        strokeWidth={hot ? 1.8 : 1.2}
        strokeOpacity={hot ? 1 : warm ? 0.9 : 0.55}
        style={{ transition: 'stroke 500ms' }}
      />
      <path
        d={glyph(n.role)}
        transform={`scale(${r * 0.62})`}
        fill={n.role === 'IoT Device' || n.role === 'Printer' ? color : 'none'}
        stroke={hot ? HEX.threat : '#b9c6cc'}
        strokeWidth={1.4 / (r * 0.62)}
        strokeLinejoin="round"
        opacity={0.85}
      />

      <text
        y={r + 12}
        textAnchor="middle"
        fontSize={showFull ? 9 : 8.5}
        className={cx('mono')}
        fill={hot ? '#ffb3ba' : selected || endpoint ? '#e6ebed' : 'rgba(155,167,174,0.75)'}
        pointerEvents="none"
      >
        {label}
      </text>
    </g>
  )
})


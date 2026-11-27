import { useEffect, useRef } from 'react'
import cytoscape, { type ElementDefinition } from 'cytoscape'
import { Maximize2 } from 'lucide-react'

/** Directed graph. Colours come from CSS variables so both themes work. */
export default function GraphView({ elements, height = 420, label }: {
  /** Every node must carry a `position`; the caller decides the layout. */
  elements: ElementDefinition[]; height?: number; label: string
}) {
  const host = useRef<HTMLDivElement>(null)
  const graph = useRef<cytoscape.Core | null>(null)

  useEffect(() => {
    if (!host.current) return
    const draw = () => {
      const css = getComputedStyle(document.documentElement)
      const v = (name: string) => css.getPropertyValue(name).trim()
      graph.current?.destroy()
      graph.current = cytoscape({
        container: host.current,
        elements: structuredClone(elements),
        minZoom: 0.25, maxZoom: 2,
        style: [
          { selector: 'node', style: {
            label: 'data(label)', 'text-wrap': 'wrap', 'text-max-width': '190px', 'font-size': 11,
            'text-valign': 'center', 'text-halign': 'center', width: 210, height: 58,
            shape: 'round-rectangle', 'background-color': v('--surface'), color: v('--text'),
            'border-width': 1.5, 'border-color': v('--border-strong') } },
          { selector: 'node.hidden-api', style: { 'border-style': 'dashed', 'border-width': 2, 'border-color': v('--accent') } },
          { selector: 'node.weak', style: { 'border-color': v('--critical'), 'border-width': 2.5 } },
          { selector: 'node.actor', style: { shape: 'ellipse', width: 130, 'background-color': v('--accent'), color: '#ffffff', 'border-width': 0 } },
          { selector: 'node.goal', style: { shape: 'round-rectangle', 'background-color': v('--critical'), color: '#ffffff', 'border-width': 0 } },
          { selector: 'edge', style: {
            width: 1.8, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
            'line-color': v('--border-strong'), 'target-arrow-color': v('--border-strong'),
            label: 'data(label)', 'font-size': 10, color: v('--text-muted'),
            'text-background-color': v('--surface'), 'text-background-opacity': 1, 'text-background-padding': '3px' } },
          { selector: 'edge.skip', style: { 'curve-style': 'unbundled-bezier',
            'control-point-distances': 170, 'control-point-weights': 0.5 } },
        ],
        layout: { name: 'preset', fit: false },
        userZoomingEnabled: false,
      })
      // Fit, but never magnify beyond natural size.
      graph.current.fit(undefined, 24)
      if (graph.current.zoom() > 1) { graph.current.zoom(1); graph.current.center() }
    }
    draw()
    const observer = new MutationObserver(draw)
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => { observer.disconnect(); graph.current?.destroy(); graph.current = null }
  }, [elements])

  const zoom = (factor: number) => {
    const g = graph.current
    if (g) g.zoom({ level: g.zoom() * factor, renderedPosition: { x: g.width() / 2, y: g.height() / 2 } })
  }

  return (
    <div className="graph-wrap">
      <div className="graph" ref={host} style={{ height }} role="img" aria-label={label} />
      <div className="graph-controls">
        <button onClick={() => zoom(1.25)} aria-label="Zoom in">+</button>
        <button onClick={() => zoom(0.8)} aria-label="Zoom out">−</button>
        <button onClick={() => graph.current?.fit(undefined, 20)} aria-label="Fit graph"><Maximize2 size={13} /></button>
      </div>
    </div>
  )
}

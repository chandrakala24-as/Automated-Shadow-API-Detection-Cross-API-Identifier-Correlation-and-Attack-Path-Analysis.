import { useMemo, useState } from 'react'
import { Route } from 'lucide-react'
import type { ElementDefinition } from 'cytoscape'
import type { AttackPath } from '../types'
import { Empty, Endpoint, SeverityBadge, TYPE_NAMES, Tag, title } from '../ui'
import GraphView from './GraphView'

const ROW = 108

function toGraph(path: AttackPath): ElementDefinition[] {
  const attacker = path.attacker === 'anonymous' ? 'Anonymous attacker' : `Attacker\n(${path.attacker})`
  const goal = `${path.data_categories.map(title).join(', ') || 'Protected'} data\nof ${path.victim}`
  const elements: ElementDefinition[] = [
    { data: { id: 'actor', label: attacker }, classes: 'actor', position: { x: 0, y: 0 } },
    { data: { id: 'goal', label: goal }, classes: 'goal', position: { x: 0, y: (path.steps.length + 1) * ROW } },
  ]
  for (const s of path.steps) {
    const classes = [s.weaknesses.length ? 'weak' : '', ['shadow', 'zombie'].includes(s.classification) ? 'hidden-api' : ''].join(' ')
    elements.push({ data: { id: `s${s.number}`, label: `${s.number}. ${s.endpoint.replace(' ', '\n')}` }, classes,
      position: { x: 0, y: s.number * ROW } })
    if (s.uses.length === 0) elements.push({ data: { id: `a${s.number}`, source: 'actor', target: `s${s.number}`, label: 'calls' } })
    for (const u of s.uses) {
      elements.push({ data: { id: `u${s.number}-${u.from_step}-${u.field}`, source: `s${u.from_step}`, target: `s${s.number}`, label: u.field },
        // Curve edges that skip a row, so they do not run through the node between.
        classes: s.number - u.from_step > 1 ? 'skip' : '' })
    }
  }
  elements.push({ data: { id: 'end', source: `s${path.steps.length}`, target: 'goal', label: 'exposes' } })
  return elements
}

export default function Paths({ paths }: { paths: AttackPath[] }) {
  const [selected, setSelected] = useState(0)
  const path = paths.find((p) => p.id === selected) ?? paths[0]
  const elements = useMemo(() => (path ? toGraph(path) : []), [path])
  if (!path) {
    return <Empty icon={<Route size={32} />} heading="No attack paths"><p className="muted">No multi-step chain was verified. Paths need two normal-user accounts that own different data.</p></Empty>
  }
  return (
    <div className="paths">
      <ol className="path-list">
        {paths.map((p) => (
          <li key={p.id}>
            <button aria-pressed={p.id === path.id} onClick={() => setSelected(p.id)}>
              <span className="between"><SeverityBadge level={p.severity} /><strong>{p.score}</strong></span>
              <span>{p.title}</span>
              <small className="muted">{p.attacker} → {p.victim}'s data</small>
            </button>
          </li>
        ))}
      </ol>
      <div className="path-detail">
        <section className="card">
          <h2>{path.title}</h2>
          <p>{path.narrative}</p>
          <GraphView elements={elements} height={(path.steps.length + 2) * 96} label={`Attack path graph. ${path.narrative}`} />
          <p className="legend small muted">
            <span><i className="key weak" /> Has a confirmed weakness</span>
            <span><i className="key hidden-api" /> Dashed: shadow or zombie API</span>
          </p>
        </section>
        <section className="card">
          <h2>Step by step</h2>
          <ol className="timeline">
            {path.steps.map((s) => (
              <li key={s.number}>
                <span className="step-number">{s.number}</span>
                <div>
                  <Endpoint label={s.endpoint} /> <Tag kind={s.classification} />
                  <div className="mono small muted">{s.request} → {s.status}</div>
                  {s.uses.map((u) => <div key={u.field + u.from_step} className="small">Uses <code>{u.field}</code> learned in step {u.from_step}</div>)}
                  {s.gains.map((g) => <div key={g.field} className="small">Reveals <code>{g.field}</code> for a later step</div>)}
                  <div>{s.weaknesses.map((w) => <span key={w}><Tag kind="weakness">{TYPE_NAMES[w] ?? title(w)}</Tag> </span>)}
                    {s.data.map((d) => <span key={d}><Tag kind="data">{title(d)}</Tag> </span>)}</div>
                </div>
              </li>
            ))}
          </ol>
          <p className="muted small">Every request in this path succeeded during the scan. Fixing any weak step that has no alternative route breaks the chain.</p>
        </section>
      </div>
    </div>
  )
}

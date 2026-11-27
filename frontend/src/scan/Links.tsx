import { useMemo, useState } from 'react'
import { ArrowRight, Fingerprint } from 'lucide-react'
import type { ElementDefinition } from 'cytoscape'
import type { Link } from '../types'
import { Empty, Endpoint, Tag, title } from '../ui'
import GraphView from './GraphView'

export default function Links({ links }: { links: Link[] }) {
  const entities = useMemo(() => [...new Set(links.map((l) => l.entity))].sort(), [links])
  const [chosen, setChosen] = useState('')
  const entity = chosen || (entities.includes('vehicle') ? 'vehicle' : entities[0])
  const shown = useMemo(() => links.filter((l) => l.entity === entity), [links, entity])

  const elements = useMemo<ElementDefinition[]>(() => {
    const names = new Set(shown.flatMap((l) => [l.producer, l.consumer]))
    // Columns: only produces | produces and consumes | only consumes.
    const column = (n: string) => {
      const produces = shown.some((l) => l.producer === n)
      const consumes = shown.some((l) => l.consumer === n)
      return produces && consumes ? 1 : produces ? 0 : 2
    }
    const used = [...new Set([...names].map(column))].sort()
    const columns = used.map((c) => [...names].filter((n) => column(n) === c).sort())
    const tallest = Math.max(1, ...columns.map((c) => c.length))
    return [
      ...columns.flatMap((members, x) => members.map((n, y) => ({
        data: { id: n, label: n.replace(' ', '\n') },
        position: { x: x * 440, y: (y + (tallest - members.length) / 2) * 82 },
      }))),
      ...shown.map((l) => ({ data: { id: `e${l.id}`, source: l.producer, target: l.consumer, label: `${l.producer_field} → ${l.consumer_param}` } })),
    ]
  }, [shown])

  if (links.length === 0) {
    return <Empty icon={<Fingerprint size={32} />} heading="No identifier links"><p className="muted">No identifier produced by one API was linked to another.</p></Empty>
  }
  return (
    <>
      <section className="card">
        <div className="between">
          <div><h2>How identifiers move between APIs</h2><p className="muted">An arrow points from the API that returns an identifier to an API that accepts it. A link alone is not a vulnerability.</p></div>
          <label>Identifier type<select value={entity} onChange={(e) => setChosen(e.target.value)}>
            {entities.map((e) => <option key={e} value={e}>{title(e)} ({links.filter((l) => l.entity === e).length})</option>)}</select></label>
        </div>
        <GraphView elements={elements} height={Math.min(640, 200 + shown.length * 45)} label={`Graph of ${entity} identifier links. The same data is in the table below.`} />
      </section>
      <section className="card">
        <div className="table-wrap"><table>
          <thead><tr><th>Produced by</th><th /><th>Consumed by</th><th>Evidence</th><th className="num">Confidence</th></tr></thead>
          <tbody>
            {shown.map((l) => (
              <tr key={l.id}>
                <td><Endpoint label={l.producer} /><br /><Tag kind="data">{l.producer_field}</Tag></td>
                <td><ArrowRight size={15} /></td>
                <td><Endpoint label={l.consumer} /><br /><Tag kind="data">{l.consumer_param}</Tag></td>
                <td><ul className="compact">{l.evidence.map((e) => <li key={e}>{e}</li>)}</ul></td>
                <td className="num">{Math.round(l.confidence * 100)}%</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </section>
    </>
  )
}

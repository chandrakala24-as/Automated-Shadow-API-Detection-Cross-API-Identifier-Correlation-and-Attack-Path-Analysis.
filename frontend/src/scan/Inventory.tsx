import { useState } from 'react'
import { Search } from 'lucide-react'
import type { Endpoint as EndpointType } from '../types'
import { Endpoint, Tag, title } from '../ui'

const MEANING: Record<string, string> = {
  documented: 'In the specification and live', shadow: 'Live but not in the specification',
  zombie: 'Deprecated or older version that is still live', unverified: 'In the specification but not confirmed live',
  candidate: 'Referenced somewhere but not confirmed live', unclassified: 'Live; no specification to compare with',
}

export default function Inventory({ endpoints }: { endpoints: EndpointType[] }) {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('all')
  const kinds = [...new Set(endpoints.map((e) => e.classification))]
  const shown = endpoints.filter((e) => (kind === 'all' || e.classification === kind)
    && `${e.method} ${e.path}`.toLowerCase().includes(query.toLowerCase()))

  return (
    <section className="card">
      <div className="filters">
        <label className="search"><Search size={15} /><input aria-label="Search paths" placeholder="Search paths…" value={query} onChange={(e) => setQuery(e.target.value)} /></label>
        <select aria-label="Filter by class" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="all">All classes</option>
          {kinds.map((k) => <option key={k} value={k}>{title(k)} ({endpoints.filter((e) => e.classification === k).length})</option>)}
        </select>
        {kind !== 'all' && <small className="muted">{MEANING[kind]}</small>}
      </div>
      <div className="table-wrap"><table>
        <thead><tr><th>API</th><th>Class</th><th>Found by</th><th>Responses</th><th>Sensitive data</th></tr></thead>
        <tbody>
          {shown.map((e) => (
            <tr key={e.id}>
              <td><Endpoint label={`${e.method} ${e.path}`} />{e.skip_reason && <small className="muted block">Not tested: {e.skip_reason}</small>}</td>
              <td><span title={MEANING[e.classification]}><Tag kind={e.classification} /></span></td>
              <td>{e.sources.map(title).join(', ')}</td>
              <td className="mono">{e.statuses.join(', ') || '–'}</td>
              <td>{Object.keys(e.sensitive).map((c) => <span key={c} title={e.sensitive[c].join(', ')}><Tag kind="data">{title(c)}</Tag> </span>)}</td>
            </tr>
          ))}
        </tbody>
      </table></div>
      {shown.length === 0 && <p className="muted center">No API matches these filters.</p>}
    </section>
  )
}

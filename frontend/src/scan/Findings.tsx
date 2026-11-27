import { useEffect, useState } from 'react'
import { CheckCircle2, HelpCircle, ShieldCheck, Wrench, X } from 'lucide-react'
import type { Finding, Triage } from '../types'
import { Empty, Endpoint, SEVERITIES, SeverityBadge, TYPE_NAMES, Tag, title } from '../ui'

const TRIAGE: Triage[] = ['open', 'fixed', 'accepted', 'false_positive']

export default function Findings({ findings, selected, select, setTriage }: {
  findings: Finding[]; selected: number | null
  select: (id: number | null) => void; setTriage: (id: number, triage: Triage) => void
}) {
  const [severity, setSeverity] = useState('all')
  const [type, setType] = useState('all')
  const shown = findings.filter((f) => (severity === 'all' || f.severity === severity) && (type === 'all' || f.type === type))
  const current = findings.find((f) => f.id === selected)

  useEffect(() => {
    const escape = (e: KeyboardEvent) => e.key === 'Escape' && select(null)
    if (current) window.addEventListener('keydown', escape)
    return () => window.removeEventListener('keydown', escape)
  }, [current, select])

  if (findings.length === 0) {
    return <Empty icon={<ShieldCheck size={32} />} heading="No findings"><p className="muted">Nothing was verified in the routes tested. This does not prove the API is secure.</p></Empty>
  }

  return (
    <section className="card">
      <div className="filters">
        <select aria-label="Filter by severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="all">All severities</option>{SEVERITIES.map((s) => <option key={s} value={s}>{title(s)}</option>)}
        </select>
        <select aria-label="Filter by type" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="all">All types</option>
          {[...new Set(findings.map((f) => f.type))].map((t) => <option key={t} value={t}>{TYPE_NAMES[t] ?? title(t)}</option>)}
        </select>
        <small className="muted">{shown.length} of {findings.length}</small>
      </div>
      <div className="table-wrap"><table className="clickable">
        <thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Status</th><th className="num">Risk</th></tr></thead>
        <tbody>
          {shown.map((f) => (
            <tr key={f.id} onClick={() => select(f.id)} className={f.triage !== 'open' ? 'dimmed' : ''}>
              <td><SeverityBadge level={f.severity} /></td>
              <td><button className="row-button" onClick={(e) => { e.stopPropagation(); select(f.id) }}><strong>{TYPE_NAMES[f.type] ?? title(f.type)}</strong></button><br /><Endpoint label={f.endpoint} /></td>
              <td>{f.confidence === 'confirmed' ? <span className="ok"><CheckCircle2 size={13} /> Confirmed</span> : <span><HelpCircle size={13} /> Needs review</span>}</td>
              <td><Tag kind={f.triage} /></td>
              <td className="num">{f.score}</td>
            </tr>
          ))}
        </tbody>
      </table></div>

      {current && (
        <div className="drawer-backdrop" onClick={() => select(null)}>
          <aside className="drawer" role="dialog" aria-modal="true" aria-label={current.title} onClick={(e) => e.stopPropagation()}>
            <div className="between"><SeverityBadge level={current.severity} />
              <button className="ghost icon" onClick={() => select(null)} aria-label="Close" autoFocus><X size={18} /></button></div>
            <h2>{current.title}</h2>
            <Endpoint label={current.endpoint} />
            <p className="muted small">{current.owasp}</p>
            <p>{current.description}</p>
            <div className="alert info"><Wrench size={16} /><div><strong>How to fix</strong><p>{current.remediation}</p></div></div>
            <label>Status<select value={current.triage} onChange={(e) => setTriage(current.id, e.target.value as Triage)}>
              {TRIAGE.map((t) => <option key={t} value={t}>{title(t)}</option>)}</select></label>
            <h3>Why the risk is {current.score}/100</h3>
            <dl>
              {Object.entries(current.score_breakdown).map(([k, v]) => <div className="dl-row" key={k}><dt>{title(k)}</dt><dd>{v > 0 ? `+${v}` : v}</dd></div>)}
            </dl>
            {current.evidence.length > 0 && <h3>Evidence</h3>}
            {current.evidence.map((item, i) => (
              <div className="evidence" key={i}>
                <strong>{item.note}</strong>
                <div className="mono small">{item.request} → {item.status} (as {item.identity})</div>
                <pre>{JSON.stringify(item.response, null, 2)}</pre>
              </div>
            ))}
          </aside>
        </div>
      )}
    </section>
  )
}

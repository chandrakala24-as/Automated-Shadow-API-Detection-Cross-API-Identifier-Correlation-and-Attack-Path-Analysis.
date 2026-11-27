import { useCallback, useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { AlertTriangle, ArrowLeft, Download, FileText, Loader2, XCircle } from 'lucide-react'
import { api } from '../api'
import type { Results, Scan, Triage } from '../types'
import { ErrorBox, Loading, PageHeader, Tag, when } from '../ui'
import Overview from '../scan/Overview'
import Inventory from '../scan/Inventory'
import Findings from '../scan/Findings'
import Links from '../scan/Links'
import Paths from '../scan/Paths'

const TABS = [['overview', 'Overview'], ['inventory', 'API inventory'], ['findings', 'Findings'],
  ['links', 'Identifier links'], ['paths', 'Attack paths']] as const

export default function ScanPage() {
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const [scan, setScan] = useState<Scan>()
  const [results, setResults] = useState<Results>()
  const [error, setError] = useState('')
  const tab = params.get('tab') ?? 'overview'
  const active = scan?.status === 'queued' || scan?.status === 'running'

  const refresh = useCallback(async () => {
    try {
      const current = await api<Scan>(`/scans/${id}`)
      setScan(current)
      if (current.status === 'completed') setResults(await api<Results>(`/scans/${id}/results`))
      setError('')
    } catch (e) {
      setError((e as Error).message)
    }
  }, [id])

  useEffect(() => { void refresh() }, [refresh])
  useEffect(() => {
    if (!active) return
    const timer = setInterval(refresh, 1000)
    return () => clearInterval(timer)
  }, [active, refresh])

  if (!scan) return error ? <ErrorBox message={error} /> : <Loading />

  const setTriage = (findingId: number, triage: Triage) =>
    api(`/findings/${findingId}`, 'PATCH', { triage }).then(refresh).catch((e: Error) => setError(e.message))
  const open = (next: string, extra: Record<string, string> = {}) => setParams({ tab: next, ...extra }, { replace: true })
  const counts: Record<string, number | undefined> = {
    inventory: results?.endpoints.length, findings: results?.findings.length,
    links: results?.links.length, paths: results?.paths.length,
  }

  return (
    <>
      <Link to={`/projects/${scan.project_id}`} className="back"><ArrowLeft size={15} /> {scan.project_name}</Link>
      <PageHeader heading={`Scan #${scan.id}`}
        sub={<>{when(scan.created_at)} · <code>{scan.base_url}</code> <Tag kind={scan.status} /></>}
        actions={results && <>
          <a className="button" href={`/api/scans/${id}/report.json`}><Download size={15} /> JSON</a>
          <a className="button primary" href={`/api/scans/${id}/report.html`} target="_blank" rel="noreferrer"><FileText size={15} /> Report / PDF</a>
        </>} />
      <ErrorBox message={error} />

      {active && (
        <div className="card progress-card" aria-live="polite">
          <div className="between"><h2><Loader2 className="spin" size={18} /> {scan.stage}</h2><strong>{scan.progress}%</strong></div>
          <div className="progress" role="progressbar" aria-valuenow={scan.progress} aria-valuemin={0} aria-valuemax={100}>
            <div style={{ width: `${scan.progress}%` }} />
          </div>
          <div className="between">
            <span className="muted">{scan.message}</span>
            <button onClick={() => api(`/scans/${id}/cancel`, 'POST').then(refresh)}><XCircle size={15} /> Cancel scan</button>
          </div>
        </div>
      )}
      {(scan.status === 'failed' || scan.status === 'cancelled') && <ErrorBox message={scan.message} />}
      {scan.status === 'completed' && !results && <Loading label="Loading results…" />}

      {results && (
        <>
          {scan.warnings.length > 0 && (
            <div className="alert warning"><AlertTriangle size={16} />
              <div><strong>Scan notes</strong><ul>{scan.warnings.map((w) => <li key={w}>{w}</li>)}</ul></div>
            </div>
          )}
          <div className="tabs" role="tablist">
            {TABS.map(([key, label]) => (
              <button key={key} role="tab" aria-selected={tab === key} onClick={() => open(key)}>
                {label}{counts[key] !== undefined && <span className="count">{counts[key]}</span>}
              </button>
            ))}
          </div>
          {tab === 'overview' && <Overview results={results} open={open} />}
          {tab === 'inventory' && <Inventory endpoints={results.endpoints} />}
          {tab === 'findings' && <Findings findings={results.findings} selected={Number(params.get('finding')) || null}
            select={(f) => open('findings', f ? { finding: String(f) } : {})} setTriage={setTriage} />}
          {tab === 'links' && <Links links={results.links} />}
          {tab === 'paths' && <Paths paths={results.paths} />}
        </>
      )}
    </>
  )
}

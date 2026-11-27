import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { FlaskConical, Pencil, Play, Trash2 } from 'lucide-react'
import { api } from '../api'
import type { Project, Scan } from '../types'
import { ErrorBox, Loading, PageHeader, Tag, useLoad, when } from '../ui'

export default function ProjectDetail() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { data: project, error, reload } = useLoad(() => api<Project>(`/projects/${id}`), [id])
  const [actionError, setActionError] = useState('')
  const [busy, setBusy] = useState(false)
  if (!project) return error ? <ErrorBox message={error} /> : <Loading />

  const fail = (e: Error) => { setActionError(e.message); setBusy(false) }
  const scan = () => {
    setBusy(true)
    api<Scan>(`/projects/${id}/scans`, 'POST').then((s) => navigate(`/scans/${s.id}`)).catch(fail)
  }
  const remove = () => {
    if (confirm(`Delete "${project.name}" and all its scan results? This cannot be undone.`)) {
      api(`/projects/${id}`, 'DELETE').then(() => navigate('/projects')).catch(fail)
    }
  }
  const removeScan = (scanId: number) => {
    if (confirm(`Delete scan #${scanId}?`)) api(`/scans/${scanId}`, 'DELETE').then(reload).catch(fail)
  }

  return (
    <>
      <PageHeader heading={project.name} sub={<code>{project.base_url}</code>} actions={<>
        <button onClick={remove} className="danger"><Trash2 size={15} /> Delete</button>
        <Link to={`/projects/${id}/edit`} className="button"><Pencil size={15} /> Edit</Link>
        <button className="primary" onClick={scan} disabled={busy}><Play size={15} /> {busy ? 'Starting…' : 'Run scan'}</button>
      </>} />
      <ErrorBox message={actionError} />
      {project.is_demo && (
        <div className="alert info"><FlaskConical size={16} />
          <span>This is the bundled <strong>deliberately vulnerable</strong> lab. <code>start.ps1</code> runs it on this computer. All its data is fake.</span>
        </div>
      )}
      <div className="grid two">
        <section className="card">
          <h2>Inputs</h2>
          <dl>
            <dt>Specification</dt><dd>{project.has_spec ? 'Provided' : 'Not provided'}</dd>
            <dt>Traffic capture</dt><dd>{project.has_har ? 'Provided' : 'Not provided'}</dd>
            <dt>JavaScript crawl</dt><dd>{project.options.enable_crawl ? 'On' : 'Off'}</dd>
            <dt>Path probing</dt><dd>{project.options.enable_wordlist ? 'On' : 'Off'}</dd>
            <dt>Limits</dt><dd>{project.options.rate} requests/s, {project.options.max_requests} maximum</dd>
          </dl>
        </section>
        <section className="card">
          <h2>Test accounts</h2>
          {project.identities.length === 0 ? <p className="muted">None. Only unauthenticated tests will run.</p> : (
            <ul className="rows">
              {project.identities.map((i) => (
                <li key={i.name}><span><strong>{i.name}</strong><small className="muted">{i.header_names.join(', ')}: ••••••</small></span><Tag kind={i.role} /></li>
              ))}
            </ul>
          )}
        </section>
      </div>
      <section className="card">
        <h2>Scan history</h2>
        {!project.scans?.length ? <p className="muted">No scans yet. Select “Run scan” to start.</p> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Scan</th><th>Status</th><th className="num">Shadow</th><th className="num">Findings</th><th className="num">Paths</th><th /></tr></thead>
            <tbody>
              {project.scans.map((s) => (
                <tr key={s.id}>
                  <td><Link to={`/scans/${s.id}`}>#{s.id} · {when(s.created_at)}</Link></td>
                  <td><Tag kind={s.status} /></td>
                  <td className="num">{s.stats.shadow ?? '–'}</td>
                  <td className="num">{s.stats.findings ?? '–'}</td>
                  <td className="num">{s.stats.paths ?? '–'}</td>
                  <td className="num"><button className="ghost icon" onClick={() => removeScan(s.id)} aria-label={`Delete scan ${s.id}`}><Trash2 size={15} /></button></td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </section>
    </>
  )
}

import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Ghost, History, Plus, Radar, Route, Server, FlaskConical } from 'lucide-react'
import { api } from '../api'
import type { DashboardData, Project } from '../types'
import { Empty, Endpoint, ErrorBox, Loading, PageHeader, SeverityBadge, SeverityChart, Stat, Tag, useLoad, when } from '../ui'

export function useDemo() {
  const navigate = useNavigate()
  const [error, setError] = useState('')
  const open = () => api<Project>('/demo', 'POST')
    .then((p) => navigate(`/projects/${p.id}`)).catch((e: Error) => setError(e.message))
  return { open, error }
}

export default function Dashboard() {
  const { data, error } = useLoad(() => api<DashboardData>('/dashboard'), [])
  const demo = useDemo()
  if (!data) return error ? <ErrorBox message={error} /> : <Loading />
  const { totals } = data

  return (
    <>
      <PageHeader heading="Dashboard" sub="Latest completed scan of each project"
        actions={<Link to="/projects/new" className="button primary"><Plus size={16} /> New project</Link>} />
      <ErrorBox message={demo.error} />
      {totals.projects === 0 ? (
        <Empty icon={<Radar size={32} />} heading="Run your first scan">
          <p className="muted">Start with the bundled vulnerable lab to see every feature, or add your own target.</p>
          <div className="actions center">
            <button className="primary" onClick={demo.open}><FlaskConical size={16} /> Try the demo lab</button>
            <Link to="/projects/new" className="button">Add my own target</Link>
          </div>
        </Empty>
      ) : (
        <>
          <div className="grid stats">
            <Stat label="Live APIs" value={totals.live} icon={<Server size={15} />} hint={`${totals.projects} project(s)`} />
            <Stat label="Shadow APIs" value={totals.shadow} icon={<Ghost size={15} />} hint="Live but undocumented" />
            <Stat label="Zombie APIs" value={totals.zombie} icon={<History size={15} />} hint="Old versions still live" />
            <Stat label="Attack paths" value={totals.paths} icon={<Route size={15} />} hint="Verified multi-step chains" />
          </div>
          <div className="grid two">
            <section className="card">
              <h2>Open findings by severity</h2>
              <SeverityChart counts={data.severity} />
            </section>
            <section className="card">
              <h2>Recent scans</h2>
              {data.recent_scans.length === 0 ? <p className="muted">No scans yet.</p> : (
                <ul className="rows">
                  {data.recent_scans.map((s) => (
                    <li key={s.id}>
                      <Link to={`/scans/${s.id}`}><strong>{s.project_name}</strong><small className="muted">{when(s.created_at)}</small></Link>
                      <Tag kind={s.status} />
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
          <section className="card">
            <h2>Highest-risk open findings</h2>
            {data.top_findings.length === 0 ? <p className="muted">No open findings in the latest scans.</p> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Project</th><th className="num">Risk</th></tr></thead>
                <tbody>
                  {data.top_findings.map((f) => (
                    <tr key={f.id}>
                      <td><SeverityBadge level={f.severity} /></td>
                      <td><Link to={`/scans/${f.scan_id}?tab=findings&finding=${f.id}`}>{f.title}</Link><br /><Endpoint label={f.endpoint} /></td>
                      <td>{f.project}</td>
                      <td className="num">{f.score}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
          </section>
        </>
      )}
    </>
  )
}

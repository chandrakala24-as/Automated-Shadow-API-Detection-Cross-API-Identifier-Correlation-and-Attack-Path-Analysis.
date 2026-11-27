import { ArrowRight, Ghost, History, Route, Server, ShieldAlert } from 'lucide-react'
import type { Results } from '../types'
import { SEVERITIES, SeverityBadge, SeverityChart, Stat } from '../ui'

export default function Overview({ results, open }: {
  results: Results; open: (tab: string, extra?: Record<string, string>) => void
}) {
  const { stats } = results.scan
  const security = results.findings.filter((f) => !['SHADOW_API', 'ZOMBIE_API'].includes(f.type))
  const counts = Object.fromEntries(SEVERITIES.map((s) =>
    [s, results.findings.filter((f) => f.severity === s && f.triage === 'open').length])) as Record<typeof SEVERITIES[number], number>
  const top = results.paths[0]

  return (
    <>
      <div className="grid stats">
        <Stat label="Live APIs" value={stats.live} icon={<Server size={15} />} hint={`${stats.endpoints} routes discovered`} />
        <Stat label="Shadow APIs" value={stats.shadow} icon={<Ghost size={15} />} />
        <Stat label="Zombie APIs" value={stats.zombie} icon={<History size={15} />} />
        <Stat label="Vulnerabilities" value={security.length} icon={<ShieldAlert size={15} />} hint="Excludes inventory notes" />
        <Stat label="Attack paths" value={stats.paths} icon={<Route size={15} />} />
      </div>
      <div className="grid two">
        <section className="card">
          <h2>Open findings by severity</h2>
          <SeverityChart counts={counts} />
          <p className="muted small">{stats.requests} read-only requests in {stats.duration_seconds}s.</p>
        </section>
        <section className="card">
          <h2>Most serious attack path</h2>
          {top ? (
            <>
              <SeverityBadge level={top.severity} /> <strong>Risk {top.score}/100</strong>
              <p>{top.narrative}</p>
              <button onClick={() => open('paths')}>View attack paths <ArrowRight size={15} /></button>
            </>
          ) : <p className="muted">No multi-step attack path was verified. This does not prove that none exists.</p>}
        </section>
      </div>
      <section className="card">
        <div className="between"><h2>Fix these first</h2><button className="link" onClick={() => open('findings')}>All findings</button></div>
        {security.length === 0 ? <p className="muted">No vulnerabilities were verified in the routes tested.</p> : (
          <ul className="rows">
            {security.filter((f) => f.triage === 'open').slice(0, 5).map((f) => (
              <li key={f.id}>
                <button className="row-button" onClick={() => open('findings', { finding: String(f.id) })}>
                  <strong>{f.title}</strong><small className="muted mono">{f.endpoint}</small>
                </button>
                <SeverityBadge level={f.severity} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  )
}

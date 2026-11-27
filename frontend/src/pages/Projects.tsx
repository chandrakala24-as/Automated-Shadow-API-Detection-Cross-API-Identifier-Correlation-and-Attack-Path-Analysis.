import { Link } from 'react-router-dom'
import { FlaskConical, FolderKanban, Globe, Plus } from 'lucide-react'
import { api } from '../api'
import type { Project } from '../types'
import { Empty, ErrorBox, Loading, PageHeader, Tag, useLoad, when } from '../ui'
import { useDemo } from './Dashboard'

export default function Projects() {
  const { data, error } = useLoad(() => api<Project[]>('/projects'), [])
  const demo = useDemo()
  if (!data) return error ? <ErrorBox message={error} /> : <Loading />
  return (
    <>
      <PageHeader heading="Projects" sub="Each project is one target you are allowed to test"
        actions={<>
          <button onClick={demo.open}><FlaskConical size={16} /> Demo lab</button>
          <Link to="/projects/new" className="button primary"><Plus size={16} /> New project</Link>
        </>} />
      <ErrorBox message={demo.error} />
      {data.length === 0 ? (
        <Empty icon={<FolderKanban size={32} />} heading="No projects yet">
          <p className="muted">Create a project or open the demo lab.</p>
        </Empty>
      ) : (
        <div className="grid cards">
          {data.map((p) => (
            <Link to={`/projects/${p.id}`} className="card project" key={p.id}>
              <div className="between"><h2>{p.name}</h2>{p.is_demo && <Tag kind="demo">Demo</Tag>}</div>
              <p className="muted mono"><Globe size={13} /> {p.base_url}</p>
              <div className="between">
                <small className="muted">{p.scan_count} scan(s){p.last_scan ? ` · last ${when(p.last_scan.created_at)}` : ''}</small>
                {p.last_scan && <Tag kind={p.last_scan.status} />}
              </div>
            </Link>
          ))}
        </div>
      )}
    </>
  )
}

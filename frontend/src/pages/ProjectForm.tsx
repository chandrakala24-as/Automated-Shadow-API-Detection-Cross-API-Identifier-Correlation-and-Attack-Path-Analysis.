import { useEffect, useState, type ChangeEvent, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { CheckCircle2, FileUp, Plus, Trash2 } from 'lucide-react'
import { api } from '../api'
import type { Project } from '../types'
import { ErrorBox, Loading, PageHeader } from '../ui'

interface Account { name: string; role: 'user' | 'admin'; header: string; value: string; saved: boolean }

const blank = (name: string, role: Account['role'] = 'user'): Account =>
  ({ name, role, header: 'Authorization', value: '', saved: false })

function FileField({ label, hint, accept, saved, value, onChange }: {
  label: string; hint: string; accept: string; saved: boolean
  value: { name: string; text: string } | null
  onChange: (v: { name: string; text: string } | null) => void
}) {
  const [error, setError] = useState('')
  async function pick(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) return
    if (file.size > 8_000_000) return setError('The file is larger than 8 MB.')
    setError('')
    onChange({ name: file.name, text: await file.text() })
  }
  const status = value ? (value.text ? value.name : 'Will be removed') : saved ? 'A file is saved' : 'No file selected'
  return (
    <div className="file-field">
      <div><strong>{label}</strong><small className="muted">{hint}</small></div>
      <div className="actions">
        <small className={value?.text || (saved && !value) ? 'ok' : 'muted'}>
          {(value?.text || (saved && !value)) && <CheckCircle2 size={13} />} {status}
        </small>
        <label className="button"><FileUp size={15} /> Choose file<input type="file" accept={accept} onChange={pick} className="sr-only" /></label>
        {(value?.text || (saved && !value)) && (
          <button type="button" className="ghost" onClick={() => onChange(saved ? { name: '', text: '' } : null)}>Remove</button>
        )}
      </div>
      <ErrorBox message={error} />
    </div>
  )
}

export default function ProjectForm() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [loaded, setLoaded] = useState<Project | null>(null)
  const [name, setName] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [spec, setSpec] = useState<{ name: string; text: string } | null>(null)
  const [har, setHar] = useState<{ name: string; text: string } | null>(null)
  const [accounts, setAccounts] = useState<Account[]>([blank('user-a'), blank('user-b')])
  const [options, setOptions] = useState({ enable_crawl: true, enable_wordlist: true, rate: 25, max_requests: 3000 })
  const [authorized, setAuthorized] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!id) return
    api<Project>(`/projects/${id}`).then((p) => {
      setLoaded(p)
      setName(p.name)
      setBaseUrl(p.base_url)
      setOptions(p.options)
      setAccounts(p.identities.map((i) => ({ name: i.name, role: i.role, header: i.header_names[0], value: '', saved: true })))
    }).catch((e: Error) => setError(e.message))
  }, [id])

  if (id && !loaded) return error ? <ErrorBox message={error} /> : <Loading />

  const change = (index: number, patch: Partial<Account>) =>
    setAccounts(accounts.map((a, i) => (i === index ? { ...a, ...patch } : a)))

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    const body = {
      name, base_url: baseUrl.trim(), authorized, options,
      spec_text: spec ? spec.text : null,
      har_text: har ? har.text : null,
      identities: accounts.map((a) => ({
        name: a.name.trim(), role: a.role,
        headers: a.saved && !a.value ? null : { [a.header.trim()]: a.value.trim() },
      })),
    }
    try {
      const project = await api<Project>(id ? `/projects/${id}` : '/projects', id ? 'PUT' : 'POST', body)
      navigate(`/projects/${project.id}`)
    } catch (e) {
      setError((e as Error).message)
      setBusy(false)
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }

  return (
    <form onSubmit={submit} className="narrow">
      <PageHeader heading={id ? 'Edit project' : 'New project'} sub="Four short steps. You can change these later." />
      <ErrorBox message={error} />

      <section className="card step">
        <h2><span className="step-number">1</span> Target</h2>
        <label>Project name<input value={name} onChange={(e) => setName(e.target.value)} required minLength={2} placeholder="Staging storefront" /></label>
        <label>Target URL<input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} required placeholder="http://localhost:8001" type="url" />
          <small className="muted">Origin only. The scanner never leaves this host and port.</small></label>
      </section>

      <section className="card step">
        <h2><span className="step-number">2</span> API information</h2>
        <FileField label="OpenAPI / Swagger specification" accept=".json,.yaml,.yml" saved={!!loaded?.has_spec}
          hint="Needed to tell documented APIs from shadow APIs." value={spec} onChange={setSpec} />
        <FileField label="Traffic capture (HAR)" accept=".har,.json" saved={!!loaded?.has_har}
          hint="Optional. Export from browser developer tools. Captured headers are not imported." value={har} onChange={setHar} />
      </section>

      <section className="card step">
        <h2><span className="step-number">3</span> Test accounts</h2>
        <p className="muted">Use two normal users that own different data to test cross-user access. An admin account helps confirm admin-route findings. Use test accounts only. Values are encrypted and never shown again.</p>
        {accounts.map((a, i) => (
          <div className="account" key={i}>
            <label>Name<input value={a.name} required onChange={(e) => change(i, { name: e.target.value, saved: false })} /></label>
            <label>Role<select value={a.role} onChange={(e) => change(i, { role: e.target.value as Account['role'] })}>
              <option value="user">Normal user</option><option value="admin">Administrator</option></select></label>
            <label>Header<input value={a.header} required onChange={(e) => change(i, { header: e.target.value, saved: false })} /></label>
            <label className="grow">Value<input type="password" value={a.value} required={!a.saved} autoComplete="off"
              placeholder={a.saved ? 'Saved. Leave empty to keep it' : 'Bearer eyJ…'} onChange={(e) => change(i, { value: e.target.value })} /></label>
            <button type="button" className="ghost icon" aria-label={`Remove account ${a.name}`}
              onClick={() => setAccounts(accounts.filter((_, j) => j !== i))}><Trash2 size={16} /></button>
          </div>
        ))}
        {accounts.length < 6 && (
          <button type="button" onClick={() => setAccounts([...accounts, blank(`user-${accounts.length + 1}`)])}><Plus size={15} /> Add account</button>
        )}
      </section>

      <section className="card step">
        <h2><span className="step-number">4</span> Options and permission</h2>
        <label className="check"><input type="checkbox" checked={options.enable_crawl} onChange={(e) => setOptions({ ...options, enable_crawl: e.target.checked })} /> Crawl pages and analyse JavaScript</label>
        <label className="check"><input type="checkbox" checked={options.enable_wordlist} onChange={(e) => setOptions({ ...options, enable_wordlist: e.target.checked })} /> Probe common hidden paths</label>
        <div className="grid two">
          <label>Requests per second<input type="number" min={1} max={100} value={options.rate} onChange={(e) => setOptions({ ...options, rate: Number(e.target.value) })} /></label>
          <label>Maximum requests<input type="number" min={10} max={20000} value={options.max_requests} onChange={(e) => setOptions({ ...options, max_requests: Number(e.target.value) })} /></label>
        </div>
        <label className="check consent"><input type="checkbox" checked={authorized} required onChange={(e) => setAuthorized(e.target.checked)} />
          I own this system or have written permission to test it.</label>
        <small className="muted">Only GET requests are sent. Some applications still change data on GET, so prefer a test environment.</small>
      </section>

      <div className="actions end">
        <button type="button" onClick={() => navigate(-1)}>Cancel</button>
        <button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save project'}</button>
      </div>
    </form>
  )
}

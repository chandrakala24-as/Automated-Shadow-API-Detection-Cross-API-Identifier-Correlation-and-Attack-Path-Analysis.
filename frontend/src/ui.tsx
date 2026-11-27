import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { AlertCircle, AlertOctagon, AlertTriangle, Info, Loader2 } from 'lucide-react'
import type { Severity } from './types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
const SEVERITY_ICON = { critical: AlertOctagon, high: AlertTriangle, medium: AlertCircle, low: Info }

export const title = (text: string) =>
  text.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())

export const TYPE_NAMES: Record<string, string> = {
  BOLA: 'BOLA / IDOR', BFLA: 'Function-level access', SECRET_EXPOSURE: 'Secret exposure',
  MISSING_AUTHENTICATION: 'Missing authentication', INVALID_TOKEN_ACCEPTED: 'Invalid token accepted',
  SHADOW_API: 'Shadow API', ZOMBIE_API: 'Zombie API',
}

export const when = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })

/** Severity is always shown as icon + text, so colour is never the only signal. */
export function SeverityBadge({ level }: { level: Severity }) {
  const Icon = SEVERITY_ICON[level]
  return (
    <span className={`badge severity ${level}`}>
      <Icon size={12} aria-hidden /> {title(level)}
    </span>
  )
}

export function Tag({ kind, children }: { kind: string; children?: ReactNode }) {
  return <span className={`badge tag ${kind}`}>{children ?? title(kind)}</span>
}

export function Endpoint({ label }: { label: string }) {
  const [method, ...rest] = label.split(' ')
  return (
    <span className="endpoint">
      <span className={`method ${method.toLowerCase()}`}>{method}</span>
      <code>{rest.join(' ')}</code>
    </span>
  )
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return <div className="loading" role="status"><Loader2 className="spin" size={20} /> {label}</div>
}

export function ErrorBox({ message }: { message: string }) {
  if (!message) return null
  return <div className="alert error" role="alert"><AlertOctagon size={16} /> {message}</div>
}

export function Empty({ icon, heading, children }: { icon: ReactNode; heading: string; children?: ReactNode }) {
  return (
    <div className="empty card">
      <div className="empty-icon">{icon}</div>
      <h3>{heading}</h3>
      {children}
    </div>
  )
}

export function PageHeader({ heading, sub, actions }: { heading: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div><h1>{heading}</h1>{sub && <p className="muted">{sub}</p>}</div>
      <div className="actions">{actions}</div>
    </header>
  )
}

export function Stat({ label, value, hint, icon }: { label: string; value: number | string; hint?: string; icon?: ReactNode }) {
  return (
    <div className="card stat">
      <div className="stat-label">{icon}{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="muted small">{hint}</div>}
    </div>
  )
}

/** One bar per severity, with a direct count label on every row. */
export function SeverityChart({ counts }: { counts: Record<Severity, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s]))
  return (
    <ul className="severity-chart">
      {SEVERITIES.map((level) => (
        <li key={level} title={`${counts[level]} ${level} finding(s)`}>
          <SeverityBadge level={level} />
          <div className="track">
            {counts[level] > 0 && <div className={`fill ${level}`} style={{ width: `${(counts[level] / max) * 100}%` }} />}
          </div>
          <strong>{counts[level]}</strong>
        </li>
      ))}
    </ul>
  )
}

export function useLoad<T>(loader: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reload = useCallback(() => loader().then((d) => { setData(d); setError('') })
    .catch((e: Error) => setError(e.message)), deps)
  useEffect(() => { setData(undefined); void reload() }, [reload])
  return { data, error, reload, setData }
}

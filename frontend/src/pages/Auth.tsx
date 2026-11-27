import { useState, type FormEvent } from 'react'
import { Fingerprint, Route, ScanSearch, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import type { User } from '../types'
import { ErrorBox } from '../ui'

export default function Auth({ onSignedIn }: { onSignedIn: (user: User) => void }) {
  const [register, setRegister] = useState(false)
  const [form, setForm] = useState({ name: '', email: '', password: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const body = register ? form : { email: form.email, password: form.password }
      onSignedIn(await api<User>(register ? '/auth/register' : '/auth/login', 'POST', body))
    } catch (e) {
      setError((e as Error).message)
      setBusy(false)
    }
  }

  const field = (key: keyof typeof form) => ({
    id: key, value: form[key], required: true,
    onChange: (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value }),
  })

  return (
    <div className="auth">
      <section className="auth-hero">
        <div className="brand"><span className="logo"><ShieldCheck size={22} /></span> ShadowAPI</div>
        <h1>Find the APIs you forgot, and the paths an attacker would take through them.</h1>
        <ul>
          <li><ScanSearch size={20} /> Detect undocumented and outdated APIs</li>
          <li><Fingerprint size={20} /> Trace how identifiers move between APIs</li>
          <li><Route size={20} /> See multi-step attack paths backed by real requests</li>
        </ul>
        <p className="small">Test only systems you own or have written permission to assess.</p>
      </section>
      <section className="auth-form">
        <form className="card" onSubmit={submit}>
          <h2>{register ? 'Create your account' : 'Sign in'}</h2>
          <p className="muted">{register ? 'The account is stored on this computer.' : 'Welcome back.'}</p>
          <ErrorBox message={error} />
          {register && <label>Name<input {...field('name')} minLength={2} autoComplete="name" /></label>}
          <label>Email<input {...field('email')} type="email" autoComplete="email" /></label>
          <label>Password
            <input {...field('password')} type="password" minLength={register ? 10 : 1}
              autoComplete={register ? 'new-password' : 'current-password'} />
            {register && <small className="muted">At least 10 characters.</small>}
          </label>
          <button className="primary" disabled={busy}>
            {busy ? 'Please wait…' : register ? 'Create account' : 'Sign in'}
          </button>
          <button type="button" className="link" onClick={() => { setRegister(!register); setError('') }}>
            {register ? 'Already have an account? Sign in' : 'New here? Create an account'}
          </button>
        </form>
      </section>
    </div>
  )
}

import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Link, NavLink, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { BookOpen, FolderKanban, LayoutDashboard, LogOut, Moon, ShieldCheck, Sun } from 'lucide-react'
import { api } from './api'
import type { User } from './types'
import { Loading } from './ui'
import Auth from './pages/Auth'
import Dashboard from './pages/Dashboard'
import Projects from './pages/Projects'
import ProjectForm from './pages/ProjectForm'
import ProjectDetail from './pages/ProjectDetail'
import ScanPage from './pages/ScanPage'
import Help from './pages/Help'
import './styles.css'

function useTheme() {
  const [theme, setTheme] = useState(() => localStorage.getItem('theme')
    ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('theme', theme)
  }, [theme])
  return [theme, () => setTheme(theme === 'dark' ? 'light' : 'dark')] as const
}

function App() {
  const [user, setUser] = useState<User | null>()
  const [theme, toggleTheme] = useTheme()
  const location = useLocation()

  useEffect(() => {
    api<User>('/auth/me').then(setUser).catch(() => setUser(null))
    const expired = () => setUser(null)
    window.addEventListener('session-expired', expired)
    return () => window.removeEventListener('session-expired', expired)
  }, [])

  if (user === undefined) return <Loading />
  if (user === null) return <Auth onSignedIn={setUser} />

  const signOut = () => api('/auth/logout', 'POST').finally(() => setUser(null))
  return (
    <div className="shell">
      <aside className="sidebar">
        <Link to="/" className="brand"><span className="logo"><ShieldCheck size={20} /></span> ShadowAPI</Link>
        <nav aria-label="Main">
          <NavLink to="/" end><LayoutDashboard size={18} /> <span>Dashboard</span></NavLink>
          <NavLink to="/projects"><FolderKanban size={18} /> <span>Projects</span></NavLink>
          <NavLink to="/help"><BookOpen size={18} /> <span>Guide</span></NavLink>
        </nav>
        <div className="sidebar-footer">
          <button className="ghost" onClick={toggleTheme}>
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            <span>{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
          </button>
          <div className="user">
            <div className="avatar">{user.name.charAt(0).toUpperCase()}</div>
            <div className="user-text"><strong>{user.name}</strong><small>{user.email}</small></div>
            <button className="ghost icon" onClick={signOut} aria-label="Sign out" title="Sign out"><LogOut size={16} /></button>
          </div>
        </div>
      </aside>
      <main key={location.pathname}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/projects/new" element={<ProjectForm />} />
          <Route path="/projects/:id" element={<ProjectDetail />} />
          <Route path="/projects/:id/edit" element={<ProjectForm />} />
          <Route path="/scans/:id" element={<ScanPage />} />
          <Route path="/help" element={<Help />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode><BrowserRouter><App /></BrowserRouter></StrictMode>,
)

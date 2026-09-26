import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { Link, Route, Routes, useLocation, Navigate, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Activity, ShieldCheck, Sun, Moon, Laptop, Lock, LogOut } from 'lucide-react'

import Login from './pages/Login'
import Upload from './pages/Upload'
import Investigations from './pages/Investigations'
import AnalysisJob from './pages/AnalysisJob'
import Dashboard from './pages/Dashboard'
import SessionDetail from './pages/SessionDetail'
import ExportPage from './pages/Export'
import AnalystDashboard from './pages/AnalystDashboard'
import AuditorDashboard from './pages/AuditorDashboard'
import AdminDashboard from './pages/AdminDashboard'
import { health as fetchHealth } from './lib/api'
import { AuthContext, useAuth } from './lib/auth'

export const ReportContext = createContext({ report: null, setReport: () => {} })
export const useReport = () => useContext(ReportContext)

function useTheme() {
  const [theme, setTheme] = useState(
    () => {
      try { return localStorage.getItem('sms-theme') || 'system' }
      catch { return 'system' }
    },
  )

  useEffect(() => {
    const root = document.documentElement
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const apply = () => {
      const dark = theme === 'dark' || (theme === 'system' && media.matches)
      root.classList.toggle('dark', dark)
    }
    apply()
    try {
      localStorage.setItem('sms-theme', theme)
    } catch {}
    media.addEventListener('change', apply)
    return () => media.removeEventListener('change', apply)
  }, [theme])

  return [theme, setTheme]
}

function Header({ health }) {
  const [theme, setTheme] = useTheme()
  const { pathname } = useLocation()
  const { token, logout, role } = useAuth()
  const navigate = useNavigate()

  const ThemeIcon = theme === 'dark' ? Moon : theme === 'light' ? Sun : Laptop

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  let dashboardPath = '/';
  if (role === 'ROLE_SOC_ANALYST') dashboardPath = '/analyst-dashboard';
  else if (role === 'ROLE_AUDITOR') dashboardPath = '/auditor-dashboard';
  else if (role === 'ROLE_ADMIN') dashboardPath = '/admin-dashboard';

  return (
    <header className="border-b border-line bg-surface/80 backdrop-blur-xl sticky top-0 z-50 transition-colors duration-300">
      <div className="max-w-[1240px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <Link to={token ? dashboardPath : "/login"} className="flex items-center gap-2.5 no-underline text-accent shrink-0 group">
            <div className="w-7 h-7 bg-accent text-surface rounded-md flex items-center justify-center transition-transform duration-300 shadow-[0_0_15px_rgba(0,255,65,0.4)] group-hover:shadow-[0_0_25px_rgba(0,255,65,0.6)]">
              <ShieldCheck size={16} className="stroke-[2.5px]" />
            </div>
            <span className="font-display font-bold text-[15px] tracking-tight uppercase">
              SecureMailScope
            </span>
          </Link>

          {token && role === 'ROLE_SOC_ANALYST' && (
            <nav className="hidden sm:flex gap-1 text-[14px]">
              <NavLink to="/analyst-dashboard" active={pathname === '/analyst-dashboard'}>
                New Analysis
              </NavLink>
              <NavLink to="/investigations" active={pathname.startsWith('/investigations')}>
                Investigations
              </NavLink>
            </nav>
          )}
          {token && role === 'ROLE_AUDITOR' && (
            <nav className="hidden sm:flex gap-1 text-[14px]">
              <NavLink to="/auditor-dashboard" active={pathname === '/auditor-dashboard'}>
                Compliance Overview
              </NavLink>
            </nav>
          )}
          {token && role === 'ROLE_ADMIN' && (
            <nav className="hidden sm:flex gap-1 text-[14px]">
              <NavLink to="/admin-dashboard" active={pathname === '/admin-dashboard'}>
                Administration
              </NavLink>
            </nav>
          )}
        </div>

        <div className="flex items-center gap-3 sm:gap-4">
          <div
            className={`flex items-center gap-2 text-[12px] font-medium px-2.5 py-1 rounded-full border transition-all duration-300 shadow-sm ${
              health?.status === 'UP' 
                ? 'bg-ok/10 border-ok/20 text-ok' 
                : health?.reachable 
                  ? 'bg-med/10 border-med/20 text-med' 
                  : 'bg-crit/10 border-crit/20 text-crit'
            }`}
          >
            <span className="relative flex h-2 w-2">
              {health?.status === 'UP' && (
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-ok opacity-40"></span>
              )}
              <span className={`relative inline-flex rounded-full h-2 w-2 ${health?.status === 'UP' ? 'bg-ok' : health?.reachable ? 'bg-med' : 'bg-crit'}`}></span>
            </span>
            {health ? (health.status === 'UP' ? 'Connected' : health.reachable ? 'Degraded' : 'Offline') : 'Connecting...'}
          </div>
          
          <div className="w-px h-4 bg-line hidden sm:block"></div>
          
          <button
            type="button"
            onClick={() =>
              setTheme(theme === 'dark' ? 'light' : theme === 'light' ? 'system' : 'dark')
            }
            className="w-8 h-8 flex items-center justify-center rounded-full border border-line bg-surface hover:bg-surface-2 text-ink-2 hover:text-ink transition-all duration-200 focus-visible:outline-accent shadow-sm"
            title="Switch theme"
          >
            <ThemeIcon size={14} className="transition-transform duration-300" />
          </button>

          {token && (
            <>
              <div className="w-px h-4 bg-line hidden sm:block"></div>
              <button
                type="button"
                onClick={handleLogout}
                className="flex items-center gap-2 text-[12px] font-medium text-ink-2 hover:text-crit transition-colors px-2"
                title="Logout"
              >
                <LogOut size={14} /> Logout
              </button>
            </>
          )}
        </div>
      </div>
    </header>
  )
}

function NavLink({ to, active, children }) {
  return (
    <Link
      to={to}
      className={`px-3 py-1.5 rounded-md no-underline transition-all duration-200 text-[13px] ${
        active 
          ? 'text-ink font-semibold bg-surface-2' 
          : 'text-ink-2 hover:text-ink hover:bg-surface-2'
      }`}
    >
      {children}
    </Link>
  )
}

function PageWrapper({ children }) {
  const { pathname } = useLocation();
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={pathname}
        initial={{ opacity: 0, y: 8, filter: 'blur(4px)' }}
        animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
        exit={{ opacity: 0, y: -8, filter: 'blur(4px)' }}
        transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
        className="h-full"
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
}

function ProtectedRoute({ children, allowedRoles }) {
  const { token, role } = useAuth();
  
  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(role)) {
    return <Navigate to="/" replace />;
  }

  return children;
}

export default function App() {
  const [report, setReport] = useState(null)
  const [health, setHealth] = useState(null)

  // Auth State
  const [token, setToken] = useState(() => localStorage.getItem('sms-token'))
  const [role, setRole] = useState(() => {
    const t = localStorage.getItem('sms-token')
    if (t) {
      try { return JSON.parse(atob(t.split('.')[1])).role } catch (e) { return null }
    }
    return null
  })

  useEffect(() => {
    let cancelled = false
    fetchHealth().then((h) => {
      if (!cancelled) setHealth(h)
    })
    return () => {
      cancelled = true
    }
  }, [])

  const login = (jwt) => {
    localStorage.setItem('sms-token', jwt)
    setToken(jwt)
    try {
      const payload = JSON.parse(atob(jwt.split('.')[1]))
      setRole(payload.role)
    } catch (e) {
      setRole(null)
    }
  }

  const logout = () => {
    localStorage.removeItem('sms-token')
    setToken(null)
    setRole(null)
  }

  const authCtx = useMemo(() => ({ token, role, login, logout }), [token, role])
  const reportCtx = useMemo(() => ({ report, setReport, health }), [report, health])

  // Determine root redirect
  const RootRedirect = () => {
    if (!token) return <Navigate to="/login" replace />
    if (role === 'ROLE_SOC_ANALYST') return <Navigate to="/analyst-dashboard" replace />
    if (role === 'ROLE_AUDITOR') return <Navigate to="/auditor-dashboard" replace />
    if (role === 'ROLE_ADMIN') return <Navigate to="/admin-dashboard" replace />
    return <Navigate to="/login" replace />
  }

  return (
    <AuthContext.Provider value={authCtx}>
      <ReportContext.Provider value={reportCtx}>
        <div className="min-h-full flex flex-col bg-paper transition-colors duration-300">
          <Header health={health} />
          <main className="flex-1 max-w-[1240px] w-full mx-auto px-4 sm:px-6 py-8">
            <PageWrapper>
              <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/" element={<RootRedirect />} />
                
                {/* ROLE_SOC_ANALYST Routes */}
                <Route path="/analyst-dashboard" element={
                  <ProtectedRoute allowedRoles={['ROLE_SOC_ANALYST']}>
                    <AnalystDashboard />
                  </ProtectedRoute>
                } />
                <Route path="/investigations" element={
                  <ProtectedRoute allowedRoles={['ROLE_SOC_ANALYST']}>
                    <Investigations />
                  </ProtectedRoute>
                } />
                <Route path="/investigations/:investigationId" element={
                  <ProtectedRoute allowedRoles={['ROLE_SOC_ANALYST']}>
                    <Investigations />
                  </ProtectedRoute>
                } />
                <Route path="/jobs/:id" element={
                  <ProtectedRoute allowedRoles={['ROLE_SOC_ANALYST']}>
                    <AnalysisJob />
                  </ProtectedRoute>
                } />
                <Route path="/report/:id" element={
                  <ProtectedRoute allowedRoles={['ROLE_SOC_ANALYST', 'ROLE_AUDITOR']}>
                    <Dashboard />
                  </ProtectedRoute>
                } />
                <Route path="/report/:id/sessions/:stream" element={
                  <ProtectedRoute allowedRoles={['ROLE_SOC_ANALYST', 'ROLE_AUDITOR']}>
                    <SessionDetail />
                  </ProtectedRoute>
                } />
                <Route path="/report/:id/export" element={
                  <ProtectedRoute allowedRoles={['ROLE_SOC_ANALYST', 'ROLE_AUDITOR']}>
                    <ExportPage />
                  </ProtectedRoute>
                } />

                {/* ROLE_AUDITOR Routes */}
                <Route path="/auditor-dashboard" element={
                  <ProtectedRoute allowedRoles={['ROLE_AUDITOR']}>
                    <AuditorDashboard />
                  </ProtectedRoute>
                } />

                {/* ROLE_ADMIN Routes */}
                <Route path="/admin-dashboard" element={
                  <ProtectedRoute allowedRoles={['ROLE_ADMIN']}>
                    <AdminDashboard />
                  </ProtectedRoute>
                } />

                <Route
                  path="*"
                  element={
                    <div className="flex flex-col items-center justify-center py-32 animate-fade-in">
                      <ShieldCheck size={48} className="text-line-2 mb-4" />
                      <div className="font-display text-2xl font-bold mb-2 text-ink">
                        Page Not Found
                      </div>
                      <Link to="/" className="text-accent font-medium hover:underline mt-4">
                        Return to Home
                      </Link>
                    </div>
                  }
                />
              </Routes>
            </PageWrapper>
          </main>
          <footer className="border-t border-line py-6 bg-surface mt-auto">
            <div className="max-w-[1240px] mx-auto px-6 font-mono text-[11px] text-ink-3 leading-relaxed flex flex-col sm:flex-row justify-between items-center gap-4">
              <span>Passive analysis only — no packet is ever transmitted and no server is contacted.</span>
              <span className="font-medium text-ink-2">Grades scoped to capture sessions.</span>
            </div>
          </footer>
        </div>
      </ReportContext.Provider>
    </AuthContext.Provider>
  )
}

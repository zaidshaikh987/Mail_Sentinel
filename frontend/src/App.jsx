import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { Link, Route, Routes, useLocation } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Activity, ShieldCheck, Sun, Moon, Laptop, FolderGit2, FileCode2 } from 'lucide-react'

import Upload from './pages/Upload'
import Investigations from './pages/Investigations'
import AnalysisJob from './pages/AnalysisJob'
import Dashboard from './pages/Dashboard'
import SessionDetail from './pages/SessionDetail'
import ExportPage from './pages/Export'
import { health as fetchHealth } from './lib/api'

/* The report currently on screen, and the capture id it belongs to. */
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
    } catch {
      /* private browsing; the choice simply will not persist */
    }
    media.addEventListener('change', apply)
    return () => media.removeEventListener('change', apply)
  }, [theme])

  return [theme, setTheme]
}

function Header({ health }) {
  const [theme, setTheme] = useTheme()
  const { pathname } = useLocation()

  const ThemeIcon = theme === 'dark' ? Moon : theme === 'light' ? Sun : Laptop

  return (
    <header className="border-b border-line bg-surface/80 backdrop-blur-xl sticky top-0 z-50 transition-colors duration-300">
      <div className="max-w-[1240px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <Link to="/" className="flex items-center gap-2.5 no-underline text-accent shrink-0 group">
            <div className="w-7 h-7 bg-accent text-surface rounded-md flex items-center justify-center transition-transform duration-300 shadow-[0_0_15px_rgba(0,255,65,0.4)] group-hover:shadow-[0_0_25px_rgba(0,255,65,0.6)]">
              <ShieldCheck size={16} className="stroke-[2.5px]" />
            </div>
            <span className="font-display font-bold text-[15px] tracking-tight uppercase">
              MailSentinel
            </span>
          </Link>

          <nav className="hidden sm:flex gap-1 text-[14px]">
            <NavLink to="/" active={pathname === '/'}>
              New Analysis
            </NavLink>
            <NavLink to="/investigations" active={pathname.startsWith('/investigations')}>
              Investigations
            </NavLink>
          </nav>
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
            title={
              health?.status === 'UP'
                ? 'API and analysis engine both responding'
                : health?.reachable
                  ? health.error || 'The API is up but cannot run the analysis engine'
                  : 'The API is not answering on /api'
            }
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

export default function App() {
  const [report, setReport] = useState(null)
  const [health, setHealth] = useState(null)

  useEffect(() => {
    let cancelled = false
    fetchHealth().then((h) => {
      if (!cancelled) setHealth(h)
    })
    return () => {
      cancelled = true
    }
  }, [])

  const ctx = useMemo(() => ({ report, setReport, health }), [report, health])

  return (
    <ReportContext.Provider value={ctx}>
      <div className="min-h-full flex flex-col bg-paper transition-colors duration-300">
        <Header health={health} />
        <main className="flex-1 max-w-[1240px] w-full mx-auto px-4 sm:px-6 py-8">
          <PageWrapper>
            <Routes>
              <Route path="/" element={<Upload />} />
              <Route path="/investigations" element={<Investigations />} />
              <Route path="/investigations/:investigationId" element={<Investigations />} />
              <Route path="/jobs/:id" element={<AnalysisJob />} />
              <Route path="/report/:id" element={<Dashboard />} />
              <Route path="/report/:id/sessions/:stream" element={<SessionDetail />} />
              <Route path="/report/:id/export" element={<ExportPage />} />
              <Route
                path="*"
                element={
                  <div className="flex flex-col items-center justify-center py-32 animate-fade-in">
                    <ShieldCheck size={48} className="text-line-2 mb-4" />
                    <div className="font-display text-2xl font-bold mb-2 text-ink">
                      Page Not Found
                    </div>
                    <Link to="/" className="text-accent font-medium hover:underline mt-4">
                      Return to New Analysis
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
  )
}

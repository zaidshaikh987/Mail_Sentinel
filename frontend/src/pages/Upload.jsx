import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { UploadCloud, FileType, Search, Info, HardDrive, ShieldCheck, Zap, FolderGit2 } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

import { Card, GradeBadge, Label, Notice, Spinner } from '../components/ui'
import { useReport } from '../App'
import {
  adaptBackendCapture,
  analyseDemoCapture,
  getCapture,
  listDemoCaptures,
  listInvestigations,
  uploadCapture,
} from '../lib/api'

export default function Upload() {
  const navigate = useNavigate()
  const [search] = useSearchParams()
  const [investigations, setInvestigations] = useState([])
  const [investigationId, setInvestigationId] = useState(search.get('investigation') || '')
  
  useEffect(() => { listInvestigations().then(setInvestigations).catch(() => {}) }, [])
  const { setReport, health } = useReport()
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState(null)
  const [demos, setDemos] = useState([])
  const inputRef = useRef(null)

  const ready = health?.status === 'UP'

  useEffect(() => {
    let cancelled = false
    if (!health?.reachable) return undefined
    listDemoCaptures()
      .then((list) => {
        if (!cancelled) setDemos(list)
      })
      .catch(() => {
        if (!cancelled) setDemos([])
      })
    return () => {
      cancelled = true
    }
  }, [health?.reachable])

  const show = useCallback(async (created) => {
    navigate(`/jobs/${created.id}`)
  }, [navigate])

  const handleFile = useCallback(
    async (file) => {
      if (!file) return
      setError(null)
      setBusy(`Analysing ${file.name}…`)
      try {
        await show(await uploadCapture(file, { investigationId }))
      } catch (e) {
        setError(e.message)
      } finally {
        setBusy(null)
      }
    },
    [show, investigationId],
  )

  const runDemo = useCallback(
    async (name) => {
      setError(null)
      setBusy(`Analysing ${name}…`)
      try {
        await show(await analyseDemoCapture(name, investigationId))
      } catch (e) {
        setError(e.message)
      } finally {
        setBusy(null)
      }
    },
    [show, investigationId],
  )

  return (
    <motion.div 
      initial={{ opacity: 0, y: 15 }} 
      animate={{ opacity: 1, y: 0 }} 
      transition={{ duration: 0.4, ease: "easeOut" }}
      className="max-w-[800px] mx-auto py-8"
    >
      <div className="mb-10 text-center flex flex-col items-center">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 bg-surface-2 text-ink-2 rounded-full text-[11px] font-bold uppercase tracking-wider mb-5 border border-line shadow-sm hover:border-line-2 transition-colors cursor-default">
          <Zap size={13} className="text-accent" /> Security Assessment
        </div>
        <h1 className="font-display text-[36px] sm:text-[44px] leading-[1.1] font-bold tracking-tight m-0 text-ink mb-4">
          Analyse a network capture
        </h1>
        <p className="text-ink-2 max-w-[56ch] leading-relaxed text-[16px] font-medium">
          Review encryption, certificates and STARTTLS use in recorded email traffic.
          Upload a capture to see security grades, supporting evidence and recommended fixes.
        </p>
      </div>

      <AnimatePresence>
        {health && !health.reachable && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
            <Notice tone="warn" title="The API is not running" className="mb-6 shadow-sm">
              Start it with <code className="font-mono text-[12.5px] bg-warn/10 border border-warn/20 px-1.5 py-0.5 rounded">docker compose up</code>, or{' '}
              <code className="font-mono text-[12.5px] bg-warn/10 border border-warn/20 px-1.5 py-0.5 rounded">java -jar backend/target/mailsentinel-1.0.0.jar</code>{' '}
              from the project root. This page will work as soon as it answers.
            </Notice>
          </motion.div>
        )}
        {health?.reachable && health.status !== 'UP' && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
            <Notice tone="warn" title="The API is running but cannot reach the analysis engine" className="mb-6 shadow-sm">
              {health.error || 'The engine could not be imported.'}
              {health.hint ? ` ${health.hint}` : ''}
            </Notice>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="bg-surface/80 backdrop-blur-xl p-5 sm:p-6 rounded-2xl border border-line shadow-sm mb-6 flex flex-col sm:flex-row sm:items-center gap-4 transition-shadow hover:shadow-soft">
        <div className="flex-1">
          <label className="text-[13px] font-semibold text-ink flex items-center gap-2 mb-1">
            <FolderGit2 size={16} className="text-ink-3" /> Target Investigation
          </label>
          <p className="text-[12.5px] text-ink-3">Group this capture with others for history and comparison.</p>
        </div>
        <select className="field flex-1 max-w-[320px] cursor-pointer" value={investigationId} onChange={e => setInvestigationId(e.target.value)} disabled={!!busy}>
          <option value="">Standalone analysis (No group)</option>
          {investigations.map(i => <option key={i.id} value={i.id}>{i.name}</option>)}
        </select>
      </div>

      <Card
        className={`capture-dropzone relative group p-10 sm:p-16 text-center ${dragging ? 'is-dragging ring-2 ring-accent ring-offset-2 ring-offset-paper' : ''}`}
        aria-busy={!!busy}
        onDragOver={(e) => {
          e.preventDefault()
          if (ready && !busy) setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          if (ready && !busy) handleFile(e.dataTransfer.files?.[0])
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap,.gz"
          className="hidden"
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
        <AnimatePresence mode="wait">
          {busy ? (
            <motion.div 
              key="busy"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="flex flex-col items-center justify-center py-6"
            >
              <Spinner label={busy} />
              <p className="mt-4 text-ink-2 font-medium">Processing evidence securely...</p>
            </motion.div>
          ) : (
            <motion.div 
              key="idle"
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center pointer-events-none"
            >
              <div className="w-16 h-16 mb-6 bg-surface-2 shadow-sm border border-line rounded-2xl flex items-center justify-center text-ink group-hover:scale-110 transition-transform duration-300">
                <UploadCloud size={32} strokeWidth={1.5} />
              </div>
              <h2 className="font-display text-[22px] sm:text-[26px] font-semibold mb-3 text-ink tracking-tight">
                Drop a <span className="capture-format">.pcap</span> or <span className="capture-format">.pcapng</span> file here
              </h2>
              <p className="text-ink-2 text-[14px] mb-8 flex items-center justify-center gap-2 font-medium">
                <FileType size={16} /> Up to 2 GB · .cap and .gz files also supported
              </p>
              <button
                type="button"
                disabled={!ready}
                onClick={() => inputRef.current?.click()}
                className="capture-choose mb-6 pointer-events-auto active:scale-95"
              >
                Select capture file
              </button>
              <div className="font-mono text-[11px] text-ink-3 flex items-center gap-1.5 bg-surface-2/50 border border-line/50 px-3 py-1.5 rounded-lg shadow-sm">
                <ShieldCheck size={12} />
                Each report includes the capture’s SHA-256 hash for evidence tracking.
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Card>

      <AnimatePresence>
        {error && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <Notice tone="crit" title="Analysis Failed" className="mt-6">
              {error}
            </Notice>
          </motion.div>
        )}
      </AnimatePresence>

      {demos.length > 0 && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mt-14"
        >
          <div className="flex flex-col items-center text-center mb-6">
            <Label className="text-ink font-bold mb-2">Sample captures</Label>
            <p className="text-[14px] text-ink-2 max-w-[60ch] leading-relaxed font-medium">
              Choose a sample to try the workflow. Each includes a known security issue or a
              correctly encrypted session; the expected grade is shown alongside it.
            </p>
          </div>
          
          <div className="grid gap-4 sm:grid-cols-2">
            {demos.map((d) => (
              <button
                key={d.name}
                type="button"
                disabled={!ready || !!busy}
                onClick={() => runDemo(d.name)}
                className="group flex flex-col text-left bg-surface/80 backdrop-blur-xl shadow-sm border border-line rounded-2xl p-5 hover:border-ink-3 hover:shadow-soft transition-all disabled:opacity-50 disabled:hover:border-line focus-visible:outline-accent outline-offset-2 active:scale-[0.99]"
              >
                <div className="flex items-center justify-between mb-3 w-full">
                  <div className="font-mono text-[11px] font-semibold tracking-wide text-ink-3 bg-surface-2 px-2 py-1 rounded-md border border-line/50 truncate max-w-[70%]">
                    {d.name}
                  </div>
                  <GradeBadge grade={d.grade} size="sm" title={`Grades ${d.grade}`} className="group-hover:scale-110 transition-transform shadow-sm" />
                </div>
                
                <span className="font-display font-bold text-[16px] text-ink group-hover:text-accent transition-colors mb-2">
                  {d.title}
                </span>
                <span className="block text-[13.5px] text-ink-2 leading-relaxed font-medium">
                  {d.note}
                </span>
              </button>
            ))}
          </div>
        </motion.div>
      )}
    </motion.div>
  )
}


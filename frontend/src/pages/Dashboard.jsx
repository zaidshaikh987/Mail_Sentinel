import React, { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { Activity, Download, ShieldAlert, Server, Network, ShieldCheck, ArrowRight, ArrowLeft, BarChart2 } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'

import {
  Card,
  Chip,
  Empty,
  GradeBadge,
  Label,
  Notice,
  SeverityPill,
  Spinner,
  StatTile,
} from '../components/ui'
import { Coverage, HistoryAssessment } from '../components/Assessment'
import { useReport } from '../App'
import { adaptBackendCapture, getCapture, retryRun } from '../lib/api'
import { bytes, datetime, sessionKind, shortHash, titleCase } from '../lib/format'

export default function Dashboard() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { report, setReport } = useReport()
  const [error, setError] = useState(null)
  const [rerunning, setRerunning] = useState(false)
  const [loading, setLoading] = useState(!report)

  useEffect(() => {
    if (report?.id && String(report.id) === String(id)) {
      setLoading(false)
      return
    }
    let cancelled = false
    setLoading(true)
    ;(async () => {
      try {
        const detail = await getCapture(id)
        if (!cancelled) setReport({ report: adaptBackendCapture(detail), id: detail.id })
      } catch (e) {
        if (!cancelled) setError(e.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [id, report, setReport])

  if (loading) {
    return (
      <div className="py-32 flex flex-col items-center justify-center animate-pulse-soft">
        <Spinner label="Loading the analysis…" />
      </div>
    )
  }
  if (error) {
    return (
      <Empty title="That analysis could not be loaded">
        <p className="mb-4">{error}</p>
        <Link to="/" className="action inline-flex items-center gap-2">
          Start again
        </Link>
      </Empty>
    )
  }
  if (!report?.report) {
    return (
      <Empty title="Nothing loaded">
        <Link to="/" className="text-accent underline font-medium hover:text-ink">
          Pick a capture
        </Link>{' '}
        to begin.
      </Empty>
    )
  }

  const r = report.report
  const c = r.capture || {}
  const counts = r.counts || {}

  const severityData = [
    { name: 'Critical', value: counts.critical || 0, color: '#ff003c' },
    { name: 'High', value: counts.high || 0, color: '#ff9d00' },
    { name: 'Medium', value: counts.medium || 0, color: '#ffea00' },
    { name: 'Low', value: counts.low || 0, color: '#005f00' }
  ].filter(d => d.value > 0);

  const gradeCounts = {'A+':0, 'A':0, 'B':0, 'C':0, 'D':0, 'E':0, 'F':0};
  (r.assets || []).forEach(a => {
    if (a.grade?.letter) {
      gradeCounts[a.grade.letter] = (gradeCounts[a.grade.letter] || 0) + 1;
    }
  });
  
  const gradeData = Object.entries(gradeCounts).map(([letter, count]) => ({
    name: letter,
    count: count,
    color: ['A+', 'A', 'B'].includes(letter) ? '#00ff41' : (['C', 'D'].includes(letter) ? '#ff9d00' : '#ff003c')
  }));

  const containerVariants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: {
        staggerChildren: 0.05
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0 }
  };

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show">
      {r.investigation_id && (
        <motion.div variants={itemVariants}>
          <Link className="inline-flex items-center gap-2 text-ink-2 hover:text-ink text-sm font-medium mb-6 transition-colors" to={`/investigations/${r.investigation_id}`}>
            <ArrowLeft size={16}/> Investigation & comparisons
          </Link>
        </motion.div>
      )}

      {/* Headline */}
      <motion.div variants={itemVariants} className="flex items-start gap-4 justify-between flex-wrap mb-8 bg-surface p-6 sm:p-8 rounded-2xl shadow-sm border border-line">
        <div className="min-w-0">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-accent-soft text-accent rounded-full text-[11px] font-semibold uppercase tracking-wider mb-3">
            <ShieldCheck size={14} /> Cryptographic Posture
          </div>
          <h1 className="font-display text-[24px] sm:text-[32px] font-bold tracking-tight m-0 break-all text-ink leading-tight">
            {c.filename}
          </h1>
          <div className="flex flex-wrap items-center gap-3 font-mono text-[12px] text-ink-3 mt-3">
            <span className="bg-surface-2 px-2 py-1 rounded">{c.format}</span>
            <span>{c.packet_count} pkts</span>
            <span>{bytes(c.bytes)}</span>
            <span className="hidden sm:inline">·</span>
            <span>Captured {datetime(c.first_packet_time)}</span>
            <span className="hidden sm:inline">·</span>
            <span className="truncate max-w-[200px]" title={c.sha256}>SHA-256 {shortHash(c.sha256, 32)}</span>
          </div>
        </div>
        
        <div className="flex flex-col gap-3 shrink-0">
          <Link
            to={`/report/${id}/export`}
            className="flex items-center justify-center gap-2 font-semibold text-[13px] px-5 py-2.5 rounded-lg border border-line bg-surface text-ink hover:text-accent hover:border-accent hover:shadow-sm transition-all"
          >
            <Download size={16} /> Export
          </Link>
          <button 
            type="button" 
            className="flex items-center justify-center gap-2 font-semibold text-[13px] px-5 py-2.5 rounded-lg border border-line bg-surface-2 text-ink-2 hover:text-ink hover:bg-surface-3 transition-all" 
            disabled={rerunning} 
            onClick={async () => {
              setRerunning(true)
              try { const run = await retryRun(id); navigate(`/jobs/${run.id}`) }
              catch (e) { setError(e.message) }
              finally { setRerunning(false) }
            }}
          >
            <Activity size={16} className={rerunning ? "animate-spin" : ""} />
            {rerunning ? 'Creating...' : 'Reanalyse'}
          </button>
        </div>
      </motion.div>

      <motion.div variants={itemVariants} className="flex flex-col lg:flex-row gap-6 mb-10">
        <div className="flex-shrink-0 flex justify-center lg:justify-start items-center">
          <GradeBadge grade={r.overall_grade} size="lg" className="transform scale-110" />
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3 flex-1 w-full">
          <StatTile label="Sessions" value={counts.sessions ?? 0} tone="accent" />
          <StatTile label="Servers" value={counts.assets ?? 0} tone="accent" />
          <StatTile label="Critical" value={counts.critical ?? 0} tone="critical" />
          <StatTile label="High" value={counts.high ?? 0} tone="high" />
          <StatTile label="Medium" value={counts.medium ?? 0} tone="medium" />
          <StatTile
            label="Creds Exposed"
            value={counts.credentials_exposed ?? 0}
            tone={counts.credentials_exposed ? 'critical' : 'ok'}
          />
        </div>
      </motion.div>

      {/* Visual Analytics */}
      <motion.section variants={itemVariants} className="mb-10">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-info-soft text-info rounded-lg"><BarChart2 size={20}/></div>
          <div>
            <h2 className="font-display text-[20px] font-bold tracking-tight text-ink m-0">Visual Summary</h2>
            <p className="text-[13px] text-ink-3 font-medium">Risk distribution across the dataset</p>
          </div>
        </div>
        
        <div className="grid md:grid-cols-2 gap-6">
          <Card className="p-6 bg-surface border-line shadow-sm">
            <h3 className="font-bold text-ink mb-6">Severity Distribution</h3>
            {severityData.length > 0 ? (
              <div className="h-[250px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={5}
                      dataKey="value"
                      stroke="none"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip 
                      contentStyle={{ backgroundColor: '#0a140a', border: '1px solid #003b00', borderRadius: '8px' }}
                      itemStyle={{ color: '#e0ffe0' }}
                    />
                    <Legend verticalAlign="bottom" height={36} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-[250px] flex items-center justify-center text-ink-3">No findings to display.</div>
            )}
          </Card>

          <Card className="p-6 bg-surface border-line shadow-sm">
            <h3 className="font-bold text-ink mb-6">Asset Grades</h3>
            <div className="h-[250px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={gradeData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#003b00" vertical={false} />
                  <XAxis dataKey="name" stroke="#008f11" tick={{ fill: '#008f11' }} axisLine={false} tickLine={false} />
                  <YAxis stroke="#008f11" tick={{ fill: '#008f11' }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#0a140a', border: '1px solid #003b00', borderRadius: '8px' }}
                    cursor={{ fill: '#0a140a' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {gradeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      </motion.section>

      <motion.div variants={itemVariants} className="grid md:grid-cols-2 gap-6 mb-10">
        <div className="space-y-6">
          <Coverage coverage={r.coverage} />
          
          <details className="text-sm bg-surface rounded-xl border border-line overflow-hidden group shadow-sm">
            <summary className="cursor-pointer font-semibold text-ink p-4 flex items-center justify-between hover:bg-surface-2 transition-colors">
              Analysis Provenance
              <span className="text-ink-3 font-mono text-xs group-open:rotate-180 transition-transform">▼</span>
            </summary>
            <dl className="p-4 pt-0 space-y-3 bg-surface border-t border-line/50">
              {Object.entries(r.provenance || {}).map(([key, value]) => (
                <div key={key} className="flex flex-col">
                  <dt className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-0.5">{key.replaceAll('_', ' ')}</dt>
                  <dd className="font-mono text-xs break-all text-ink-2 bg-surface-2 p-2 rounded">{String(value)}</dd>
                </div>
              ))}
            </dl>
          </details>
        </div>
        <div>
          <HistoryAssessment history={r.history} />
          
          {(r.warnings || []).length > 0 && (
            <div className="mt-6 space-y-3">
              <h3 className="font-semibold text-[15px] flex items-center gap-2 text-ink"><ShieldAlert size={16} className="text-crit"/> Capture Notes</h3>
              {(r.warnings || []).map((w, i) => (
                <Notice key={i} tone="warn" className="shadow-sm">
                  {w}
                </Notice>
              ))}
            </div>
          )}
        </div>
      </motion.div>

      {/* Servers */}
      <motion.section variants={itemVariants} className="mb-12">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-accent-soft text-accent rounded-lg"><Server size={20}/></div>
          <div>
            <h2 className="font-display text-[20px] font-bold tracking-tight text-ink m-0">Servers, worst first</h2>
            <p className="text-[13px] text-ink-3 font-medium">Ranked by risk × traffic volume</p>
          </div>
        </div>
        
        <Card className="overflow-x-auto shadow-sm rounded-xl border-line">
          <table className="w-full text-[13.5px] min-w-[720px] whitespace-nowrap">
            <thead>
              <tr className="bg-surface-2 border-b border-line text-ink-2">
                <Th>Server</Th>
                <Th>Protocol</Th>
                <Th>Role</Th>
                <Th>Grade</Th>
                <Th className="text-right">Score</Th>
                <Th>TLS Coverage</Th>
                <Th className="text-right">Sessions</Th>
                <Th className="text-right">Exposure</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/50 bg-surface">
              {(r.assets || []).map((a) => (
                <tr key={a.key} className="hover:bg-surface-2/50 transition-colors">
                  <Td className="font-mono font-medium">{a.host}:{a.port}</Td>
                  <Td className="font-bold text-ink-2">{String(a.protocol || '').toUpperCase()}</Td>
                  <Td>
                    <Chip tone={a.role === 'mta_relay' ? 'muted' : 'accent'}>
                      {a.role === 'mta_relay' ? 'relay' : 'submission'}
                    </Chip>
                  </Td>
                  <Td>
                    <div className="flex items-center gap-2">
                      <GradeBadge grade={a.grade?.letter} size="sm" />
                      {a.grade?.trusted === false && <span className="text-[10px] font-bold tracking-wider uppercase text-crit bg-crit-soft px-2 py-0.5 rounded">untrusted</span>}
                    </div>
                  </Td>
                  <Td className="text-right font-mono tabular-nums font-semibold text-ink">
                    {a.grade?.raw_score ?? '—'}
                  </Td>
                  <Td className="font-mono text-[12px] text-ink-2">
                    {a.worst_tls
                      ? a.version_spread
                        ? <span className="flex items-center gap-1">{a.worst_tls} <ArrowRight size={10}/> {a.best_tls}</span>
                        : a.worst_tls
                      : 'None'}
                  </Td>
                  <Td className="text-right font-mono tabular-nums">{a.session_count}</Td>
                  <Td className="text-right font-mono tabular-nums font-medium">{a.exposure_score}</Td>
                </tr>
              ))}
            </tbody>
          </table>
          {!(r.assets || []).length && (
            <div className="p-8 text-center text-ink-3">No servers detected in this capture.</div>
          )}
        </Card>
      </motion.section>

      {/* Remediation */}
      {(r.remediation || []).length > 0 && (
        <motion.section variants={itemVariants} className="mb-12">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-crit-soft text-crit rounded-lg"><ShieldAlert size={20}/></div>
            <div>
              <h2 className="font-display text-[20px] font-bold tracking-tight text-ink m-0">Recommended Fixes</h2>
              <p className="text-[13px] text-ink-3 font-medium">Prioritized in order of impact</p>
            </div>
          </div>
          
          <div className="grid gap-3">
            {r.remediation.map((m) => (
              <Card key={m.rule_id} className="p-5 shadow-sm border-line hover:shadow-soft transition-shadow bg-surface">
                <div className="flex flex-col md:flex-row items-start md:items-center gap-4">
                  <div className="flex items-center gap-3 shrink-0 md:w-48">
                    <span className="flex items-center justify-center w-8 h-8 rounded-full bg-surface-2 border border-line font-mono text-[13px] font-bold text-ink-3">
                      {String(m.order).padStart(2, '0')}
                    </span>
                    <SeverityPill severity={m.severity} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="font-bold text-[15px] text-ink">{m.title}</h3>
                    <p className="text-[14px] text-ink-2 mt-1 leading-relaxed">
                      {m.action}
                    </p>
                    <div className="font-mono text-[11px] text-ink-3 mt-2 bg-surface-2 inline-block px-2 py-1 rounded">
                      {m.rule_id} · {m.standard}
                    </div>
                  </div>
                  <div className="md:w-64 shrink-0">
                    <p className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-1">Affected Assets</p>
                    <p className="font-mono text-[12px] text-ink-2 break-all bg-surface-2 p-2 rounded-lg border border-line">
                      {(m.affected_assets || []).join(', ')}
                    </p>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </motion.section>
      )}

      {/* Sessions */}
      <motion.section id="sessions" variants={itemVariants} className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-info-soft text-info rounded-lg"><Network size={20}/></div>
          <div>
            <h2 className="font-display text-[20px] font-bold tracking-tight text-ink m-0">Observed Sessions</h2>
            <p className="text-[13px] text-ink-3 font-medium">Full protocol traces and forensics</p>
          </div>
        </div>
        
        <div className="grid sm:grid-cols-2 gap-3">
          {(r.sessions || []).map((s) => (
            <Link
              key={s.tcp_stream}
              to={`/report/${id}/sessions/${s.tcp_stream}`}
              className="group flex flex-col justify-between text-left bg-surface shadow-sm border border-line rounded-xl p-5 hover:border-accent hover:shadow-soft transition-all no-underline"
            >
              <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex items-center gap-2">
                  <GradeBadge grade={s.grade?.letter} size="sm" className="transform group-hover:scale-105 transition-transform" />
                  <span className="font-bold text-ink group-hover:text-accent transition-colors">{sessionKind(s)}</span>
                </div>
                <div className="font-mono text-[11px] font-semibold text-ink-3 bg-surface-2 px-2 py-1 rounded">
                  {(s.findings || []).filter((f) => f.severity !== 'info').length} findings
                </div>
              </div>
              
              <div className="font-mono text-[12px] text-ink-2 mb-3 bg-surface-2/50 p-2 rounded border border-line/50">
                <span className="text-ink font-medium">{s.client?.ip}</span>:{s.client?.port} 
                <span className="mx-2 text-ink-3">→</span> 
                <span className="text-ink font-medium">{s.server?.ip}</span>:{s.server?.port}
              </div>

              <div className="flex flex-wrap gap-1.5 mb-3">
                {s.capability_mangled && <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-crit-soft text-crit">downgrade</span>}
                {s.cleartext_auth && <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-crit-soft text-crit">creds exposed</span>}
                {s.ml?.anomaly && <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-high-soft text-high">anomaly</span>}
                {s.confidence === 'partial' && <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase bg-surface-3 text-ink-2">partial</span>}
              </div>
              
              <div className="font-mono text-[12px] text-ink-2 mt-auto pt-3 border-t border-line/50 flex flex-wrap gap-2">
                <span className={s.tls_version ? "text-accent font-medium" : "text-crit font-medium"}>
                  {s.tls_version ? `TLS ${s.tls_version}` : 'No Encryption'}
                </span>
                {s.cipher_suite && <span className="text-ink-3">· <span className="text-ink-2">{s.cipher_suite}</span></span>}
              </div>
            </Link>
          ))}
          {!(r.sessions || []).length && (
            <div className="sm:col-span-2 p-8 text-center text-ink-3 bg-surface border border-line rounded-xl">
              No sessions found in capture.
            </div>
          )}
        </div>
      </motion.section>
    </motion.div>
  )
}

function Th({ children, className = '' }) {
  return (
    <th
      className={`font-semibold tracking-[0.05em] text-[12px] text-ink-2 text-left px-5 py-3 whitespace-nowrap ${className}`}
    >
      {children}
    </th>
  )
}

function Td({ children, className = '' }) {
  return <td className={`px-5 py-3 align-middle ${className}`}>{children}</td>
}


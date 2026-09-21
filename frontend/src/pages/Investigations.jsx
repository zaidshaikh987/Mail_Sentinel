import React, { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { FolderGit2, FileCode2, ArrowRight, Activity, Plus, RefreshCw, Layers, GitCompare, ListFilter, Server, ArrowLeft, ArrowUpRight } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { listInvestigations, createInvestigation, getInvestigation, compareRuns, listCaptures, saveRemediation } from '../lib/api'
import { Card, Notice, GradeBadge } from '../components/ui'

export default function Investigations() {
  const { investigationId } = useParams()
  const [items, setItems] = useState([]), [detail, setDetail] = useState(null), [runs, setRuns] = useState([])
  const [name, setName] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false)
  const [before, setBefore] = useState(''), [after, setAfter] = useState(''), [comparison, setComparison] = useState(null)

  async function load() {
    if (investigationId) setDetail(await getInvestigation(investigationId))
    else { const [i, r] = await Promise.all([listInvestigations(), listCaptures()]); setItems(i); setRuns(r) }
  }

  useEffect(() => {
    let alive = true
    setDetail(null); setComparison(null); setBefore(''); setAfter(''); setError('')
    const request = investigationId ? getInvestigation(investigationId) : Promise.all([listInvestigations(), listCaptures()])
    request.then(data => { if (!alive) return; if (investigationId) setDetail(data); else { setItems(data[0]); setRuns(data[1]) } }).catch(e => { if (alive) setError(e.message) })
    return () => { alive = false }
  }, [investigationId])

  async function perform(fn) { setBusy(true); setError(''); try { await fn() } catch (e) { setError(e.message) } finally { setBusy(false) } }
  const shownRuns = detail?.runs || runs
  const complete = shownRuns.filter(r => r.status === 'COMPLETED')

  const isDetail = !!investigationId;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }} className="pb-10 pt-4">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-10">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-surface-2 border border-line shadow-sm text-ink rounded-2xl flex items-center justify-center h-14 w-14">
            {isDetail ? <ListFilter size={24} className="opacity-90" /> : <FolderGit2 size={24} className="opacity-90" />}
          </div>
          <div>
            <h1 className="text-[28px] sm:text-[34px] font-display font-bold text-ink leading-[1.1] tracking-tight m-0">
              {detail?.investigation.name || (isDetail ? 'Loading investigation…' : 'Investigations & History')}
            </h1>
            <p className="text-[14px] sm:text-[15px] text-ink-2 mt-2 font-medium max-w-[60ch] leading-relaxed">
              Keep evidence together, review changes and track remediation.
            </p>
          </div>
        </div>
        <Link className="action group h-[42px] px-5" to={isDetail ? `/?investigation=${investigationId}` : '/'}>
          <FileCode2 size={16} className="text-ink-3 group-hover:text-ink transition-colors" /> Upload capture
        </Link>
      </div>

      <AnimatePresence>
        {error && (
          <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <Notice tone="warn" title="Request failed" className="mb-8">{error}</Notice>
          </motion.div>
        )}
      </AnimatePresence>

      {!isDetail && (
        <div className="grid lg:grid-cols-3 gap-6 mb-12">
          <Card className="p-6 col-span-1 border-line/50 flex flex-col justify-between">
            <div>
              <h2 className="text-[15px] font-semibold flex items-center gap-2 mb-2 text-ink">
                <Plus size={16} className="text-ink-3"/> New Investigation
              </h2>
              <p className="text-[13px] text-ink-2 mb-5">Create a container for a new assessment or audit.</p>
            </div>
            <form className="flex flex-col gap-3" onSubmit={e => { e.preventDefault(); perform(async () => { await createInvestigation(name); setName(''); await load() }) }}>
              <input required maxLength={160} className="field text-[14px]" value={name} onChange={e => setName(e.target.value)} placeholder="E.g., Mail infrastructure review" />
              <button className="action w-full flex justify-center items-center gap-2 bg-ink text-surface hover:bg-ink/90 border-transparent transition-all h-[42px]" disabled={busy || !name.trim()}>
                Create Project
              </button>
            </form>
          </Card>
          
          <div className="col-span-1 lg:col-span-2">
            <h2 className="text-[15px] font-semibold flex items-center gap-2 mb-4 text-ink">
              <Layers size={16} className="text-ink-3"/> Active Investigations
            </h2>
            <div className="grid sm:grid-cols-2 gap-4">
              <AnimatePresence>
                {items.length === 0 ? (
                  <p className="text-[13.5px] text-ink-3 col-span-full bg-surface/50 border border-line/50 p-6 rounded-2xl flex items-center justify-center h-full min-h-[140px] shadow-sm">No investigations created yet.</p>
                ) : (
                  items.map(i => (
                    <motion.div key={i.id} layout initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}>
                      <Link to={`/investigations/${i.id}`} className="group flex items-center justify-between border border-line bg-surface/80 backdrop-blur-xl p-5 rounded-2xl text-ink shadow-sm hover:shadow-soft hover:border-ink-3 transition-all">
                        <span className="truncate pr-4 font-semibold text-[15px] group-hover:text-ink transition-colors">{i.name}</span>
                        <div className="w-8 h-8 rounded-full bg-surface-2 flex items-center justify-center group-hover:bg-ink group-hover:text-surface transition-colors shrink-0 border border-line group-hover:border-ink">
                          <ArrowRight size={14} className="text-ink-2 group-hover:text-surface transition-all" />
                        </div>
                      </Link>
                    </motion.div>
                  ))
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between mb-4 mt-10">
        <h2 className="text-[18px] font-bold text-ink flex items-center gap-2"><Activity size={18} className="text-ink-3"/> Analysis Runs</h2>
        <button className="text-[12px] font-bold uppercase tracking-wider text-ink-2 hover:text-ink flex items-center gap-1.5 transition-colors bg-surface-2 px-3 py-1.5 rounded-lg border border-line/50 shadow-sm" disabled={busy} onClick={() => perform(load)}>
          <RefreshCw size={12} className={busy ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      <div className="bg-surface/80 backdrop-blur-xl border border-line rounded-2xl shadow-sm overflow-hidden mb-12">
        <div className="overflow-x-auto">
          <table className="w-full text-[13.5px] text-left whitespace-nowrap">
            <thead className="bg-surface-2/50 text-ink-2 font-semibold border-b border-line text-[12px] uppercase tracking-wider">
              <tr>
                <th className="p-4 px-5">Run / capture</th>
                <th className="p-4 px-5">Status</th>
                <th className="p-4 px-5">Grade</th>
                <th className="p-4 px-5">Uploaded</th>
                <th className="p-4 px-5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line/50 font-medium">
              {shownRuns.map(r => (
                <tr key={r.id} className="hover:bg-surface-2/30 transition-colors group">
                  <td className="p-4 px-5">
                    <div className="flex items-center gap-2 text-ink">
                      <span className="font-mono text-[11px] bg-surface-2 border border-line/50 px-1.5 py-0.5 rounded text-ink-3 font-bold">#{r.id}</span>
                      <span className="font-mono text-[12px] truncate max-w-[200px]" title={r.filename}>{r.filename}</span>
                    </div>
                    {r.sourceCaptureId && <div className="text-[11px] text-ink-3 mt-1.5 flex items-center gap-1.5 font-semibold"><RefreshCw size={10} className="text-ink-2"/> Retry of #{r.sourceCaptureId}</div>}
                  </td>
                  <td className="p-4 px-5">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold tracking-wide uppercase ${r.status === 'COMPLETED' ? 'bg-ok/10 text-ok border-ok/20' : r.status === 'FAILED' ? 'bg-crit/10 text-crit border-crit/20' : 'bg-info/10 text-info border-info/20'}`}>
                      {r.status.toLowerCase()}
                    </span>
                  </td>
                  <td className="p-4 px-5">{r.overallGrade ? <GradeBadge grade={r.overallGrade} size="sm" className="group-hover:scale-110 transition-transform" /> : <span className="text-ink-3 font-mono">—</span>}</td>
                  <td className="p-4 px-5 text-ink-2 text-[13px]">{new Date(r.uploadedAt).toLocaleString()}</td>
                  <td className="p-4 px-5 text-right">
                    <Link className="inline-flex items-center gap-1.5 text-ink-2 font-semibold hover:text-ink text-[13px] transition-colors bg-surface-2/50 border border-line/50 px-3 py-1.5 rounded-lg group-hover:bg-surface-3 group-hover:border-line" to={r.status === 'COMPLETED' ? `/report/${r.id}` : `/jobs/${r.id}`}>
                      View <ArrowRight size={14} className="opacity-70" />
                    </Link>
                  </td>
                </tr>
              ))}
              {!shownRuns.length && <tr><td colSpan="5" className="p-10 text-center text-ink-3 text-[14px]">No captures yet. Upload one to start.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {isDetail && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-12">
          <section>
            <h2 className="text-[18px] font-bold text-ink flex items-center gap-2 mb-4"><GitCompare size={18} className="text-ink-3"/> Compare Captures</h2>
            <Card className="p-6 lg:p-8 bg-surface/80 shadow-sm border-line">
              <form className="flex flex-col md:flex-row gap-5 items-end" onSubmit={e => { e.preventDefault(); perform(async () => setComparison(await compareRuns(investigationId, before, after))) }}>
                {[['Before baseline', before, setBefore], ['After remediation', after, setAfter]].map(([label, value, set]) => (
                  <label key={label} className="text-[13.5px] font-semibold flex-1 w-full">
                    <span className="text-ink-2 mb-1.5 block">{label}</span>
                    <div className="relative">
                      <select required className="field w-full appearance-none pr-10" value={value} onChange={e => { set(e.target.value); setComparison(null) }}>
                        <option value="">Select completed run...</option>
                        {complete.map(r => <option key={r.id} value={r.id}>#{r.id} · {r.filename}</option>)}
                      </select>
                      <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-ink-3">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m6 9 6 6 6-6"/></svg>
                      </div>
                    </div>
                  </label>
                ))}
                <button className="action whitespace-nowrap h-[46px] px-6 bg-ink text-surface hover:bg-ink/90 border-transparent shadow-[0_2px_10px_rgba(0,0,0,0.1)]" disabled={busy || !before || !after || before === after}>Generate Comparison</button>
              </form>
            </Card>

            {comparison && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="mt-8 space-y-8 overflow-hidden">
                {comparison.caveats.length > 0 && (
                  <div className="flex flex-col gap-3">
                    {comparison.caveats.map(c => <Notice key={c} tone="info" className="!my-0">{c}</Notice>)}
                  </div>
                )}
                
                <Card className="p-6 sm:p-8 shadow-sm bg-surface-2/50 border-line">
                  <strong className="text-[13px] uppercase tracking-wider font-bold text-ink-3 block mb-4">Coverage Summary</strong>
                  <div className="flex flex-wrap gap-4 text-[14px]">
                    <div className="bg-surface px-5 py-3 rounded-xl border border-line flex-1 shadow-sm flex items-center justify-between"><span className="text-ink-2 font-medium">Before:</span> <div><span className="font-bold text-[18px] text-ink">{comparison.beforeCoverage.assessed_checks ?? '?'}</span> <span className="text-ink-3 text-[13px]">/ {comparison.beforeCoverage.applicable_checks ?? '?'}</span></div></div>
                    <div className="bg-surface px-5 py-3 rounded-xl border border-line flex-1 shadow-sm flex items-center justify-between"><span className="text-ink-2 font-medium">After:</span> <div><span className="font-bold text-[18px] text-ink">{comparison.afterCoverage.assessed_checks ?? '?'}</span> <span className="text-ink-3 text-[13px]">/ {comparison.afterCoverage.applicable_checks ?? '?'}</span></div></div>
                  </div>
                </Card>

                <div>
                  <h3 className="font-bold text-[18px] mb-4 text-ink">Findings & Remediation</h3>
                  {!comparison.findings.length && <p className="text-[14px] text-ink-3 bg-surface-2/50 border border-line p-6 rounded-xl flex items-center justify-center min-h-[100px]">No non-informational findings in either run.</p>}
                  <div className="space-y-4">
                    {comparison.findings.map(f => (
                      <Card key={f.key} className="p-5 sm:p-6 shadow-sm border-line hover:shadow-soft transition-shadow bg-surface">
                        <div className="flex flex-col lg:flex-row items-start justify-between gap-6">
                          <div className="flex-1 min-w-[280px]">
                            <span className={`inline-block px-2.5 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider mb-3 ${f.state.includes('NEW') ? 'bg-crit/10 text-crit border-crit/20' : f.state.includes('RESOLVED') ? 'bg-ok/10 text-ok border-ok/20' : 'bg-med/10 text-med border-med/20'}`}>
                              {f.state.replaceAll('_', ' ')}
                            </span>
                            <h4 className="font-bold text-[16px] text-ink leading-snug">{f.rule} <span className="text-ink-3 mx-1 font-normal">|</span> {f.title}</h4>
                            <div className="mt-4 bg-surface-2/50 border border-line/50 p-3 rounded-lg relative">
                              <div className="absolute -top-2.5 left-3 bg-surface-2 px-1.5 text-[9px] font-bold uppercase tracking-wider text-ink-3 border border-line/50 rounded">Remediation</div>
                              <p className="text-[13.5px] text-ink-2 leading-relaxed">{f.remediation}</p>
                            </div>
                            <p className="text-[11px] font-mono text-ink-3 bg-surface-2 border border-line/50 px-2 py-1 rounded inline-block mt-4">{f.key}</p>
                          </div>
                          
                          <div className="w-full lg:w-64 shrink-0 bg-surface-2/50 p-4 rounded-xl border border-line">
                            <label className="text-[11px] font-bold uppercase tracking-wider text-ink-3 block mb-2">Analyst Status</label>
                            <div className="relative">
                              <select className="field text-[13px] font-medium py-2 px-3 h-auto w-full appearance-none pr-8 bg-surface shadow-sm" disabled={busy} value={detail?.remediation.find(r => r.finding_key === f.key)?.status || 'open'} onChange={e => perform(async () => { await saveRemediation(investigationId, f.key, e.target.value); await load() })}>
                                <option value="open">Open</option>
                                <option value="in_progress">In progress</option>
                                <option value="fix_reported">Fix reported</option>
                              </select>
                              <div className="absolute right-2.5 top-1/2 -translate-y-1/2 pointer-events-none text-ink-3">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m6 9 6 6 6-6"/></svg>
                              </div>
                            </div>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="font-bold text-[18px] mb-4 text-ink">Observed Server Changes</h3>
                  <div className="grid lg:grid-cols-2 gap-4">
                    {comparison.servers.map(s => (
                      <Card key={s.identity} className="p-5 shadow-sm bg-surface">
                        <p className="font-mono text-[11px] bg-surface-2 border border-line/50 px-2 py-1 rounded inline-block mb-3 break-all font-semibold">{s.identity}</p>
                        <p className="text-[14px] font-semibold text-accent mb-5">{s.match.replaceAll('_', ' ')}</p>
                        <div className="grid grid-cols-2 gap-4 text-[13px] bg-surface-2/50 border border-line/50 p-4 rounded-xl">
                          {[['Before', s.before], ['After', s.after]].map(([label, values]) => (
                            <div key={label}>
                              <strong className="text-ink text-[13px] block mb-3 pb-1 border-b border-line/50">{label}</strong>
                              {Object.entries(values).map(([key, value]) => (
                                <div key={key} className="mb-3 last:mb-0">
                                  <span className="text-[10px] uppercase tracking-wider font-bold text-ink-3 block mb-0.5">{key}</span>
                                  <span className="font-mono text-[11.5px] break-all bg-surface px-1 py-0.5 rounded border border-line/50">{value.join(', ')}</span>
                                </div>
                              ))}
                              {!Object.keys(values).length && <span className="text-ink-3 text-[12px] italic">Not observed</span>}
                            </div>
                          ))}
                        </div>
                      </Card>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}
          </section>

          <section>
            <h2 className="text-[18px] font-bold text-ink flex items-center gap-2 mb-2"><Server size={18} className="text-ink-3"/> Server Observation History</h2>
            <p className="text-[14px] text-ink-2 mb-6 max-w-[70ch] leading-relaxed">Latest analysed run per observed identity. Open a report to inspect its historical baseline and supporting evidence.</p>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
              {detail?.servers.map(s => (
                <Card key={s.assessment.identity} className="p-5 shadow-sm border-line hover:shadow-soft transition-shadow flex flex-col h-full bg-surface">
                  <div className="flex justify-between items-start gap-2 mb-4">
                    <strong className="font-mono text-[13px] font-bold text-ink break-all">{s.assessment.host}:{s.assessment.port}</strong>
                  </div>
                  <div className="text-[13px] text-ink-2 mb-4 flex-1">
                    <div className="font-semibold text-ink mb-1.5">{s.assessment.status.replaceAll('_', ' ')}</div>
                    <div className="flex items-center gap-2 text-[12px]"><span className="font-mono bg-surface-2 px-1 rounded">{s.assessment.prior_sessions}</span> prior sessions</div>
                    <div className="flex items-center gap-2 text-[12px] mt-1"><span className="font-mono bg-surface-2 px-1 rounded">{s.assessment.prior_captures}</span> prior captures</div>
                  </div>
                  <div className="pt-4 border-t border-line/50 flex items-center justify-between mt-auto">
                    <span className="text-[9px] font-bold tracking-wider uppercase text-ink-3 bg-surface-2 border border-line/50 px-2 py-0.5 rounded">{s.assessment.identity_confidence.replaceAll('_', ' ')}</span>
                    <Link className="text-ink-2 font-semibold hover:text-ink transition-colors flex items-center gap-1 text-[12px] bg-surface-2/50 hover:bg-surface-3 px-2 py-1 rounded" to={`/report/${s.captureId}`}>
                      Run #{s.captureId} <ArrowUpRight size={12}/>
                    </Link>
                  </div>
                </Card>
              ))}
            </div>
            {!detail?.servers?.length && <p className="text-[13.5px] text-ink-3 bg-surface-2/50 border border-line p-6 rounded-xl mt-4 flex items-center justify-center min-h-[100px]">No servers observed yet.</p>}
          </section>

          <Link className="inline-flex items-center gap-2 text-ink-2 hover:text-ink font-semibold mt-8 mb-4 transition-colors text-[14px]" to="/investigations">
            <ArrowLeft size={16}/> Back to all investigations
          </Link>
        </motion.div>
      )}
    </motion.div>
  )
}

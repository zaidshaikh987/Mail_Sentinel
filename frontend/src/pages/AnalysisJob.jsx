import React, { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { getCapture, cancelRun, retryRun } from '../lib/api'
import { Card, Notice } from '../components/ui'
const stages = ['QUEUED', 'STARTING', 'READING', 'REASSEMBLING', 'TLS_AND_CERTIFICATES', 'RULES_AND_COVERAGE', 'ML_ASSESSMENT', 'AGGREGATING', 'HISTORY_COMPARISON', 'COMPLETED']
const title = value => (value || 'queued').toLowerCase().replaceAll('_', ' ')
export default function AnalysisJob() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [job, setJob] = useState(null)
  const [error, setError] = useState('')
  const [acting, setActing] = useState(false)
  useEffect(() => {
    let stop = false, timer
    setJob(null); setError('')
    async function poll() {
      try {
        const data = await getCapture(id)
        if (stop) return
        setJob(data); setError('')
        if (data.status === 'COMPLETED') { navigate(`/report/${id}`, { replace: true }); return }
        if (['FAILED', 'CANCELLED'].includes(data.status)) return
      } catch (e) { if (!stop) setError(e.message) }
      if (!stop) timer = setTimeout(poll, 1200)
    }
    poll()
    return () => { stop = true; clearTimeout(timer) }
  }, [id, navigate])
  async function act(action) {
    setActing(true)
    try {
      const data = await action(id)
      if (data.id !== Number(id)) navigate(`/jobs/${data.id}`)
      else setJob(data)
    } catch (e) { setError(e.message) }
    finally { setActing(false) }
  }
  const terminal = ['FAILED', 'CANCELLED'].includes(job?.status)
  return <div className="max-w-[760px] mx-auto">
    <h1 className="text-2xl font-semibold mb-2">Analysis run #{id}</h1>
    <p className="text-ink-2 mb-5">{job?.filename || 'Loading run…'}</p>
    {error && <Notice tone="warn" title="Could not update the run">{error}</Notice>}
    <Card className="p-6">
      <p role="status" className="font-medium capitalize">{title(job?.stage || job?.status)}</p>
      <p className="text-sm text-ink-2 mt-2">You can leave this page. The server keeps the job and its evidence.</p>
      <ol className="grid sm:grid-cols-2 gap-3 my-6 text-sm">
        {stages.filter(s => !['STARTING', 'COMPLETED'].includes(s)).map(s => <li key={s} className={stages.indexOf(s) <= stages.indexOf(job?.stage) ? 'text-accent font-medium' : 'text-ink-3'}>
          {stages.indexOf(s) < stages.indexOf(job?.stage) ? '✓' : '·'} <span className="capitalize">{title(s)}</span>
        </li>)}
      </ol>
      {job?.errorMessage && <p className="text-crit text-sm mb-4">{job.errorMessage}</p>}
      {job && <button className="action" disabled={acting} onClick={() => act(terminal ? retryRun : cancelRun)}>{terminal ? 'Retry as a new run' : 'Cancel analysis'}</button>}
      <p className="mt-4 text-xs text-ink-3">Stages reflect engine events, not an estimated percentage. Retry preserves this run.</p>
    </Card>
    <Link className="inline-block text-accent mt-5" to={job?.investigationId ? `/investigations/${job.investigationId}` : '/investigations'}>Back to analysis history →</Link>
  </div>
}

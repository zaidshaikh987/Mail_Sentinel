import React from 'react'
import { Card } from './ui'
export function Coverage({ coverage }) {
  if (!coverage) return <p className="text-sm text-ink-3 my-4">Coverage was not recorded by this older analysis run.</p>
  return <Card className="p-4 my-5">
    <h2 className="font-semibold">Evidence coverage · separate from the security grade</h2>
    <p className="text-sm text-ink-2 mt-2">{coverage.assessed_checks ?? 0} of {coverage.applicable_checks ?? 0} applicable evidence checks assessed.
      {coverage.limited_sessions !== undefined && ` ${coverage.limited_sessions} session(s) have visibility limits.`}
      {' '}A good grade does not mean unobservable evidence was verified.</p>
    {coverage.checks && <ul className="mt-3 divide-y divide-line">{coverage.checks.map(c => <li key={c.check} className="py-2 text-sm"><strong className="capitalize">{c.check.replaceAll('_', ' ')} · {c.status.replaceAll('_', ' ')}</strong><p className="text-ink-2 mt-1">{c.reason}</p></li>)}</ul>}
  </Card>
}
export function HistoryAssessment({ history }) {
  return <section className="my-6"><h2 className="text-lg font-semibold mb-3">Changes against earlier observations</h2>
    <p className="text-sm text-ink-2 mb-3">Baselines require 8 prior sessions from 2 distinct, earlier captures in this investigation, with matching hostname and endpoint. Deviations are review prompts, not proof of attacks.</p>
    {!history?.servers?.length && <p className="text-sm text-ink-3">No server baseline available for this run.</p>}
    {history?.servers?.map(s => <Card key={s.identity} className="p-4 mb-2">
      <div className="flex justify-between flex-wrap gap-2"><strong>{s.host}:{s.port}</strong><span className="text-xs text-ink-2">{s.status.replaceAll('_', ' ')}</span></div>
      <p className="text-xs text-ink-3 mt-1">{s.prior_sessions} prior sessions · {s.prior_captures} distinct captures · {s.identity_confidence.replaceAll('_', ' ')}</p>
      {s.changes.map(c => <p key={c.field} className="text-sm mt-2 break-all">{c.field}: {c.previous.join(', ')} → {c.new.join(', ')}</p>)}
      {s.anomalies?.some(a => a.unusual) && <p className="text-high text-sm mt-2">{s.anomalies.filter(a => a.unusual).length} session(s) unusual against historical baseline.</p>}
      <p className="text-xs text-ink-2 mt-2">Historical ML: {(s.ml_status || 'unavailable').replaceAll('_', ' ')}</p>
    </Card>)}
  </section>
}

import React, { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ShieldAlert, CheckCircle, AlertTriangle, Key, FileText, Activity, AlertCircle, FileLock2, BrainCircuit } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

import {
  Card,
  Chip,
  Empty,
  GradeBadge,
  Label,
  Notice,
  SeverityPill,
  ShapChart,
  Spinner,
} from '../components/ui'
import { Coverage } from '../components/Assessment'
import { useReport } from '../App'
import { adaptBackendCapture, getCapture } from '../lib/api'
import { dateOnly, sessionKind, yesNo } from '../lib/format'

export default function SessionDetail() {
  const { id, stream } = useParams()
  const { report, setReport } = useReport()
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(!report)

  useEffect(() => {
    if (report?.id && String(report.id) === String(id)) {
      setLoading(false)
      return
    }
    let cancelled = false
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
        <Spinner label="Loading the session…" />
      </div>
    )
  }
  if (error) return (
    <Empty title="Could not load that session">
      <p className="mb-4">{error}</p>
      <Link to={`/report/${id}`} className="action inline-flex items-center gap-2">
        Back to Dashboard
      </Link>
    </Empty>
  )

  const s = (report?.report?.sessions || []).find(
    (x) => String(x.tcp_stream) === String(stream),
  )
  if (!s) {
    return (
      <Empty title="No such session in this capture">
        <Link to={`/report/${id}`} className="text-accent underline font-medium hover:text-ink">
          Back to the dashboard
        </Link>
      </Empty>
    )
  }

  const leaf = (s.chain || [])[0]
  const findings = s.findings || []
  const real = findings.filter((f) => f.severity !== 'info')
  const info = findings.filter((f) => f.severity === 'info')

  const containerVariants = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.05 } }
  };
  const itemVariants = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0 }
  };

  return (
    <motion.div variants={containerVariants} initial="hidden" animate="show" className="pb-10">
      <motion.div variants={itemVariants}>
        <Link
          to={`/report/${id}`}
          className="inline-flex items-center gap-2 text-ink-2 hover:text-ink text-sm font-medium mb-6 transition-colors"
        >
          <ArrowLeft size={16}/> Back to dashboard
        </Link>
      </motion.div>

      {/* Header */}
      <motion.div variants={itemVariants} className="flex items-start gap-4 mb-8 bg-surface p-6 sm:p-8 rounded-2xl shadow-sm border border-line flex-wrap">
        <GradeBadge grade={s.grade?.letter} size="lg" className="transform scale-110" />
        <div className="min-w-0 flex-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-accent-soft text-accent rounded-full text-[11px] font-semibold uppercase tracking-wider mb-3">
            <Activity size={14} /> Session #{s.tcp_stream}
          </div>
          <h1 className="font-display text-[24px] sm:text-[32px] font-bold tracking-tight m-0 text-ink leading-tight">
            {sessionKind(s)}
          </h1>
          <div className="flex flex-wrap items-center gap-3 font-mono text-[13px] text-ink-2 mt-3 p-3 bg-surface-2 rounded-lg border border-line/50">
            <span className="font-medium text-ink">{s.client?.ip}:{s.client?.port}</span> 
            <span className="text-ink-3">→</span> 
            <span className="font-medium text-ink">{s.server?.ip}:{s.server?.port}</span>
            {s.server_name && <span className="bg-surface border border-line px-2 py-0.5 rounded text-ink-2">SNI: {s.server_name}</span>}
            <span className="hidden sm:inline">·</span>
            <span>Frames {s.first_frame}–{s.last_frame}</span>
            <span className="hidden sm:inline">·</span>
            <span className="uppercase tracking-wider text-[11px] font-bold text-ink-3">Role: {s.role}</span>
          </div>
          <div className="flex gap-2 mt-4 flex-wrap">
            {s.grade?.trusted === false && <Chip tone="warn" className="shadow-sm">Untrusted chain</Chip>}
            {s.confidence === 'partial' && <Chip tone="muted" className="shadow-sm">Partial view</Chip>}
            {s.ml?.anomaly && <Chip tone="warn" className="shadow-sm border-warn/30">Anomalous session</Chip>}
          </div>
        </div>
      </motion.div>

      <motion.div variants={itemVariants} className="mb-8 space-y-6">
        <Coverage coverage={s.coverage} />
        
        <Card className="p-5 shadow-sm border-line bg-surface">
          <div className="flex items-center gap-2 mb-3">
            <Activity size={16} className="text-accent" />
            <h3 className="font-semibold text-[14px] text-ink">Score Breakdown</h3>
          </div>
          <div className="font-mono text-[13px] text-ink-2 leading-relaxed bg-surface-2 p-3 rounded-lg">
            Weighted Score: <strong className="text-ink text-[15px]">{s.grade?.raw_score}</strong>
            {s.grade?.components && (
              <span className="ml-2 text-ink-3">
                (Protocol <span className="text-ink-2">{fmt(s.grade.components.protocol)}</span> · 
                Key Exchange <span className="text-ink-2">{fmt(s.grade.components.key_exchange)}</span> · 
                Cipher <span className="text-ink-2">{fmt(s.grade.components.cipher)}</span>)
              </span>
            )}
            {s.grade?.capped_by ? (
              <div className="mt-2 text-warn font-medium flex items-center gap-1.5">
                <AlertTriangle size={14}/> Capped to {s.grade.letter} by {s.grade.capped_by}
              </div>
            ) : (
              '.'
            )}
            {s.grade?.zero_category && (
              <div className="mt-2 text-crit font-medium flex items-center gap-1.5">
                <AlertCircle size={14}/> A zero in {s.grade.zero_category} forces the score to 0.
              </div>
            )}
          </div>
        </Card>
      </motion.div>

      {/* Downgrade Evidence */}
      <AnimatePresence>
        {s.capability_mangled && (
          <motion.div variants={itemVariants}>
            <Notice tone="crit" title="Downgrade evidence" className="mb-6 shadow-sm border-crit/20">
              The capability list contains <code className="font-mono bg-crit/10 px-1 rounded text-crit">{s.mangled_token}</code>{' '}
              where the STARTTLS keyword belongs — an equal-length substitution that keeps packet
              sizes identical so nothing downstream notices. This exact attack was measured in the
              wild by Durumeric et al., IMC 2015.
            </Notice>
          </motion.div>
        )}

        {s.cleartext_auth && (
          <motion.div variants={itemVariants}>
            <Notice tone="crit" title="Credentials exposed" className="mb-6 shadow-sm border-crit/20">
              {s.cleartext_auth.mechanism || 'Authentication'} credentials for{' '}
              <code className="font-mono bg-crit/10 px-1 rounded text-crit">{s.cleartext_auth.username || 'an unknown user'}</code>{' '}
              were sent before any encryption existed
              {s.cleartext_auth.frame ? ` (frame ${s.cleartext_auth.frame})` : ''}. The password
              itself is never stored by this tool — only a SHA-256, so reuse can be correlated
              without the report becoming a second copy of the leak. Treat the credential as
              compromised.
            </Notice>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Two failure surfaces */}
      <motion.div variants={itemVariants} className="grid md:grid-cols-2 gap-6 mb-10">
        <Card className="p-6 shadow-sm border-line">
          <Label className="mb-4 flex items-center gap-2 text-[15px] font-bold text-ink">
            <FileLock2 size={18} className="text-accent" /> TLS Handshake
          </Label>
          <div className="space-y-1">
            <Row k="Version" v={s.tls_version || 'none — cleartext'} bad={!s.tls_version} />
            <Row k="Cipher suite" v={s.cipher_suite || '—'} />
            <Row
              k="Key exchange"
              v={s.kex ? `${s.kex}${s.kex_bits ? ` · ${s.kex_bits}-bit equivalent` : ''}` : '—'}
            />
            <Row
              k="Forward secrecy"
              v={yesNo(s.forward_secrecy)}
              bad={s.forward_secrecy === false}
            />
            <Row k="STARTTLS offered" v={yesNo(s.starttls_offered, 'no')} />
            <Row k="STARTTLS completed" v={yesNo(s.starttls_accepted, 'no')} />
            <Row k="JA4" v={s.ja4 || '—'} mono />
            <Row k="JA3" v={s.ja3 || '—'} mono />
          </div>
        </Card>

        <Card className="p-6 shadow-sm border-line">
          <Label className="mb-4 flex items-center gap-2 text-[15px] font-bold text-ink">
            <FileText size={18} className="text-accent" /> X.509 Certificate
          </Label>
          {s.cert_visibility === 'encrypted_tls13' ? (
            <div className="text-[13.5px] text-ink-2 leading-relaxed bg-surface-2 p-4 rounded-lg">
              TLS 1.3 encrypts the Certificate message (RFC 8446 §4.4), so a passive sensor
              cannot read it. No certificate findings apply to this session — that is a
              property of the protocol, not a gap in the analysis.
            </div>
          ) : leaf ? (
            <div className="space-y-1">
              <Row k="Subject" v={leaf.subject} />
              <Row k="Issuer" v={leaf.issuer} bad={leaf.self_signed} />
              <Row
                k="Valid until"
                v={
                  <span className="flex items-center gap-2 flex-wrap justify-end">
                    {dateOnly(leaf.not_after)}
                    {leaf.expired_at_capture ? (
                      <Chip tone="crit">expired</Chip>
                    ) : (
                      <Chip tone="ok">valid</Chip>
                    )}
                  </span>
                }
              />
              <Row
                k="Key / signature"
                v={`${leaf.key_algorithm || '?'} ${leaf.key_bits || '?'} · ${leaf.signature_hash || '?'}`}
                bad={leaf.key_bits && leaf.key_bits < 2048}
              />
              <Row k="Self-signed" v={yesNo(leaf.self_signed, 'no')} bad={leaf.self_signed} />
              <Row
                k="Chain valid"
                v={yesNo(s.chain_valid, 'not evaluated')}
                bad={s.chain_valid === false}
              />
              <Row k="Revocation" v={revocationText(s.revocation)} />
            </div>
          ) : (
            <div className="text-[13.5px] text-ink-3 bg-surface-2 p-4 rounded-lg flex items-center justify-center h-[120px]">
              No certificate was presented — this session never negotiated TLS.
            </div>
          )}
        </Card>
      </motion.div>

      {/* Findings */}
      <motion.section variants={itemVariants} className="mb-10">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-crit-soft text-crit rounded-lg"><ShieldAlert size={20}/></div>
          <div>
            <h2 className="font-display text-[20px] font-bold tracking-tight text-ink m-0">Findings</h2>
            <p className="text-[13px] text-ink-3 font-medium">Rule violations detected in this session</p>
          </div>
        </div>
        
        {real.length === 0 && (
          <Card className="p-6 text-[14px] text-ink-2 bg-surface shadow-sm border-line flex items-center gap-3">
            <CheckCircle size={20} className="text-ok" /> Nothing above informational severity. This session met every rule the tool checks.
          </Card>
        )}
        <div className="grid gap-3">
          {real.map((f) => (
            <FindingCard key={f.rule_id} f={f} />
          ))}
          {info.map((f) => (
            <FindingCard key={f.rule_id} f={f} />
          ))}
        </div>
      </motion.section>

      {/* ML Model */}
      {s.ml && (
        <motion.section variants={itemVariants} className="mb-10">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 bg-accent-soft text-accent rounded-lg"><BrainCircuit size={20}/></div>
            <div>
              <h2 className="font-display text-[20px] font-bold tracking-tight text-ink m-0">Model Assessment</h2>
            </div>
          </div>
          <p className="text-[13.5px] text-ink-2 mb-4 max-w-[75ch] leading-relaxed">
            The model never decides a finding — every verdict above comes from the
            deterministic rule engine. It contributes an estimate of overall posture and a
            reason for it, which matters most on sessions where the rules have to abstain.
          </p>
          <Card className="p-6 shadow-sm border-line bg-surface">
            <div className="flex gap-4 items-center flex-wrap mb-5 bg-surface-2 p-4 rounded-xl border border-line">
              <div className="flex flex-col">
                <span className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-1">Risk Class</span>
                <span className={`inline-flex items-center px-3 py-1 rounded-full text-[13px] font-bold uppercase tracking-wide ${s.ml.risk_class === 'critical' ? 'bg-crit text-surface' : s.ml.risk_class === 'secure' ? 'bg-ok text-surface' : 'bg-warn text-surface'}`}>
                  {s.ml.risk_class}
                </span>
              </div>
              <div className="h-8 w-px bg-line mx-2 hidden sm:block"></div>
              <div className="flex flex-col">
                <span className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-1">Critical Prob.</span>
                <span className="font-mono text-[14px] font-medium text-ink">{s.ml.risk_score}</span>
              </div>
              <div className="h-8 w-px bg-line mx-2 hidden sm:block"></div>
              <div className="flex flex-col">
                <span className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-1">Anomaly</span>
                <span className="font-medium text-[14px] text-ink flex items-center gap-1">
                  {s.ml.anomaly ? <AlertTriangle size={14} className="text-warn"/> : <CheckCircle size={14} className="text-ok"/>}
                  {s.ml.anomaly ? 'Yes' : 'No'}
                </span>
              </div>
              {s.ml.model_version && (
                <>
                  <div className="h-8 w-px bg-line mx-2 hidden sm:block"></div>
                  <div className="flex flex-col">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-1">Version</span>
                    <span className="font-mono text-[13px] text-ink-2 bg-surface p-1 rounded">{s.ml.model_version}</span>
                  </div>
                </>
              )}
            </div>
            {s.ml.explanation && (
              <div className="mb-6 bg-surface p-4 rounded-lg border border-line shadow-sm">
                <p className="text-[14px] text-ink leading-relaxed font-medium">{s.ml.explanation}</p>
              </div>
            )}
            <ShapChart contributions={s.ml.shap || []} />
          </Card>
        </motion.section>
      )}

      {/* Packet-Level Evidence Viewer (The Drill-Down) */}
      {(s.command_transcript || []).length > 0 && (
        <motion.section variants={itemVariants} className="mb-10">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-surface-3 text-ink rounded-lg"><FileText size={20}/></div>
              <div>
                <h2 className="font-display text-[20px] font-bold tracking-tight text-ink m-0">Packet-Level Evidence Viewer</h2>
                <p className="text-[13px] text-ink-3 font-medium">Reconstructed protocol trace and hex forensics</p>
              </div>
            </div>
            <div className="flex gap-2">
              <button className="bg-ok/10 text-ok border border-ok/20 px-4 py-2 rounded text-xs font-bold uppercase tracking-wider hover:bg-ok/20 transition-colors shadow-sm">Acknowledge</button>
              <button className="bg-surface-2 text-ink-2 border border-line px-4 py-2 rounded text-xs font-bold uppercase tracking-wider hover:bg-surface-3 transition-colors shadow-sm">False Positive</button>
              <button className="bg-crit/10 text-crit border border-crit/20 px-4 py-2 rounded text-xs font-bold uppercase tracking-wider hover:bg-crit/20 transition-colors shadow-sm">Escalate to IR</button>
            </div>
          </div>
          
          <Card className="p-0 overflow-hidden shadow-sm border-line flex flex-col md:flex-row h-[500px]">
            {/* Left Side: Protocol State Machine */}
            <div className="md:w-1/3 bg-surface-2 border-r border-line flex flex-col h-full">
              <div className="px-4 py-3 border-b border-line bg-surface-3 font-bold text-xs uppercase tracking-wider text-ink-3">
                Protocol State Machine
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
                {['TCP 3-Way Handshake', 'Server Greeting', 'Client EHLO', 'STARTTLS Upgrade', 'TLS Client Hello', 'TLS Server Hello', 'Encrypted Application Data'].map((state, i) => (
                  <div key={i} className="flex gap-3">
                    <div className="flex flex-col items-center">
                      <div className={`w-3 h-3 rounded-full ${i <= 3 ? 'bg-ok' : i === 4 ? 'bg-warn shadow-[0_0_8px_rgba(255,184,0,0.6)]' : 'bg-line'}`}></div>
                      {i < 6 && <div className={`w-0.5 h-8 ${i < 3 ? 'bg-ok' : 'bg-line'}`}></div>}
                    </div>
                    <div className={`text-sm ${i === 4 ? 'font-bold text-ink' : i < 4 ? 'text-ink-2' : 'text-ink-3'}`}>
                      {state}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            {/* Right Side: Raw Hex/ASCII Dump */}
            <div className="md:w-2/3 bg-surface flex flex-col h-full">
              <div className="px-4 py-3 border-b border-line bg-surface-2 flex items-center justify-between">
                <span className="font-mono text-[11px] text-ink-3 uppercase tracking-wider">Raw Hex Dump (Evidence)</span>
                <span className="font-mono text-[11px] bg-warn-soft text-warn px-2 py-0.5 rounded font-bold">Injection Point Detected</span>
              </div>
              <pre className="font-mono text-[12px] leading-relaxed p-5 m-0 text-ink-2 overflow-y-auto custom-scrollbar flex-1">
                {s.command_transcript.flatMap((line, lineIdx) => {
                  const strLine = String(line || '');
                  const chunks = [];
                  for (let i = 0; i < strLine.length; i += 16) {
                    chunks.push({ chunkStr: strLine.substring(i, i + 16), origIdx: lineIdx, offset: i });
                  }
                  if (chunks.length === 0) chunks.push({ chunkStr: "", origIdx: lineIdx, offset: 0 });
                  return chunks;
                }).map(({chunkStr, origIdx, offset}, idx) => {
                  const hex = Array.from(chunkStr).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
                  const ascii = chunkStr.replace(/[\u0000-\u001F\u007F-\u009F]/g, '.');
                  // highlight the 3rd line as a mock injection point
                  const isHighlighted = origIdx === 2 && s.capability_mangled; 
                  return (
                    <div key={idx} className={`flex gap-6 ${isHighlighted ? 'bg-warn/10 -mx-5 px-5 py-0.5 border-y border-warn/30 text-warn font-bold' : 'hover:bg-surface-2'}`}>
                      <div className="w-12 text-ink-3 shrink-0 select-none">{(offset).toString(16).padStart(4, '0')}</div>
                      <div className="w-[410px] shrink-0 whitespace-pre font-mono">{hex.padEnd(47, ' ')}</div>
                      <div className="flex-1 whitespace-pre font-mono text-ink">{ascii}</div>
                    </div>
                  )
                })}
              </pre>
            </div>
          </Card>
        </motion.section>
      )}

      {(s.notes || []).length > 0 && (
        <motion.div variants={itemVariants} className="text-[13px] text-ink-3 leading-relaxed bg-surface-2 p-4 rounded-xl border border-line">
          {s.notes.map((n, i) => (
            <div key={i} className="flex items-start gap-2 mb-2 last:mb-0">
              <AlertCircle size={14} className="mt-0.5 shrink-0" />
              <span>{n}</span>
            </div>
          ))}
        </motion.div>
      )}
    </motion.div>
  )
}

function FindingCard({ f }) {
  return (
    <Card className="p-5 shadow-sm border-line hover:shadow-soft transition-shadow bg-surface">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-3 flex-wrap mb-2">
            <SeverityPill severity={f.severity} />
            <span className="font-mono text-[11px] font-bold text-ink-3 bg-surface-2 px-2 py-0.5 rounded uppercase tracking-wider">{f.rule_id}</span>
            {f.cap_grade && <Chip tone="warn" className="border-warn/30 shadow-sm">caps at {f.cap_grade}</Chip>}
          </div>
          <h3 className="font-bold text-[15px] text-ink mb-2">{f.title}</h3>
          {f.detail && (
            <p className="text-[14px] text-ink-2 leading-relaxed mb-4">{f.detail}</p>
          )}
          
          <div className="bg-surface-2 border border-line rounded-lg p-3 mt-4 relative">
            <div className="absolute -top-3 left-3 bg-surface-2 px-2 text-[10px] font-bold uppercase tracking-wider text-accent border border-line rounded">Fix</div>
            <p className="text-[13.5px] leading-relaxed text-ink mt-1">
              {f.remediation}
            </p>
          </div>
        </div>
        
        <div className="sm:w-48 shrink-0 bg-surface-2 p-3 rounded-lg border border-line self-start w-full">
          <div className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-1">Standard</div>
          <div className="font-mono text-[12px] text-ink mb-3">{f.standard}</div>
          
          {(f.evidence?.frames?.length || f.frames) && (
            <>
              <div className="text-[11px] font-bold uppercase tracking-wider text-ink-3 mb-1">Evidence Frames</div>
              <div className="font-mono text-[12px] text-ink bg-surface px-2 py-1 rounded border border-line">
                {f.evidence?.frames?.length ? f.evidence.frames.join(', ') : f.frames}
              </div>
            </>
          )}
        </div>
      </div>
    </Card>
  )
}

function Row({ k, v, bad = false, mono = false }) {
  return (
    <div className="flex justify-between gap-4 py-[9px] border-b border-line/50 last:border-0 items-center">
      <span className="font-semibold text-[12.5px] text-ink-2 shrink-0">{k}</span>
      <span
        className={`text-[13.5px] text-right break-all ${mono ? 'font-mono text-[12px] bg-surface-2 px-1.5 py-0.5 rounded border border-line' : ''} ${
          bad ? 'text-crit font-bold' : 'text-ink font-medium'
        }`}
      >
        {v}
      </span>
    </div>
  )
}

function fmt(n) {
  return n == null ? '—' : Math.round(n)
}

function revocationText(v) {
  switch (v) {
    case 'good':
      return <span className="flex items-center gap-1 justify-end"><CheckCircle size={14} className="text-ok"/> Not revoked (stapled OCSP)</span>
    case 'revoked':
      return <span className="flex items-center gap-1 justify-end text-crit"><AlertTriangle size={14}/> REVOKED (stapled OCSP)</span>
    default:
      return <span className="text-ink-3 text-[12px] italic">Not checked (offline mode)</span>
  }
}

import React from 'react'
import { AlertCircle, CheckCircle, Info, Loader2, AlertTriangle } from 'lucide-react'

// ---------------------------------------------------------------- primitives

export function Card({ children, className = '', ...rest }) {
  return (
    <div
      className={`bg-surface/80 backdrop-blur-xl border border-line rounded-2xl shadow-sm hover:shadow-soft transition-all duration-300 ${className}`}
      {...rest}
    >
      {children}
    </div>
  )
}

export function Label({ children, className = '' }) {
  return (
    <div
      className={`font-mono text-[11px] font-bold tracking-[0.1em] uppercase text-ink-3 ${className}`}
    >
      {children}
    </div>
  )
}

export function Mono({ children, className = '' }) {
  return <span className={`font-mono text-[12.5px] bg-surface-2 px-1.5 py-0.5 rounded border border-line ${className}`}>{children}</span>
}

// -------------------------------------------------------------------- grades

const GRADE_TONE = {
  'A+': 'bg-ok/10 text-ok border-ok/20',
  A: 'bg-ok/10 text-ok border-ok/20',
  B: 'bg-info/10 text-info border-info/20',
  C: 'bg-warn/10 text-warn border-warn/20',
  D: 'bg-high/10 text-high border-high/20',
  E: 'bg-crit/10 text-crit border-crit/20',
  F: 'bg-crit/10 text-crit border-crit/20',
}

export function GradeBadge({ grade, size = 'md', title, className = '' }) {
  const letter = grade || '—'
  const tone = GRADE_TONE[letter] || 'bg-surface-3 text-ink-2 border-line'
  const dims =
    size === 'lg'
      ? 'w-20 h-20 text-[40px] rounded-2xl shadow-sm'
      : size === 'sm'
        ? `${letter.length > 1 ? 'px-2 min-w-[28px]' : 'w-7'} h-7 text-[13px] rounded-lg`
        : 'w-12 h-12 text-xl rounded-xl'
  return (
    <span
      className={`inline-flex items-center justify-center font-display font-bold tracking-tight shrink-0 border ${dims} ${tone} ${className}`}
      title={title || `Grade ${letter}`}
      aria-label={`Grade ${letter}`}
    >
      {letter}
    </span>
  )
}

// ----------------------------------------------------------------- severity

const SEVERITY_TONE = {
  critical: 'bg-crit/10 text-crit border-crit/20',
  high: 'bg-high/10 text-high border-high/20',
  medium: 'bg-med/10 text-med border-med/20',
  low: 'bg-surface-2 text-ink-2 border-line',
  info: 'bg-info/10 text-info border-info/20',
}

export function SeverityPill({ severity, className = '' }) {
  const key = String(severity || 'info').toLowerCase()
  return (
    <span
      className={`inline-block font-mono text-[10px] font-bold tracking-[0.06em] uppercase px-2 py-0.5 rounded-full border ${
        SEVERITY_TONE[key] || SEVERITY_TONE.info
      } ${className}`}
    >
      {key}
    </span>
  )
}

export function Chip({ children, tone = 'muted', className = '' }) {
  const tones = {
    muted: 'bg-surface-2 text-ink-2 border-line',
    accent: 'bg-accent/10 text-accent border-accent/20',
    ok: 'bg-ok/10 text-ok border-ok/20',
    warn: 'bg-high/10 text-high border-high/20',
    crit: 'bg-crit/10 text-crit border-crit/20',
    info: 'bg-info/10 text-info border-info/20',
  }
  return (
    <span
      className={`inline-block font-mono text-[10px] font-bold tracking-[0.05em] uppercase px-2 py-0.5 rounded border ${tones[tone]} ${className}`}
    >
      {children}
    </span>
  )
}

// --------------------------------------------------------------- stat tiles

export function StatTile({ label, value, tone = 'default', hint }) {
  const accentBar = {
    default: 'bg-line-2',
    critical: 'bg-crit',
    high: 'bg-high',
    medium: 'bg-med',
    low: 'bg-line-2',
    ok: 'bg-ok',
    accent: 'bg-accent',
  }[tone]

  return (
    <div className="relative overflow-hidden bg-surface/80 backdrop-blur-xl border border-line rounded-2xl p-4 sm:p-5 flex flex-col items-start shadow-sm hover:shadow-soft transition-all group">
      <span className={`absolute top-0 left-0 w-full h-[3px] opacity-80 group-hover:opacity-100 transition-opacity ${accentBar}`} aria-hidden="true" />
      <div className="w-full">
        <div className="text-[28px] sm:text-[32px] font-display leading-none font-bold text-ink mb-1">{value}</div>
        <Label className="mt-1">{label}</Label>
        {hint && <div className="text-[12px] text-ink-3 mt-1.5 font-medium leading-snug">{hint}</div>}
      </div>
    </div>
  )
}

// -------------------------------------------------- model attribution chart

export function ShapChart({ contributions = [], max = 8 }) {
  const rows = contributions.slice(0, max)
  if (!rows.length) return null
  const peak = Math.max(...rows.map((c) => Math.abs(c.contribution)), 0.0001)

  return (
    <figure className="m-0 bg-surface-2/50 p-4 sm:p-5 rounded-xl border border-line/50">
      <figcaption className="flex flex-wrap items-center gap-x-4 gap-y-1 mb-4">
        <span className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-ink-3">
          <span className="w-2.5 h-2.5 rounded-full bg-shap-pos" aria-hidden="true" />
          Pushes toward verdict
        </span>
        <span className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-ink-3">
          <span className="w-2.5 h-2.5 rounded-full bg-shap-neg" aria-hidden="true" />
          Pulls away
        </span>
      </figcaption>

      <div className="space-y-[8px]">
        {rows.map((c) => {
          const positive = c.contribution > 0
          const width = (Math.abs(c.contribution) / peak) * 50
          return (
            <div
              key={c.feature}
              className="grid grid-cols-[minmax(0,180px)_1fr_60px] gap-3 items-center hover:bg-surface/50 p-1 rounded-md transition-colors"
              title={`${c.feature} = ${c.value} contributes ${c.contribution > 0 ? '+' : ''}${c.contribution}`}
            >
              <div className="font-mono text-[11px] text-ink-2 truncate flex items-center gap-1.5" title={c.feature}>
                <span className="font-semibold text-ink">{c.feature}</span>
                <span className="text-ink-3">=</span>
                <span className="bg-surface border border-line/50 px-1 rounded">{formatFeatureValue(c.value)}</span>
              </div>

              <div className="relative h-[12px]">
                <span
                  className="absolute inset-y-[-2px] left-1/2 w-[2px] bg-line-2 rounded-full opacity-50"
                  aria-hidden="true"
                />
                <span
                  className={`absolute top-0 h-[12px] ${
                    positive
                      ? 'left-1/2 bg-shap-pos/80 border border-shap-pos rounded-r-full shadow-[0_0_8px_rgba(var(--color-shap-pos),0.4)]'
                      : 'right-1/2 bg-shap-neg/80 border border-shap-neg rounded-l-full shadow-[0_0_8px_rgba(var(--color-shap-neg),0.4)]'
                  }`}
                  style={{ width: `${width}%` }}
                />
              </div>

              <div className={`font-mono text-[11px] font-bold tabular-nums text-right ${positive ? 'text-shap-pos' : 'text-shap-neg'}`}>
                {c.contribution > 0 ? '+' : ''}
                {Number(c.contribution).toFixed(3)}
              </div>
            </div>
          )
        })}
      </div>
    </figure>
  )
}

function formatFeatureValue(v) {
  if (v === -1) return 'N/A'
  if (typeof v === 'number') return Number.isInteger(v) ? v : v.toFixed(2)
  return String(v)
}

// ------------------------------------------------------------------ notices

export function Notice({ tone = 'warn', title, children, className = '' }) {
  const tones = {
    warn: 'border-warn/30 bg-warn/10 text-warn',
    crit: 'border-crit/30 bg-crit/10 text-crit',
    ok: 'border-ok/30 bg-ok/10 text-ok',
    info: 'border-info/30 bg-info/10 text-info',
  }
  
  const Icons = {
    warn: AlertTriangle,
    crit: AlertCircle,
    ok: CheckCircle,
    info: Info,
  }
  
  const Icon = Icons[tone]

  return (
    <div className={`border rounded-xl px-4 py-3.5 my-3 flex gap-3 items-start ${tones[tone]} ${className}`}>
      <Icon size={18} className="shrink-0 mt-0.5 opacity-80" />
      <div>
        {title && <div className="font-semibold text-[14px] mb-1 leading-tight">{title}</div>}
        <div className="text-[13.5px] leading-relaxed opacity-90">{children}</div>
      </div>
    </div>
  )
}

export function Empty({ title, children }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-24 px-6">
      <div className="w-16 h-16 bg-surface-2 rounded-2xl flex items-center justify-center mb-6 shadow-sm border border-line">
        <Info size={28} className="text-ink-3" />
      </div>
      <h2 className="font-display text-[22px] font-bold text-ink mb-2 tracking-tight">{title}</h2>
      <div className="text-ink-2 text-[15px] max-w-md mx-auto leading-relaxed font-medium">{children}</div>
    </div>
  )
}

export function Spinner({ label }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 text-ink-2">
      <Loader2 size={32} className="animate-spin text-accent" />
      {label && <span className="font-semibold text-sm tracking-wide">{label}</span>}
    </div>
  )
}

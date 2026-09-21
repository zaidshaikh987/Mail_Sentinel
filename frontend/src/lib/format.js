/* Small formatting helpers, kept out of the components. */

export function bytes(n) {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

export function datetime(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  } catch {
    return String(iso)
  }
}

export function dateOnly(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
    })
  } catch {
    return String(iso)
  }
}

/** Tri-state booleans read better as words than as true/false/null. */
export function yesNo(v, unknown = 'not observable') {
  if (v === true) return 'yes'
  if (v === false) return 'no'
  return unknown
}

export function shortHash(h, n = 16) {
  if (!h) return '—'
  return h.length <= n ? h : `${h.slice(0, n)}…`
}

export function titleCase(s) {
  if (!s) return '—'
  return String(s).replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

/** Protocol + mode as one legible phrase. */
export function sessionKind(s) {
  const proto = (s.protocol || 'unknown').toUpperCase()
  const mode = {
    implicit: 'implicit TLS',
    starttls: 'STARTTLS',
    cleartext: 'cleartext',
    unknown: 'unknown mode',
  }[s.tls_mode] || s.tls_mode
  return `${proto} over ${mode}`
}

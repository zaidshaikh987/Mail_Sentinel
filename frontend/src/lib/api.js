/*
 * API client.
 *
 * One source of data: the Spring Boot backend at /api. There used to be a
 * second — pre-generated engine reports in public/samples/, served when no
 * backend was reachable — and it was a mistake. It meant two code paths through
 * the same screens, and they drifted: exports worked in one and not the other,
 * and a static-routing bug could only ever be hit on the sample path. A demo
 * that does not exercise the real path is not a demo of the product.
 *
 * The bundled captures are still one click away; they are now analysed by the
 * backend like any upload.
 */

export const fetchWithAuth = async (url, options = {}) => {
  const token = localStorage.getItem('sms-token');
  const headers = { ...options.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return fetch(url, { ...options, headers });
};


async function json(res) {
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body && body.message) message = body.message
    } catch {
      /* the response had no JSON body; the status line is all we have */
    }
    const err = new Error(message)
    err.status = res.status
    throw err
  }
  return res.json()
}

/**
 * Is the backend reachable, and can it actually analyse?
 *
 * `status` is UP only when the engine imported cleanly; DEGRADED means the API
 * is up but the interpreter cannot run the engine, and the body carries the
 * reason and the fix. The UI shows that rather than failing at upload time.
 */
export async function health() {
  try {
    const res = await fetchWithAuth('/api/health', { signal: AbortSignal.timeout(4000) })
    const body = await res.json()
    return { ...body, reachable: true }
  } catch {
    return { reachable: false, status: 'DOWN' }
  }
}

/** The bundled captures the backend can analyse on request. */
export async function listDemoCaptures() {
  return json(await fetchWithAuth('/api/demo-captures'))
}

/** Analyse a bundled capture — the same pipeline an upload takes. */
export async function analyseDemoCapture(name, investigationId) {
  return json(await fetchWithAuth(`/api/captures/demo/${encodeURIComponent(name)}?sync=false${investigationId ? `&investigationId=${investigationId}` : ""}`, {
    method: 'POST',
  }))
}

export async function listCaptures() {
  return json(await fetchWithAuth('/api/captures'))
}

export async function getCapture(id) {
  return json(await fetchWithAuth(`/api/captures/${id}`))
}

export async function getSession(captureId, sessionId) {
  return json(await fetchWithAuth(`/api/captures/${captureId}/sessions/${sessionId}`))
}

export async function uploadCapture(file, { sync = false, investigationId } = {}) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetchWithAuth(`/api/captures${sync ? '/sync' : ''}${investigationId ? `?investigationId=${investigationId}` : ''}`, {
    method: 'POST',
    body: form,
  })
  return json(res)
}

export async function deleteCapture(id) {
  const res = await fetchWithAuth(`/api/captures/${id}`, { method: 'DELETE' })
  if (!res.ok && res.status !== 204) throw new Error('could not delete that capture')
}

export function reportJsonUrl(id) {
  return `/api/captures/${id}/report.json`
}

export function reportHtmlUrl(id) {
  return `/api/captures/${id}/report.html`
}

/**
 * The same report, opened so the browser prints it.
 *
 * There is no server-side PDF endpoint. There was one, backed by WeasyPrint,
 * and it needed Pango and cairo — native libraries that install in a container
 * and usually not on a laptop, so it answered 501 wherever anyone used it. The
 * report already carries `@page` rules, so the browser produces the same
 * document with nothing installed, identically in every deployment.
 */
export function reportPrintUrl(id) {
  return `/api/captures/${id}/report.html?print=1`
}

/*
 * The backend returns a flattened, camelCase view of a capture; the engine's own
 * JSON is snake_case and nested. The UI works against the engine shape, so a
 * live backend response is mapped onto it here — one adapter, in one place.
 */
export function adaptBackendCapture(detail) {
  if (detail.report) return { ...detail.report, investigation_id: detail.investigationId,
    sessions: detail.report.sessions.map(s => ({ ...s, backendId: detail.sessions?.find(row => row.stream === s.tcp_stream)?.id })) }
  return {
    investigation_id: detail.investigationId,
    coverage: detail.coverage,
    provenance: detail.provenance,
    history: detail.history,
    capture: {
      filename: detail.filename,
      sha256: detail.sha256,
      bytes: detail.sizeBytes,
      format: detail.format,
      packet_count: detail.packetCount,
      first_packet_time: detail.capturedAt,
    },
    overall_grade: detail.overallGrade,
    overall_score: detail.overallScore,
    counts: {
      sessions: detail.counts?.sessions ?? 0,
      assets: detail.counts?.assets ?? 0,
      critical: detail.counts?.critical ?? 0,
      high: detail.counts?.high ?? 0,
      medium: detail.counts?.medium ?? 0,
      low: detail.counts?.low ?? 0,
      credentials_exposed: detail.counts?.credentialsExposed ?? 0,
    },
    assets: (detail.assets || []).map((a) => ({
      key: a.key,
      host: a.host,
      port: a.port,
      protocol: a.protocol,
      role: a.role,
      grade: {
        letter: a.grade,
        raw_score: a.rawScore,
        capped_by: a.cappedBy,
        trusted: a.trusted,
      },
      session_count: a.sessionCount,
      distinct_clients: a.distinctClients,
      best_tls: a.bestTls,
      worst_tls: a.worstTls,
      version_spread: a.versionSpread,
      credentials_exposed: a.credentialsExposed,
      exposure_score: a.exposureScore,
    })),
    sessions: (detail.sessions || []).map(adaptBackendSession),
    remediation: detail.remediation || [],
    warnings: detail.warnings || [],
  }
}

export function adaptBackendSession(s) {
  const [clientIp, clientPort] = String(s.client || ':').split(':')
  const [serverIp, serverPort] = String(s.server || ':').split(':')
  return {
    backendId: s.id,
    tcp_stream: s.stream,
    first_frame: s.firstFrame,
    last_frame: s.lastFrame,
    protocol: s.protocol,
    role: s.role,
    tls_mode: s.tlsMode,
    client: { ip: clientIp, port: Number(clientPort) },
    server: { ip: serverIp, port: Number(serverPort) },
    server_name: s.serverName,
    tls_version: s.tlsVersion,
    cipher_suite: s.cipherSuite,
    kex: s.keyExchange,
    kex_bits: s.keyExchangeBits,
    forward_secrecy: s.forwardSecrecy,
    cert_visibility: s.certVisibility,
    chain: s.chain || (s.certSubject
      ? [{
          subject: s.certSubject,
          issuer: s.certIssuer,
          self_signed: s.certSelfSigned,
          expired_at_capture: s.certExpiredAtCapture,
        }]
      : []),
    chain_valid: s.chainValid,
    starttls_offered: s.starttlsOffered,
    starttls_requested: s.starttlsRequested,
    starttls_accepted: s.starttlsAccepted,
    capability_mangled: s.capabilityMangled,
    mangled_token: s.mangledToken,
    cleartext_auth: s.cleartextAuth ? { username: s.exposedUsername } : null,
    confidence: s.confidence,
    ja3: s.ja3,
    ja4: s.ja4,
    grade: {
      letter: s.grade,
      raw_score: s.rawScore,
      capped_by: s.cappedBy,
      trusted: s.trusted,
      components: s.components || {},
    },
    ml: s.ml || (s.mlRiskClass
      ? {
          risk_class: s.mlRiskClass,
          risk_score: s.mlRiskScore,
          anomaly: s.mlAnomaly,
          explanation: s.mlExplanation,
          shap: [],
        }
      : null),
    findings: s.findings || [],
    command_transcript: s.transcript || [],
    notes: s.notes || [],
  }
}

export const listInvestigations = async () => json(await fetchWithAuth('/api/investigations'))
export const getInvestigation = async id => json(await fetchWithAuth(`/api/investigations/${id}`))
export const createInvestigation = async name => json(await fetchWithAuth('/api/investigations', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }),
}))
export const cancelRun = async id => json(await fetchWithAuth(`/api/captures/${id}/cancel`, { method: 'POST' }))
export const retryRun = async id => json(await fetchWithAuth(`/api/captures/${id}/retry`, { method: 'POST' }))
export const compareRuns = async (id, before, after) => json(await fetchWithAuth(`/api/investigations/${id}/compare?before=${before}&after=${after}`))
export const saveRemediation = async (id, key, status, note = '') => json(await fetchWithAuth(`/api/investigations/${id}/remediation`, {
  method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, status, note }),
}))

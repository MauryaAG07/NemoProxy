import type { EvidenceItem, InvestigationResult, SandboxSession, Verdict } from './types'

// Backend contract — spec §5 (verified against the rewritten backend in
// backend/ and the SpacetimeDB module in spacetimedb/src/index.ts):
//   GET  /api/health                       -> { status, demo_mode, credentials_status }
//   GET  /api/scenarios                    -> [{ key, id, name, raw_message, target_domain }]
//   POST /api/ingest { scenario }          -> { incident_id, status: 'queued' }
//        scenario is one of 'phishing' | 'legitimate' | 'ambiguous' | 'injection'
//        (a browser-supplied user_id is ignored for ownership)
//   GET  /api/state                        -> { incidents, evidence_items,
//                                              proposed_actions, sandbox_sessions }
//        incident (message_event JOIN investigation_status):
//          { incident_id, scenario_id, status: 'investigating'|'assessed'|'failed'|'incomplete',
//            verdict: 'suspected_phishing'|'benign_indicator'|
//                     'insufficient_evidence'|'pending',
//            confidence_band: 'low'|'medium'|'high', summary, redacted_message,
//            unknowns, assessment,
//            investigation_started_at_ms, investigation_finished_at_ms,
//            investigation_duration_ms }
//        Timings (spec §10): investigation_duration_ms is the server-side
//        pipeline wall time in ms (null until the final assessment is
//        published). fetchIncidentTiming reads the three fields so the
//        frontend can show DB-to-client latency in the operator view.
//        'incomplete' (Phase C) = budget exhausted or unvalidatable model
//        output: partial evidence kept, no verdict produced.
//        assessment (Phase C, demo mode) = the validated structured
//        assessment { concern_level, explanation, evidence_ids,
//        missing_evidence, conflicts_resolved, recommended_next_step,
//        proposed_action, recovery_step_ids, recovery_steps,
//        injection_attempt_detected, injection_details, unknowns };
//        live read-back carries null (no §5 column) and the key facts
//        stay in the human-readable summary.
//        The §5 investigation_status table has no verdict column, so the
//        backend writes it as a "verdict=<v>" first line of the stored
//        explanation and strips it again here; a row with no recorded
//        verdict reads back as 'pending' and is treated as not ready.
//        evidence item (evidence table): { evidence_id, incident_id,
//          source_tool (= type), is_simulated, summary (= result),
//          raw_json ('' on live read-back — the §5 table has no column) }
//   POST /api/session/compromise           -> { session: { session_id, status: 'compromised_sim', ... } }
//   POST /api/session/revoke { session_id }-> { session: { session_id, status: 'revoked', ... },
//                                              action_id, idempotency_key, receipt, source }
//        (Phase B: revoke now runs the approved flow — propose → approve
//        → revoke with one idempotency key — server-side.)
//   POST /api/session/protect { session_id, reason?, idempotency_key? }
//        -> same approved revocation, customer 'Protect demo account' action
//   POST /api/session/issue                -> sets the HttpOnly
//        'nemo_session' cookie (raw credential is ONLY in the cookie, never
//        in the JSON body); -> { session_id, credential_issued, expires_at_ms }
//   POST /api/session/reset                -> resets the demo run in
//        SpacetimeDB, issues a fresh credential (new cookie)
//   GET  /api/account/overview              -> fictional sandbox account
//        overview; requires the session credential (cookie or Bearer).
//        401 revoked/expired/wrong/missing, 503 SpacetimeDB unreachable.
//   (POST /api/session/toggle_sim_freeze was removed in Phase A: the §5
//   session table has no SIM-freeze column.)
//
// The backend keeps its own synthetic fixture per scenario key and redacts
// it server-side; the frontend sends ONLY the scenario key, never a message
// or an expected label. A failed live call is never presented as a live
// success — the caller falls back only to an explicitly labelled mock.

const API_URL = (import.meta.env.VITE_API_URL as string | undefined) || ''

// Mode is decided at RUNTIME, not build time. Vite inlines
// import.meta.env.VITE_* at build time, so a plain
// `const MOCK_MODE = import.meta.env.VITE_MOCK_MODE !== 'false'` folds to
// a constant `true` and Rollup dead-code-eliminates every live branch —
// the built bundle then contains no /api/* calls at all. Checking the URL
// (?mode=live|mock) and localStorage first keeps the live code in the bundle.
export function isMockMode(): boolean {
  if (typeof window !== 'undefined') {
    const q = new URLSearchParams(window.location.search).get('mode')
    if (q === 'live') return false
    if (q === 'mock') return true
    try {
      const stored = window.localStorage.getItem('nemoproxy-mode')
      if (stored === 'live') return false
      if (stored === 'mock') return true
    } catch {
      // storage unavailable — fall through to the env default
    }
  }
  return (import.meta.env.VITE_MOCK_MODE as string | undefined) !== 'false'
}

export const MOCK_MODE = isMockMode()

export function setMode(mode: 'live' | 'mock'): void {
  try {
    window.localStorage.setItem('nemoproxy-mode', mode)
  } catch {
    // ignore
  }
  window.location.search = `mode=${mode}`
}

export type BackendScenarioKey = 'phishing' | 'legitimate' | 'ambiguous' | 'injection'

function url(path: string): string {
  return `${API_URL}${path}`
}

async function fetchJson(path: string, init?: RequestInit, timeoutMs = 5000) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url(path), { ...init, signal: ctrl.signal })
    if (!res.ok) throw new Error(`Backend ${res.status}`)
    return (await res.json()) as Record<string, unknown>
  } finally {
    clearTimeout(t)
  }
}

/** Like fetchJson, but returns the HTTP status instead of throwing on
 * 4xx/5xx — the protected-resource test needs to SHOW the 401/503, not
 * hide it. Sends cookies (the HttpOnly session credential). */
async function fetchStatus(
  path: string,
  init?: RequestInit,
  timeoutMs = 5000,
): Promise<{ status: number; data: Record<string, unknown> | null }> {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url(path), { ...init, signal: ctrl.signal, credentials: 'include' })
    let data: Record<string, unknown> | null = null
    try {
      data = (await res.json()) as Record<string, unknown>
    } catch {
      data = null
    }
    return { status: res.status, data }
  } finally {
    clearTimeout(t)
  }
}

export interface BackendHealth {
  healthy: boolean
  /** True when the backend reports demo_mode: its Nemotron/reputation results are simulated. */
  demoMode: boolean
}

export async function checkBackend(): Promise<BackendHealth> {
  try {
    const data = await fetchJson('/api/health', undefined, 3000)
    return { healthy: data.status === 'healthy', demoMode: data.demo_mode === true }
  } catch {
    return { healthy: false, demoMode: false }
  }
}

export interface BackendScenario {
  key: BackendScenarioKey
  id: string
  name: string
  raw_message: string
  target_domain: string
}

export async function fetchScenarios(): Promise<BackendScenario[] | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/scenarios')
    return data as unknown as BackendScenario[]
  } catch {
    return null
  }
}

/** Create an incident on the backend. Returns null when no backend is reachable. */
export async function createIncident(
  scenarioKey: BackendScenarioKey,
): Promise<string | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenarioKey }),
    })
    const id = data.incident_id
    return typeof id === 'string' ? id : null
  } catch {
    return null
  }
}

function mapVerdict(v: string): Verdict | null {
  if (v === 'benign_indicator') return 'legitimate_looking'
  if (v === 'insufficient_evidence') return 'insufficient_evidence'
  if (v === 'suspected_phishing') return 'suspected_phishing'
  // 'pending' (or anything unknown): no recorded verdict — never invent one.
  return null
}

function mapConfidence(band: string): 'low' | 'medium' | 'high' {
  if (band === 'high') return 'high'
  if (band === 'medium') return 'medium'
  return 'low'
}

/** Poll GET /api/state for a finished result. Null = not ready / unreachable.
 * The result mode is 'live' only when the backend is NOT in demo mode;
 * a demo-mode backend returns simulated Nemotron results, labelled 'live-demo'.
 * Phase C: an 'incomplete' incident (budget exhausted / unvalidatable
 * output) is also terminal — it returns a result with incomplete=true and
 * the partial evidence, never a faked verdict.
 * Timings (spec §10): the incident also carries
 * investigation_started_at_ms / investigation_finished_at_ms /
 * investigation_duration_ms (server-side pipeline wall time, null until
 * the final assessment is published). See fetchIncidentTiming. */
export async function fetchIncidentResult(
  incidentId: string,
  claimedOrg: string,
  requestedAction: string,
): Promise<InvestigationResult | null> {
  if (MOCK_MODE) return null
  try {
    const health = await checkBackend()
    const data = await fetchJson('/api/state')
    const incidents = (data.incidents ?? []) as Record<string, unknown>[]
    const inc = incidents.find((i) => i.incident_id === incidentId)
    if (!inc || (inc.status !== 'assessed' && inc.status !== 'incomplete')) return null
    const evidence = ((data.evidence_items ?? []) as Record<string, unknown>[])
      .filter((e) => e.incident_id === incidentId)
      .map((e, i): EvidenceItem => {
        const raw = typeof e.raw_json === 'string' ? e.raw_json : ''
        return {
          id: String(e.evidence_id ?? `ev-${i}`),
          label: String(e.source_tool ?? 'evidence'),
          detail: String(e.summary ?? ''),
          source: e.is_simulated === false ? 'live' : 'simulated',
          limitation:
            raw.length > 0
              ? 'See the backend evidence record for the full fixture; a single tool result does not prove a reverse proxy or session theft.'
              : 'A single tool result does not prove a reverse proxy or session theft.',
        }
      })
    const summary = String(inc.summary ?? '')
    const split = summary.split('UNCERTAINTY BOUNDARY:')
    const assessment = (inc.assessment ?? null) as InvestigationResult['assessment']
    const recoverySteps =
      assessment && Array.isArray(assessment.recovery_steps)
        ? assessment.recovery_steps
        : []
    const base = {
      incidentId,
      claimedOrg,
      requestedAction,
      evidence,
      mode: health.demoMode ? 'live-demo' : 'live',
      reputationUrlNote:
        'Reputation result, if any, applies to the redacted/modified URL, not the original.',
      assessment,
      recoverySteps,
    } as const
    if (inc.status === 'incomplete') {
      return {
        ...base,
        verdict: 'insufficient_evidence',
        confidence: 'low',
        summary: split[0].trim() || summary,
        uncertainty:
          String(inc.unknowns ?? '') ||
          'The investigation ran out of budget before a validated assessment could be produced.',
        incomplete: true,
        incompleteReason: String(inc.unknowns ?? '') || summary,
      }
    }
    const verdict = mapVerdict(String(inc.verdict ?? ''))
    if (!verdict) return null // Assessed but no recorded verdict yet — not ready.
    return {
      ...base,
      verdict,
      confidence: mapConfidence(String(inc.confidence_band ?? 'low')),
      summary: split[0].trim() || summary,
      uncertainty: (split[1] ?? '').trim() ||
        'Domain age, hosting and brand mismatch are indicators, not proof a reverse proxy exists or a session was stolen.',
    }
  } catch {
    return null
  }
}

export interface IncidentTiming {
  /** Server-side pipeline wall time (redaction + Nemotron loop + commit),
   * in ms. Null until the final assessment is published, or when the
   * backend predates the timing fields. */
  investigationDurationMs: number | null
  investigationStartedAtMs: number | null
  investigationFinishedAtMs: number | null
}

/** Read one incident's server-side timings from GET /api/state (demo and
 * live mode alike). Null = backend unreachable or incident not present.
 * The caller uses investigationFinishedAtMs to measure DB-to-client
 * latency: time from the server committing the assessment to this
 * browser first seeing the result. */
export async function fetchIncidentTiming(
  incidentId: string,
): Promise<IncidentTiming | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/state')
    const incidents = (data.incidents ?? []) as Record<string, unknown>[]
    const inc = incidents.find((i) => i.incident_id === incidentId)
    if (!inc) return null
    const num = (v: unknown): number | null => (typeof v === 'number' ? v : null)
    return {
      investigationDurationMs: num(inc.investigation_duration_ms),
      investigationStartedAtMs: num(inc.investigation_started_at_ms),
      investigationFinishedAtMs: num(inc.investigation_finished_at_ms),
    }
  } catch {
    return null
  }
}

function mapSession(s: Record<string, unknown>, mode: 'live' | 'mock'): SandboxSession {
  const status = String(s.status ?? '')
  return {
    id: String(s.session_id ?? 'sess_demo_carrier_01'),
    accountLabel: `${String(s.device_label ?? 'Sandbox device')} · ${String(s.account_id ?? '')} (fictional, sandbox only)`,
    // Backend states are distinct: 'active' (normal), 'compromised_sim'
    // (controlled simulated compromise), 'revoked', 'expired'. Never
    // collapse compromised_sim into 'active' or 'active' into 'none'.
    // 'expired' has no UI state of its own — it is not a usable session.
    state:
      status === 'revoked'
        ? 'revoked'
        : status === 'compromised_sim'
          ? 'compromised'
          : status === 'active'
            ? 'active'
            : 'none',
    createdAt: Date.now(),
    revokedAt: status === 'revoked' ? Date.now() : undefined,
    mode,
  }
}

/** Live simulated compromise. Null = no backend; caller must not fake it. */
export async function simulateCompromiseLive(): Promise<SandboxSession | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/session/compromise', { method: 'POST' })
    const s = data.session as Record<string, unknown> | undefined
    return s ? mapSession(s, 'live') : null
  } catch {
    return null
  }
}

/** Live sandbox revocation. Returns the backend session, or null if unreachable. */
export async function revokeSessionLive(
  sessionId: string,
): Promise<SandboxSession | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/session/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId }),
    })
    const s = data.session as Record<string, unknown> | undefined
    return s ? mapSession(s, 'live') : null
  } catch {
    return null
  }
}

export interface ProtectResult {
  session: SandboxSession
  actionId: string
  idempotencyKey: string
  receipt: string
  source: string
}

/** Customer 'Protect demo account': the approved propose → approve →
 * revoke flow for THIS session, one idempotency key. Null = unreachable
 * or the backend refused (e.g. SpacetimeDB down — never faked). */
export async function protectDemoAccountLive(
  sessionId: string,
): Promise<ProtectResult | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/session/protect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId }),
    })
    const s = data.session as Record<string, unknown> | undefined
    if (!s) return null
    return {
      session: mapSession(s, 'live'),
      actionId: String(data.action_id ?? ''),
      idempotencyKey: String(data.idempotency_key ?? ''),
      receipt: String(data.receipt ?? ''),
      source: String(data.source ?? ''),
    }
  } catch {
    return null
  }
}

export interface ProtectedTestResult {
  status: number
  summary: string
  source?: string
}

/** Test the protected resource (GET /api/account/overview). Returns the
 * status code and a short summary even for 401/503 — the point of the
 * control is to SHOW the denial after revocation. The raw credential
 * is never read, shown, or stored here: it travels only in the
 * HttpOnly cookie the browser sends. Null = backend unreachable. */
export async function testProtectedResourceLive(): Promise<ProtectedTestResult | null> {
  if (MOCK_MODE) return null
  try {
    const { status, data } = await fetchStatus('/api/account/overview')
    if (status === 200 && data) {
      return {
        status,
        summary:
          `200 · fictional account ${String(data.account_id ?? '')} · ` +
          `${String(data.plan_name ?? '')} · balance $${String(data.balance_due_usd ?? '')} · ` +
          `data ${String(data.data_used_gb ?? '')}/${String(data.data_allowance_gb ?? '')} GB`,
        source: String(data.verification_source ?? ''),
      }
    }
    const detail =
      data && typeof data.detail === 'string' ? data.detail : 'Protected resource denied.'
    return { status, summary: `${status} · ${detail}` }
  } catch {
    return null
  }
}

/** Issue a fresh demo session credential. The raw credential lands in
 * the HttpOnly cookie only — this returns just the expiry. Null =
 * unreachable or the backend refused (e.g. session revoked). */
export async function issueSessionCredentialLive(): Promise<{ expiresAtMs: number } | null> {
  if (MOCK_MODE) return null
  try {
    const { status, data } = await fetchStatus('/api/session/issue', { method: 'POST' })
    if (status !== 200 || !data) return null
    return { expiresAtMs: Number(data.expires_at_ms ?? 0) }
  } catch {
    return null
  }
}

/** Reset the demo run: SpacetimeDB rows cleared, session active again,
 * old credential invalidated, fresh credential issued (new cookie).
 * Returns the fresh session, or null if unreachable/refused. */
export async function resetDemoRunLive(): Promise<SandboxSession | null> {
  if (MOCK_MODE) return null
  try {
    const { status, data } = await fetchStatus('/api/session/reset', { method: 'POST' })
    if (status !== 200 || !data) return null
    const s = data.session as Record<string, unknown> | undefined
    return s ? mapSession(s, 'live') : null
  } catch {
    return null
  }
}

/** Read the committed session state back from GET /api/state (source:
 * SpacetimeDB rows in live mode). Used after protect/revoke/reset so
 * both views show the committed outcome, not local state. */
export async function fetchSessionStateLive(): Promise<SandboxSession | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/state')
    const sessions = (data.sandbox_sessions ?? []) as Record<string, unknown>[]
    const s = sessions.find((x) => String(x.session_id ?? '') === 'sess_demo_carrier_01') ?? sessions[0]
    return s ? mapSession(s, 'live') : null
  } catch {
    return null
  }
}

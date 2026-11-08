import type { EvidenceItem, InvestigationResult, SandboxSession, Verdict } from './types'

// Backend contract — verified against MauryaAG07/NemoProxy main @ 06f9ed8b
// (backend/main.py, backend/incident.py, backend/spacetime_client.py):
//   GET  /api/health                       -> { status, demo_mode, credentials_status }
//   GET  /api/scenarios                    -> [{ key, id, name, raw_message, target_domain }]
//   POST /api/ingest { scenario }          -> { incident_id, status: 'queued' }
//        scenario is one of 'phishing' | 'legitimate' | 'ambiguous'
//        (a browser-supplied user_id is ignored for ownership)
//   GET  /api/state                        -> { incidents, evidence_items,
//                                              proposed_actions, sandbox_sessions }
//        incident: { incident_id, scenario_id, status: 'investigating'|'assessed',
//                    verdict: 'suspected_phishing'|'benign_indicator'|'insufficient_evidence',
//                    confidence_band: 'low'|'medium'|'high', summary, redacted_message }
//        evidence item: { evidence_id, incident_id, source_tool, is_simulated,
//                         summary, raw_json }
//   POST /api/session/compromise           -> { session: { session_id, status: 'compromised_sim', ... } }
//   POST /api/session/revoke { session_id }-> { session: { session_id, status: 'revoked', ... } }
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

export type BackendScenarioKey = 'phishing' | 'legitimate' | 'ambiguous'

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

function mapVerdict(v: string): Verdict {
  if (v === 'benign_indicator') return 'legitimate_looking'
  if (v === 'insufficient_evidence') return 'insufficient_evidence'
  return 'suspected_phishing'
}

function mapConfidence(band: string): 'low' | 'medium' | 'high' {
  if (band === 'high') return 'high'
  if (band === 'medium') return 'medium'
  return 'low'
}

/** Poll GET /api/state for a finished result. Null = not ready / unreachable.
 * The result mode is 'live' only when the backend is NOT in demo mode;
 * a demo-mode backend returns simulated Nemotron results, labelled 'live-demo'. */
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
    if (!inc || inc.status !== 'assessed') return null
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
    return {
      incidentId,
      verdict: mapVerdict(String(inc.verdict ?? '')),
      confidence: mapConfidence(String(inc.confidence_band ?? 'low')),
      claimedOrg,
      requestedAction,
      summary: split[0].trim() || summary,
      uncertainty: (split[1] ?? '').trim() ||
        'Domain age, hosting and brand mismatch are indicators, not proof a reverse proxy exists or a session was stolen.',
      evidence,
      mode: health.demoMode ? 'live-demo' : 'live',
      reputationUrlNote:
        'Reputation result, if any, applies to the redacted/modified URL, not the original.',
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
    // (controlled simulated compromise), 'revoked'. Never collapse
    // compromised_sim into 'active' or 'active' into 'none'.
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

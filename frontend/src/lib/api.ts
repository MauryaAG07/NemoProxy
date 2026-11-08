import type { InvestigationResult } from './types'

// Backend contract (see ../BACKEND_CONTRACT.md).
// The FastAPI backend on Chan's Mac exposes, per the spec:
//   POST /api/v1/incidents  { scenario_id }  -> { incident_id }
//   GET  /api/v1/incidents/{id}              -> incident + result when done
//   POST /api/v1/sandbox/sessions           -> { session_id }
//   POST /api/v1/sandbox/sessions/{id}/revoke -> { state: 'revoked' }
//
// This file tries that contract with a short timeout. If the backend is
// unreachable, or VITE_MOCK_MODE=true, the caller falls back to the
// labelled mock path — and the UI says so. A failed live call is never
// presented as a live success.

const API_URL = (import.meta.env.VITE_API_URL as string | undefined) || ''
export const MOCK_MODE =
  (import.meta.env.VITE_MOCK_MODE as string | undefined) !== 'false'

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

/** Create an incident on the backend. Returns null when no backend is reachable. */
export async function createIncident(scenarioId: string): Promise<string | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson('/api/v1/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario_id: scenarioId }),
    })
    const id = data.incident_id ?? data.id
    return typeof id === 'string' ? id : null
  } catch {
    return null
  }
}

/** Poll the backend for a finished result. Returns null if not ready / unreachable. */
export async function fetchIncidentResult(
  incidentId: string,
): Promise<InvestigationResult | null> {
  if (MOCK_MODE) return null
  try {
    const data = await fetchJson(`/api/v1/incidents/${incidentId}`)
    if (data.status !== 'complete' || !data.result) return null
    return { ...(data.result as InvestigationResult), mode: 'live' }
  } catch {
    return null
  }
}

/** Ask the backend to revoke a sandbox session. Null = no backend; caller uses mock. */
export async function revokeSessionLive(sessionId: string): Promise<boolean> {
  if (MOCK_MODE) return false
  try {
    await fetchJson(`/api/v1/sandbox/sessions/${sessionId}/revoke`, { method: 'POST' })
    return true
  } catch {
    return false
  }
}

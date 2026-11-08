// SpacetimeDB module — authoritative tables (spec).
// This file is the TypeScript mirror of the SpacetimeDB module that lives
// in spacetimedb/ at the repo root (reducers.ts). The real module is the
// source of truth; these types exist so the frontend and the module agree
// on table shapes. No credentials are stored here.
//
// Tables:
//   incidents        { id, scenario_id, status, created_at }
//   evidence         { id, incident_id, label, detail, source, limitation }
//   actions          { id, incident_id, kind, created_at }
//   sandbox_sessions { id, account_label, state, created_at, revoked_at }
//
// Reducers (called by the backend, never directly by the browser with a
// user-supplied id — server-generated ids / per-run ownership, spec §3):
//   create_incident(scenario_id) -> incident id
//   add_evidence(incident_id, label, detail, source, limitation)
//   set_verdict(incident_id, verdict, confidence, summary, uncertainty)
//   create_sandbox_session(account_label) -> session id
//   revoke_sandbox_session(session_id) -> state 'revoked'
//   ping() -> connectivity check (see backend verification step 2)

export interface SpacetimeIncidentRow {
  id: string
  scenarioId: string
  status: string
  createdAt: number
}

export interface SpacetimeEvidenceRow {
  id: string
  incidentId: string
  label: string
  detail: string
  source: 'simulated' | 'live'
  limitation: string
}

export interface SpacetimeSessionRow {
  id: string
  accountLabel: string
  state: 'active' | 'revoked'
  createdAt: number
  revokedAt?: number
}

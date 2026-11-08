// SpacetimeDB module — authoritative tables (spec).
// This file is the TypeScript mirror of the SpacetimeDB module that lives
// at the repo root in spacetimedb/src/index.ts (NOT reducers.ts — that
// file never existed in the module). The real module is the source of
// truth; these types exist so the frontend and the module agree on table
// shapes. No credentials are stored here.
//
// Verified live 2026-11-08 against a local SpacetimeDB 2.14.1 server:
// published as database `nemo-proxy`, every reducer below called via the
// CLI and read back with SQL.
//
// Tables (all public):
//   incident        { incident_id (pk), scenario_id, redacted_message,
//                     status, verdict, confidence_band, summary,
//                     created_at (timestamp) }
//   evidence_item   { evidence_id (pk), incident_id, source_tool,
//                     is_simulated, summary, raw_json }
//   proposed_action { action_id (pk), incident_id, action_type, reason,
//                     status }
//   sandbox_session { session_id (pk), account_id, device_label,
//                     phone_masked, status, sim_freeze_enabled,
//                     revocation_reason, updated_at (timestamp) }
//
// Reducers (called by the backend, never directly by the browser with a
// user-supplied id — server-generated ids / per-run ownership, spec §3):
//   create_incident(incident_id, scenario_id, redacted_message)
//   update_incident_verdict(incident_id, status, verdict, confidence_band, summary)
//   add_evidence(evidence_id, incident_id, source_tool, is_simulated, summary, raw_json)
//   propose_action(action_id, incident_id, action_type, reason)
//   create_sandbox_session(session_id, account_id, device_label, phone_masked)
//   trigger_compromise(session_id)
//   revoke_sandbox_session(session_id, reason)
//   toggle_sim_freeze(session_id)
//   ping() -> connectivity check (see backend verification step 2)

export type IncidentStatus = 'queued' | 'investigating' | 'assessed' | 'failed'
export type IncidentVerdict =
  | 'pending'
  | 'suspected_phishing'
  | 'insufficient_evidence'
  | 'benign_indicator'
export type ConfidenceBand = 'low' | 'medium' | 'high'

export interface SpacetimeIncidentRow {
  incident_id: string
  scenario_id: string
  redacted_message: string
  status: IncidentStatus
  verdict: IncidentVerdict
  confidence_band: ConfidenceBand
  summary: string
  created_at: number // SpacetimeDB timestamp, ms since epoch
}

export interface SpacetimeEvidenceRow {
  evidence_id: string
  incident_id: string
  source_tool: string
  is_simulated: boolean
  summary: string
  raw_json: string
}

export interface SpacetimeProposedActionRow {
  action_id: string
  incident_id: string
  action_type: string
  reason: string
  status: 'proposed' | 'accepted' | 'rejected'
}

export type SandboxSessionStatus = 'active' | 'compromised_sim' | 'revoked'

export interface SpacetimeSessionRow {
  session_id: string
  account_id: string
  device_label: string
  phone_masked: string
  status: SandboxSessionStatus
  sim_freeze_enabled: boolean
  revocation_reason: string
  updated_at: number // SpacetimeDB timestamp, ms since epoch
}

// SpacetimeDB module — authoritative tables (spec §5).
// This file is the TypeScript mirror of the SpacetimeDB module that lives
// in spacetimedb/src/index.ts. The real module is the source of truth;
// these types exist so the frontend and the module agree on table shapes.
// No credentials are stored here — the `session` table is private and
// does not even appear in the generated bindings.
//
// Verified live 2026-11-08 against a local SpacetimeDB 2.14.1 server:
// published as database `nemo-proxy`, every reducer called via the CLI
// and read back with SQL (see spacetimedb/README.md "Verified live").
//
// Tables (spec §5):
//   message_event        { incident_id (pk), owner_id, sanitized_message,
//                          scenario_id, created_at (timestamp) }
//   investigation_status { incident_id (pk), phase, concern_level,
//                          explanation, unknowns, version (u64),
//                          updated_at (timestamp) }
//   evidence             { evidence_id (pk), incident_id, type, result,
//                          source, is_simulated, observed_at (timestamp) }
//   session              PRIVATE { session_id (pk), owner_id,
//                          credential_hash, state, expiry (u64 ms),
//                          revoked_at (u64 ms, 0 = not revoked) }
//   response_action      { action_id (pk), incident_id, session_id, type,
//                          approval_state, execution_state,
//                          idempotency_key (unique), receipt }
//
// Identity-scoped views (credential-free projections of `session`):
//   customer_session_view { session_id (pk), owner_id, state, expiry,
//                           revoked_at } — rows owned by the caller's
//                           SpacetimeDB identity only
//   operator_session_view same shape — only when the caller is the
//                           backend service identity
// The demo seed session's owner_id is a fictional account id, not an
// identity, so both views return empty for it; session state for the
// demo reaches the UI through the backend's /api/state instead.
//
// Reducers (called by the backend, never directly by the browser —
// every reducer except `ping` requires the backend service identity):
//   create_incident(incident_id, owner_id, sanitized_message, scenario_id)
//   record_evidence(evidence_id, incident_id, type, result, source, is_simulated)
//   update_investigation_progress(incident_id, phase, concern_level, explanation, unknowns)
//   publish_assessment(incident_id, expected_version, phase, concern_level, explanation, unknowns)
//   create_session(session_id, owner_id, credential_hash, expiry)
//   propose_action(action_id, incident_id, session_id, type, idempotency_key)
//   approve_action(action_id, idempotency_key)
//   revoke_session(session_id, reason, idempotency_key)
//   inject_compromise(session_id, incident_id, idempotency_key)
//   reset_demo_run()
//   ping() -> connectivity check
//
// Verdict encoding: the §5 investigation_status table has no verdict
// column, so the backend writes the verdict as a machine-readable first
// line of `explanation` ("verdict=<verdict>\n<summary>") and strips it
// again when serving /api/state. The direct-subscription path in
// src/lib/sync.ts parses the same prefix (see parseAssessment there).
// An assessed row with no prefix has verdict "pending" — never invent a
// verdict from free text.

export type InvestigationPhase = 'queued' | 'investigating' | 'assessed' | 'failed'
export type ConcernLevel = 'low' | 'medium' | 'high'

export interface SpacetimeMessageEventRow {
  incident_id: string
  owner_id: string
  sanitized_message: string
  scenario_id: string
  created_at: number // SpacetimeDB timestamp, ms since epoch
}

export interface SpacetimeInvestigationStatusRow {
  incident_id: string
  phase: InvestigationPhase
  concern_level: ConcernLevel
  explanation: string
  unknowns: string
  version: bigint // u64
  updated_at: number // SpacetimeDB timestamp, ms since epoch
}

export interface SpacetimeEvidenceRow {
  evidence_id: string
  incident_id: string
  type: string
  result: string
  source: string
  is_simulated: boolean
  observed_at: number // SpacetimeDB timestamp, ms since epoch
}

export interface SpacetimeResponseActionRow {
  action_id: string
  incident_id: string
  session_id: string
  type: string
  approval_state: 'proposed' | 'approved' | 'rejected'
  execution_state: 'pending' | 'executed' | 'failed'
  idempotency_key: string
  receipt: string
}

// Credential-free projection returned by the session views. There is no
// credential_hash here by design — the private `session` table never
// exposes it to a client.
export interface SpacetimeSessionViewRow {
  session_id: string
  owner_id: string
  state: 'active' | 'compromised_sim' | 'revoked' | 'expired'
  expiry: bigint // u64, ms since epoch
  revoked_at: bigint // u64, ms since epoch; 0 = not revoked
}

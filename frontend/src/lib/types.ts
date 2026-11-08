// Shared types for NemoProxy. Keep these in sync with the backend
// (backend/main.py) and the SpacetimeDB module (spacetimedb/schema.ts).
// Expected labels live ONLY in scenarios.ts and are never sent to Nemotron.

export type Verdict =
  | 'suspected_phishing'
  | 'insufficient_evidence'
  | 'legitimate_looking'

export type IncidentStatus =
  | 'received'
  | 'investigating'
  | 'complete'
  | 'error'

export interface EvidenceItem {
  id: string
  label: string
  detail: string
  /** 'simulated' = fixture in this demo; 'live' = a real service supplied it. */
  source: 'simulated' | 'live'
  /** What this evidence does NOT prove. */
  limitation: string
}

export interface InvestigationResult {
  incidentId: string
  verdict: Verdict
  confidence: 'low' | 'medium' | 'high'
  claimedOrg: string
  requestedAction: string
  summary: string
  uncertainty: string
  evidence: EvidenceItem[]
  /** 'mock' = labelled demo path, no live Nemotron call. 'live' = backend/Nemotron. */
  mode: 'mock' | 'live'
  reputationUrlNote?: string
}

export interface Incident {
  id: string
  scenarioId: string
  status: IncidentStatus
  createdAt: number
  result?: InvestigationResult
  error?: string
}

export type SessionState = 'none' | 'active' | 'revoked'

export interface SandboxSession {
  id: string
  accountLabel: string
  state: SessionState
  createdAt: number
  revokedAt?: number
  /** 'mock' | 'live' — revocation is sandbox-only in both cases. */
  mode: 'mock' | 'live'
}

export interface SharedState {
  incident: Incident | null
  session: SandboxSession | null
  /** Incremented on every state change so both views re-render in sync. */
  version: number
}

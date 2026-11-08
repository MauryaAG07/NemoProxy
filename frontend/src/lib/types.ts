// Shared types for NemoProxy. Keep these in sync with the backend
// (backend/main.py) and the SpacetimeDB module (spacetimedb/src/index.ts).
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

export interface RecoveryStep {
  id: string
  label: string
}

export interface CrossCheck {
  claim: string
  domain_evidence: string
  reputation_evidence: string
  resolution: string
}

/** Phase C validated structured assessment (backend/nvidia_client.py).
 * No 0–100 probability, no confidence number — concern is a band. */
export interface StructuredAssessment {
  concern_level: 'low' | 'suspicious' | 'high' | 'inconclusive'
  explanation: string
  evidence_ids: string[]
  missing_evidence: string[]
  conflicts_resolved: CrossCheck[]
  recommended_next_step: string
  proposed_action?: string | null
  recovery_step_ids: string[]
  recovery_steps: RecoveryStep[]
  injection_attempt_detected: boolean
  injection_details: string
  unknowns: string
  is_simulated?: boolean
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
  /** 'mock' = labelled demo path, no live Nemotron call. 'live' = backend/Nemotron.
   * 'live-demo' = backend reachable but in demo mode (simulated Nemotron),
   * so a live-mode result must NOT be labelled as a live Nemotron result. */
  mode: 'mock' | 'live' | 'live-demo'
  reputationUrlNote?: string
  /** Phase C: validated structured assessment, when the backend served one. */
  assessment?: StructuredAssessment | null
  /** Phase C: recovery checklist selected for this subscriber's exposure. */
  recoverySteps?: RecoveryStep[]
  /** Phase C: budget exhausted / unvalidatable output — partial evidence
   * kept, no verdict produced. */
  incomplete?: boolean
  incompleteReason?: string
}

export interface Incident {
  id: string
  scenarioId: string
  status: IncidentStatus
  createdAt: number
  result?: InvestigationResult
  error?: string
}

export type SessionState = 'none' | 'active' | 'compromised' | 'revoked'

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

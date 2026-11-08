import { useEffect, useRef, useState } from 'react'
import type { SharedState, InvestigationResult, EvidenceItem, SandboxSession } from './types'
import { SCENARIOS } from './scenarios'
import { connectSpacetime, SPACETIME_HOST, type SpacetimeStatus } from '../spacetimedb/client'
import type { Incident as SpacetimeIncident, EvidenceItem as SpacetimeEvidence, SandboxSession as SpacetimeSession } from '../spacetimedb/types'
import { MOCK_MODE } from './api'

// Two synchronized demo views (spec: React + SpacetimeDB SDK).
// The authoritative store is SpacetimeDB (see src/spacetimedb/schema.ts
// and the generated bindings in src/spacetimedb/index.ts).
//
// When VITE_SPACETIMEDB_HOST is set (and the app is in live mode), the
// views stay in sync through a real DbConnection subscription to the
// incident / evidence_item / sandbox_session tables of the published
// `nemo-proxy` database. BroadcastChannel is then NOT used.
//
// When no SpacetimeDB host is configured (mock mode, or live mode without
// a host), the two views fall back to a BroadcastChannel (same browser,
// two tabs) plus React state (same tab, side-by-side). That fallback is
// labelled in the UI as "Demo sync", NOT as a live SpacetimeDB connection.
// A failed live connection also falls back to BroadcastChannel and the
// header reports the SpacetimeDB status as "error" — it is never faked
// as connected.

const CHANNEL = 'nemoproxy-sync-v1'

export const initialState: SharedState = {
  incident: null,
  session: null,
  version: 0,
}

function requestedActionFor(backendKey: string): string {
  if (backendKey === 'phishing') return 'Pay an overdue bill via a link'
  if (backendKey === 'legitimate') return 'View a billing statement (no payment request in message)'
  return 'Claim a voucher via a link'
}

function mapVerdict(v: string): InvestigationResult['verdict'] {
  if (v === 'benign_indicator') return 'legitimate_looking'
  if (v === 'insufficient_evidence') return 'insufficient_evidence'
  return 'suspected_phishing'
}

function mapConfidence(band: string): 'low' | 'medium' | 'high' {
  if (band === 'high') return 'high'
  if (band === 'medium') return 'medium'
  return 'low'
}

function toMillis(ts: { toMillis: () => bigint }): number {
  return Number(ts.toMillis())
}

export type SyncSource = 'spacetimedb' | 'broadcast'

export function useSharedState() {
  const [state, setState] = useState<SharedState>(initialState)
  const [spacetimeStatus, setSpacetimeStatus] = useState<SpacetimeStatus>(
    SPACETIME_HOST ? 'connecting' : 'not_configured',
  )
  const [syncSource, setSyncSource] = useState<SyncSource>('broadcast')
  // Refs so row callbacks always see the latest local state without
  // re-subscribing on every render.
  const stateRef = useRef(state)
  stateRef.current = state
  const evidenceRef = useRef<Map<string, EvidenceItem>>(new Map())

  // Evidence is cached per incident; clear it when a new investigation starts.
  const activeIncidentId = state.incident?.id
  useEffect(() => {
    evidenceRef.current.clear()
  }, [activeIncidentId])

  // BroadcastChannel fallback — used only when SpacetimeDB is not the
  // active sync source. A single channel instance is shared by the effect.
  const bcRef = useRef<BroadcastChannel | null>(null)
  const useBroadcastRef = useRef(true)

  useEffect(() => {
    if (MOCK_MODE || !SPACETIME_HOST) return undefined
    const handle = connectSpacetime({
      onStatus: (s) => {
        setSpacetimeStatus(s)
        if (s === 'connected') {
          useBroadcastRef.current = false
          setSyncSource('spacetimedb')
          bcRef.current?.close()
          bcRef.current = null
        } else if (s === 'error') {
          // Fall back to BroadcastChannel; header shows the error.
          useBroadcastRef.current = true
          setSyncSource('broadcast')
        }
      },
      onIncident: (row: SpacetimeIncident) => {
        const currentId = stateRef.current.incident?.id
        if (!currentId || row.incidentId !== currentId) return
        const result = buildResult(row, [...evidenceRef.current.values()])
        setState((prev) => {
          if (!prev.incident || prev.incident.id !== row.incidentId) return prev
          return {
            ...prev,
            incident: {
              ...prev.incident,
              status: row.status === 'assessed' ? 'complete' : 'investigating',
              result: row.status === 'assessed' ? result : prev.incident.result,
            },
            version: prev.version + 1,
          }
        })
      },
      onEvidence: (row: SpacetimeEvidence) => {
        const currentId = stateRef.current.incident?.id
        if (!currentId || row.incidentId !== currentId) return
        const item: EvidenceItem = {
          id: row.evidenceId,
          label: row.sourceTool,
          detail: row.summary,
          source: row.isSimulated === false ? 'live' : 'simulated',
          limitation: 'A single tool result does not prove a reverse proxy or session theft.',
        }
        evidenceRef.current.set(row.evidenceId, item)
        // Rebuild the result with the new evidence if the incident is done.
        setState((prev) => {
          if (!prev.incident || !prev.incident.result) return prev
          return {
            ...prev,
            incident: {
              ...prev.incident,
              result: { ...prev.incident.result, evidence: [...evidenceRef.current.values()] },
            },
            version: prev.version + 1,
          }
        })
      },
      onSession: (row: SpacetimeSession) => {
        const local = stateRef.current.session
        // Only mirror the DB session when there is no local session yet,
        // or when the DB reports a real state change (compromised/revoked).
        // Never let a stale 'active' row overwrite a locally compromised
        // or revoked session (the backend session endpoints do not write
        // to SpacetimeDB yet — see BACKEND_CONTRACT.md).
        if (local && row.sessionId === local.id) {
          if (row.status === 'active' && (local.state === 'compromised' || local.state === 'revoked')) return
        } else if (local) {
          return
        }
        const session: SandboxSession = {
          id: row.sessionId,
          accountLabel: `${row.deviceLabel} · ${row.accountId} (fictional, sandbox only)`,
          state:
            row.status === 'revoked'
              ? 'revoked'
              : row.status === 'compromised_sim'
                ? 'compromised'
                : row.status === 'active'
                  ? 'active'
                  : 'none',
          createdAt: toMillis(row.updatedAt),
          revokedAt: row.status === 'revoked' ? toMillis(row.updatedAt) : undefined,
          mode: 'live',
        }
        setState((prev) => ({ ...prev, session, version: prev.version + 1 }))
      },
    })
    return () => handle?.disconnect()
    // Connect once on mount; row handlers read latest state via refs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!useBroadcastRef.current && spacetimeStatus === 'connected') return undefined
    const bc = new BroadcastChannel(CHANNEL)
    bcRef.current = bc
    bc.onmessage = (ev: MessageEvent<SharedState>) => {
      if (ev.data && typeof ev.data.version === 'number') setState(ev.data)
    }
    return () => {
      bc.close()
      if (bcRef.current === bc) bcRef.current = null
    }
  }, [spacetimeStatus])

  const update = (fn: (prev: SharedState) => SharedState) => {
    setState((prev) => {
      const next = { ...fn(prev), version: prev.version + 1 }
      if (useBroadcastRef.current) {
        try {
          new BroadcastChannel(CHANNEL).postMessage(next)
        } catch {
          // BroadcastChannel unavailable — views in this tab still update.
        }
      }
      return next
    })
  }

  return { state, update, spacetimeStatus, syncSource }
}

function buildResult(
  row: SpacetimeIncident,
  evidence: EvidenceItem[],
): InvestigationResult {
  const scenario = SCENARIOS.find((s) => s.backendKey === row.scenarioId)
  const summary = row.summary || ''
  const split = summary.split('UNCERTAINTY BOUNDARY:')
  return {
    incidentId: row.incidentId,
    verdict: mapVerdict(row.verdict),
    confidence: mapConfidence(row.confidenceBand),
    claimedOrg: scenario?.sender ?? row.scenarioId,
    requestedAction: requestedActionFor(row.scenarioId),
    summary: split[0].trim() || summary,
    uncertainty:
      (split[1] ?? '').trim() ||
      'Domain age, hosting and brand mismatch are indicators, not proof a reverse proxy exists or a session was stolen.',
    evidence: evidence.filter((e) => e.id),
    mode: 'live',
    reputationUrlNote:
      'Reputation result, if any, applies to the redacted/modified URL, not the original.',
  }
}

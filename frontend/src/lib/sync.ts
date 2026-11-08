import { useEffect, useRef, useState } from 'react'
import type { SharedState, InvestigationResult, EvidenceItem, SandboxSession, Verdict } from './types'
import { SCENARIOS } from './scenarios'
import { connectSpacetime, SPACETIME_HOST, type SpacetimeStatus } from '../spacetimedb/client'
import type { MessageEvent as SpacetimeMessageEvent, InvestigationStatus as SpacetimeStatusRow, Evidence as SpacetimeEvidence, SessionView as SpacetimeSessionView } from '../spacetimedb/types'
import { MOCK_MODE } from './api'

// Two synchronized demo views (spec: React + SpacetimeDB SDK).
// The authoritative store is SpacetimeDB (see src/spacetimedb/schema.ts
// and the generated bindings in src/spacetimedb/index.ts).
//
// When VITE_SPACETIMEDB_HOST is set (and the app is in live mode), the
// views stay in sync through a real DbConnection subscription to the
// public spec §5 tables (message_event, investigation_status, evidence)
// plus the identity-scoped customer_session_view of the published
// `nemo-proxy` database. An incident row is the JOIN of a message_event
// row and its investigation_status row by incident_id. The private
// `session` table is never subscribed to — session state reaches the UI
// through the backend's /api/state instead (see src/lib/api.ts).
// BroadcastChannel is then NOT used.
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

/**
 * The §5 investigation_status table has no verdict column: the backend
 * writes the verdict as a machine-readable first line of `explanation`
 * ("verdict=<verdict>\n<summary>"). Parse it back here for the direct
 * subscription path (/api/state already strips it server-side). An
 * assessed row with no prefix has no recorded verdict — return null
 * rather than inventing one from free text.
 */
export function parseAssessment(explanation: string): { verdict: Verdict | null; summary: string } {
  const m = /^verdict=([a-z_]+)\n/.exec(explanation || '')
  if (!m) return { verdict: null, summary: explanation || '' }
  const verdict = mapVerdict(m[1])
  return { verdict, summary: explanation.slice(m[0].length) }
}

function mapVerdict(v: string): Verdict | null {
  if (v === 'benign_indicator') return 'legitimate_looking'
  if (v === 'insufficient_evidence') return 'insufficient_evidence'
  if (v === 'suspected_phishing') return 'suspected_phishing'
  return null
}

function mapConfidence(band: string): 'low' | 'medium' | 'high' {
  if (band === 'high') return 'high'
  if (band === 'medium') return 'medium'
  return 'low'
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
  const eventRef = useRef<Map<string, SpacetimeMessageEvent>>(new Map())
  const statusRef = useRef<Map<string, SpacetimeStatusRow>>(new Map())

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
      onMessageEvent: (row: SpacetimeMessageEvent) => {
        eventRef.current.set(row.incidentId, row)
        const currentId = stateRef.current.incident?.id
        if (!currentId || row.incidentId !== currentId) return
        // The event arrived (or re-arrived); if the assessment is already
        // in, rebuild the result with the event's scenario info.
        const status = statusRef.current.get(row.incidentId)
        if (!status || status.phase !== 'assessed') return
        const result = buildResult(row, status, [...evidenceRef.current.values()])
        if (!result) return
        setState((prev) => {
          if (!prev.incident || prev.incident.id !== row.incidentId) return prev
          return {
            ...prev,
            incident: { ...prev.incident, status: 'complete', result },
            version: prev.version + 1,
          }
        })
      },
      onInvestigationStatus: (row: SpacetimeStatusRow) => {
        statusRef.current.set(row.incidentId, row)
        const currentId = stateRef.current.incident?.id
        if (!currentId || row.incidentId !== currentId) return
        const event = eventRef.current.get(row.incidentId)
        if (!event) return
        if (row.phase !== 'assessed') {
          setState((prev) => {
            if (!prev.incident || prev.incident.id !== row.incidentId) return prev
            return {
              ...prev,
              incident: { ...prev.incident, status: 'investigating' },
              version: prev.version + 1,
            }
          })
          return
        }
        const result = buildResult(event, row, [...evidenceRef.current.values()])
        if (!result) return
        setState((prev) => {
          if (!prev.incident || prev.incident.id !== row.incidentId) return prev
          return {
            ...prev,
            incident: { ...prev.incident, status: 'complete', result },
            version: prev.version + 1,
          }
        })
      },
      onEvidence: (row: SpacetimeEvidence) => {
        const currentId = stateRef.current.incident?.id
        if (!currentId || row.incidentId !== currentId) return
        const item: EvidenceItem = {
          id: row.evidenceId,
          label: row.type,
          detail: row.result,
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
      onSession: (row: SpacetimeSessionView) => {
        const local = stateRef.current.session
        // Only mirror the view's session when there is no local session
        // yet, or when the view reports a real state change
        // (compromised/revoked). Never let a stale 'active' row overwrite
        // a locally compromised or revoked session.
        if (local && row.sessionId === local.id) {
          if (row.state === 'active' && (local.state === 'compromised' || local.state === 'revoked')) return
        } else if (local) {
          return
        }
        const session: SandboxSession = {
          id: row.sessionId,
          accountLabel: `${row.ownerId} (fictional, sandbox only)`,
          state:
            row.state === 'revoked'
              ? 'revoked'
              : row.state === 'compromised_sim'
                ? 'compromised'
                : row.state === 'active'
                  ? 'active'
                  : 'none',
          createdAt: Date.now(),
          revokedAt:
            row.state === 'revoked' && row.revokedAt > 0n
              ? Number(row.revokedAt)
              : row.state === 'revoked'
                ? Date.now()
                : undefined,
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
  event: SpacetimeMessageEvent,
  status: SpacetimeStatusRow,
  evidence: EvidenceItem[],
): InvestigationResult | null {
  const scenario = SCENARIOS.find((s) => s.backendKey === event.scenarioId)
  const { verdict, summary } = parseAssessment(status.explanation)
  // No recorded verdict in the row: do not present a result yet.
  if (!verdict) return null
  const split = summary.split('UNCERTAINTY BOUNDARY:')
  return {
    incidentId: event.incidentId,
    verdict,
    confidence: mapConfidence(status.concernLevel),
    claimedOrg: scenario?.sender ?? event.scenarioId,
    requestedAction: requestedActionFor(event.scenarioId),
    summary: split[0].trim() || summary,
    uncertainty:
      (split[1] ?? '').trim() ||
      (status.unknowns.trim() ||
        'Domain age, hosting and brand mismatch are indicators, not proof a reverse proxy exists or a session was stolen.'),
    evidence: evidence.filter((e) => e.id),
    mode: 'live',
    reputationUrlNote:
      'Reputation result, if any, applies to the redacted/modified URL, not the original.',
  }
}

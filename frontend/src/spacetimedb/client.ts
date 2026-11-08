// SpacetimeDB connection for the demo UI (spec §1, verification step 3).
//
// Uses the generated bindings in ./index.ts (produced by
// `spacetime generate nemo-proxy --lang typescript` against the real module
// at ../../spacetimedb/src/index.ts, published as database `nemo-proxy`).
// The SDK package `spacetimedb` is a dependency (package.json).
//
// Connection needs a host and database name only — no backend identity
// token, and no credentials of any kind, are shipped in this bundle.
// If VITE_SPACETIMEDB_HOST is unset, status is honestly "not_configured"
// and the two views fall back to BroadcastChannel (labelled "Demo sync").
// If it IS set, we connect with DbConnection and subscribe to the
// incident / evidence_item / sandbox_session tables; any failure is
// reported as "error", never faked as connected.

import { DbConnection } from './index'
import type { Incident, EvidenceItem, SandboxSession } from './types'

export type SpacetimeStatus =
  | 'not_configured'
  | 'connecting'
  | 'connected'
  | 'error'

export const SPACETIME_HOST =
  (import.meta.env.VITE_SPACETIMEDB_HOST as string | undefined) || ''
export const SPACETIME_DB =
  (import.meta.env.VITE_SPACETIMEDB_DB as string | undefined) || 'nemo-proxy'

export interface SpacetimeRowEvents {
  onIncident: (row: Incident) => void
  onEvidence: (row: EvidenceItem) => void
  onSession: (row: SandboxSession) => void
  onStatus: (status: SpacetimeStatus) => void
  /** Called once the initial subscription is applied and the cache is filled. */
  onReady?: (conn: DbConnection) => void
}

/**
 * Connect to the published `nemo-proxy` database and subscribe to the
 * three demo tables. Returns a handle to disconnect, or null when no host
 * is configured. Never throws — connection errors surface via onStatus.
 */
export function connectSpacetime(events: SpacetimeRowEvents): { disconnect: () => void } | null {
  if (!SPACETIME_HOST) {
    events.onStatus('not_configured')
    return null
  }
  events.onStatus('connecting')
  let conn: DbConnection | null = null
  try {
    conn = DbConnection.builder()
      .withUri(SPACETIME_HOST)
      .withDatabaseName(SPACETIME_DB)
      .onConnect((c) => {
        events.onStatus('connected')
        // Row-level events keep the two demo views in sync.
        c.db.incident.onInsert((_ctx, row) => events.onIncident(row))
        c.db.incident.onUpdate((_ctx, _oldRow, row) => events.onIncident(row))
        c.db.evidenceItem.onInsert((_ctx, row) => events.onEvidence(row))
        c.db.sandboxSession.onInsert((_ctx, row) => events.onSession(row))
        c.db.sandboxSession.onUpdate((_ctx, _oldRow, row) => events.onSession(row))
        c.subscriptionBuilder()
          .onApplied((ctx) => {
            // Initial snapshot: replay the rows already in the cache so a
            // late-opening view still sees the current incident/session.
            for (const row of ctx.db.incident.iter()) events.onIncident(row)
            for (const row of ctx.db.evidenceItem.iter()) events.onEvidence(row)
            for (const row of ctx.db.sandboxSession.iter()) events.onSession(row)
            events.onReady?.(c)
          })
          .onError((ctx) => {
            console.error('SpacetimeDB subscription error:', ctx.event)
            events.onStatus('error')
          })
          .subscribe([
            'SELECT * FROM incident',
            'SELECT * FROM evidence_item',
            'SELECT * FROM sandbox_session',
          ])
      })
      .onConnectError((_ctx, err) => {
        console.error('SpacetimeDB connect error:', err)
        events.onStatus('error')
      })
      .onDisconnect((_ctx, err) => {
        if (err) console.error('SpacetimeDB disconnected:', err)
        events.onStatus('error')
      })
      .build()
  } catch (err) {
    console.error('SpacetimeDB connect failed:', err)
    events.onStatus('error')
    return null
  }
  return {
    disconnect: () => {
      try {
        conn?.disconnect()
      } catch {
        // Already disconnected — nothing to do.
      }
    },
  }
}

/** Backwards-compatible one-shot status check (no subscription). */
export async function trySpacetimeConnect(): Promise<SpacetimeStatus> {
  if (!SPACETIME_HOST) return 'not_configured'
  return new Promise((resolve) => {
    let done = false
    const finish = (s: SpacetimeStatus) => {
      if (done) return
      done = true
      handle?.disconnect()
      resolve(s)
    }
    const handle = connectSpacetime({
      onIncident: () => {},
      onEvidence: () => {},
      onSession: () => {},
      onStatus: (s) => {
        if (s === 'connected' || s === 'error') finish(s)
      },
    })
    if (!handle) {
      resolve('not_configured')
      return
    }
    // Give up after 8s rather than hanging the UI.
    setTimeout(() => finish('error'), 8000)
  })
}

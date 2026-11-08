// SpacetimeDB connection for the demo UI (spec §1, §5).
//
// Uses the generated bindings in ./index.ts (produced by
// `spacetime generate --lang typescript --module-path spacetimedb`
// against the real module at ../../spacetimedb/src/index.ts, published
// as database `nemo-proxy`). The SDK package `spacetimedb` is a
// dependency (package.json).
//
// Connection needs a host and database name only — no backend identity
// token, and no credentials of any kind, are shipped in this bundle.
// If VITE_SPACETIMEDB_HOST is unset, status is honestly "not_configured"
// and the two views fall back to BroadcastChannel (labelled "Demo sync").
// If it IS set, we connect with DbConnection and subscribe to the public
// spec §5 tables (message_event, investigation_status, evidence) plus
// the identity-scoped customer_session_view. The private `session` table
// is not subscribable and does not appear in the generated bindings at
// all — session state reaches the UI through the backend's /api/state,
// never through a subscription. The operator_session_view is likewise
// not subscribed here: a browser identity never qualifies as the backend
// service identity, so it would always be empty for this client.
// Any failure is reported as "error", never faked as connected.

import { DbConnection } from './index'
import type {
  MessageEvent,
  InvestigationStatus,
  Evidence,
  SessionView,
} from './types'

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
  onMessageEvent: (row: MessageEvent) => void
  onInvestigationStatus: (row: InvestigationStatus) => void
  onEvidence: (row: Evidence) => void
  onSession: (row: SessionView) => void
  onStatus: (status: SpacetimeStatus) => void
  /** Called once the initial subscription is applied and the cache is filled. */
  onReady?: (conn: DbConnection) => void
}

/**
 * Connect to the published `nemo-proxy` database and subscribe to the
 * public §5 tables plus the customer session view. Returns a handle to
 * disconnect, or null when no host is configured. Never throws —
 * connection errors surface via onStatus.
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
        c.db.messageEvent.onInsert((_ctx, row) => events.onMessageEvent(row))
        c.db.investigationStatus.onInsert((_ctx, row) => events.onInvestigationStatus(row))
        c.db.investigationStatus.onUpdate((_ctx, _oldRow, row) => events.onInvestigationStatus(row))
        c.db.evidence.onInsert((_ctx, row) => events.onEvidence(row))
        c.db.customerSessionView.onInsert((_ctx, row) => events.onSession(row))
        c.db.customerSessionView.onUpdate((_ctx, _oldRow, row) => events.onSession(row))
        c.subscriptionBuilder()
          .onApplied((ctx) => {
            // Initial snapshot: replay the rows already in the cache so a
            // late-opening view still sees the current incident/session.
            for (const row of ctx.db.messageEvent.iter()) events.onMessageEvent(row)
            for (const row of ctx.db.investigationStatus.iter()) events.onInvestigationStatus(row)
            for (const row of ctx.db.evidence.iter()) events.onEvidence(row)
            for (const row of ctx.db.customerSessionView.iter()) events.onSession(row)
            events.onReady?.(c)
          })
          .onError((ctx) => {
            console.error('SpacetimeDB subscription error:', ctx.event)
            events.onStatus('error')
          })
          .subscribe([
            'SELECT * FROM message_event',
            'SELECT * FROM investigation_status',
            'SELECT * FROM evidence',
            'SELECT * FROM customer_session_view',
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
      onMessageEvent: () => {},
      onInvestigationStatus: () => {},
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

import { useEffect, useState } from 'react'
import type { SharedState } from './types'

// Two synchronized demo views (spec: React + SpacetimeDB SDK).
// The authoritative store is SpacetimeDB (see src/spacetimedb/schema.ts).
// Until a live SpacetimeDB host + generated bindings are configured,
// the two views in this demo stay in sync through a BroadcastChannel
// (same browser, two tabs) plus React state (same tab, side-by-side).
// This is labelled in the UI as "Demo sync", NOT as a live SpacetimeDB
// connection. When VITE_SPACETIMEDB_HOST is set, spacetimedb/client.ts
// attempts a real SDK connection and reports its true status.

const CHANNEL = 'nemoproxy-sync-v1'

export const initialState: SharedState = {
  incident: null,
  session: null,
  version: 0,
}

export function useSharedState() {
  const [state, setState] = useState<SharedState>(initialState)

  useEffect(() => {
    const bc = new BroadcastChannel(CHANNEL)
    bc.onmessage = (ev: MessageEvent<SharedState>) => {
      if (ev.data && typeof ev.data.version === 'number') setState(ev.data)
    }
    return () => bc.close()
  }, [])

  const update = (fn: (prev: SharedState) => SharedState) => {
    setState((prev) => {
      const next = { ...fn(prev), version: prev.version + 1 }
      try {
        new BroadcastChannel(CHANNEL).postMessage(next)
      } catch {
        // BroadcastChannel unavailable — views in this tab still update.
      }
      return next
    })
  }

  return { state, update }
}

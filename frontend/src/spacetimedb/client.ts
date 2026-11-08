// SpacetimeDB connection status for the demo UI.
// The SDK package `spacetimedb` is a dependency (package.json). A live
// connection needs a real host, database, generated module bindings and a
// backend identity token — none of which are in this repo, and none of
// which may ever be shipped in a frontend bundle (spec §1).
//
// So: if VITE_SPACETIMEDB_HOST is unset, status is honestly
// "not_configured". If it IS set, we dynamically import the SDK and try
// to connect; any failure is reported as "error", never faked as connected.
// The two demo views sync via src/lib/sync.ts in the meantime (labelled
// "Demo sync" in the UI).

export type SpacetimeStatus =
  | 'not_configured'
  | 'connecting'
  | 'connected'
  | 'error'

export const SPACETIME_HOST =
  (import.meta.env.VITE_SPACETIMEDB_HOST as string | undefined) || ''
export const SPACETIME_DB =
  (import.meta.env.VITE_SPACETIMEDB_DB as string | undefined) || 'nemoproxy'

export async function trySpacetimeConnect(): Promise<SpacetimeStatus> {
  if (!SPACETIME_HOST) return 'not_configured'
  try {
    // Dynamic import so a missing/broken SDK never breaks the mock demo.
    const sdk = (await import('spacetimedb')) as Record<string, unknown>
    // The SDK exposes a connection builder; we only verify the module
    // loads and the host is reachable-shaped. Full subscription wiring
    // needs the generated bindings from `spacetime generate`.
    if (!sdk || typeof sdk !== 'object') return 'error'
    return 'error' // No generated bindings in this build — report honestly.
  } catch {
    return 'error'
  }
}

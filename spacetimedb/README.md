# NemoProxy SpacetimeDB module

TypeScript module (SpacetimeDB 2.x) holding the shared state the FastAPI
backend writes and the React frontend subscribes to.

## Tables

| Table | Rows |
|---|---|
| `incident` | One per investigated message. `status`: queued / investigating / assessed / failed. `verdict`: pending / suspected_phishing / insufficient_evidence / benign_indicator |
| `evidence_item` | Evidence attached to an incident, with `source_tool` and `is_simulated` |
| `proposed_action` | Actions the agent proposes (e.g. `revoke_session`), `status`: proposed / accepted / rejected |
| `sandbox_session` | Sandbox carrier sessions. `status`: active / compromised_sim / revoked |

## Reducers (names are exact — the backend calls them by name)

- `create_incident(incident_id, scenario_id, redacted_message)`
- `update_incident_verdict(incident_id, status, verdict, confidence_band, summary)`
- `add_evidence(evidence_id, incident_id, source_tool, is_simulated, summary, raw_json)`
- `propose_action(action_id, incident_id, action_type, reason)`
- `create_sandbox_session(session_id, account_id, device_label, phone_masked)`
- `trigger_compromise(session_id)` — controlled simulated compromise, not a real breach
- `revoke_sandbox_session(session_id, reason)`
- `toggle_sim_freeze(session_id)`
- `ping()` — no-op connectivity check

`init` seeds the demo sandbox session `sess_demo_carrier_01`
(Samsung Galaxy S24 eSIM, `+1 (214) •••-4102`), the same one the backend
uses in mock mode.

## Check it

```bash
cd spacetimedb
npm install
npm run typecheck   # tsc --noEmit; passes
```

## Publish it (needs the SpacetimeDB CLI, on your Mac)

```bash
curl -sSf https://install.spacetimedb.com | sh
cd spacetimedb
spacetime publish nemo-proxy
```

Then point the backend at it:

```bash
SPACETIME_HOST=http://localhost:3000   # or your SpacetimeDB Cloud host
SPACETIME_DB=nemo-proxy
SPACETIME_TOKEN=<token>
DEMO_MODE=false
```

## What is NOT verified yet

- The live SpacetimeDB subscription is wired in the React frontend
  (`frontend/src/spacetimedb/client.ts` + `frontend/src/lib/sync.ts`,
  generated bindings in `frontend/src/spacetimedb/`), with
  BroadcastChannel only as a labelled fallback — but it has not yet been
  verified end-to-end in a browser against the live server, and the
  backend still does not write incidents to SpacetimeDB (its reducer
  calls use the old endpoint — see below), so a live-mode investigation
  will not yet appear in the SpacetimeDB tables.
- **The backend's `spacetime_client.py` does NOT match this module's
  server version yet.** It calls
  `POST {host}/api/{db}/reducer/<name>`, which returns **404** against a
  SpacetimeDB 2.14.1 server. The working endpoint is
  `POST {host}/v1/database/<database-identity>/call/<name>` (verified:
  `POST /v1/database/c20064.../call/ping` returns 200; the old
  `/api/nemo-proxy/reducer/ping` returns 404). The backend client needs
  updating to that endpoint, and `SPACETIME_DB` must be `nemo-proxy`
  (dashes — underscores are invalid database names).

## Verified live (2026-11-08, local server, SpacetimeDB 2.14.1)

- `npm run typecheck` passes; `spacetime build` succeeds.
- Published as database `nemo-proxy` (identity
  `c200645bcd25d414949c4a97fc7f7eca097e43ce7dcb90af441c1d53abe8c03f`).
- `init` seeds `sess_demo_carrier_01` (active).
- Live reducer calls via the CLI, read back with SQL:
  - `create_incident` → incident `inc_live_01`, investigating / pending / low
  - `add_evidence` → `ev_live_01`, `server_side_sanitizer`, `is_simulated=false`
  - `update_incident_verdict` → assessed / `suspected_phishing` / high
  - `propose_action` → `act_live_01`, `revoke_session`, proposed
  - `trigger_compromise` + `revoke_sandbox_session` → session `revoked`
    with the revocation reason stored.
- Two things the pasted Step 1 got wrong, fixed while building:
  - `@spacetimedb/spacetimedb` does not exist on npm (404); the real
    package is `spacetimedb` (^2.14.1), importing `spacetimedb/server`.
  - The decorator API (`@spacetimedb.table()`, `@spacetimedb.reducer()`)
    is not the current 2.x TypeScript module API; this module uses
    `schema()` + `table()` + `t.*` with reducers registered by name.
  - `tsconfig.json`: `moduleResolution: "node"` cannot resolve the
    `spacetimedb/server` subpath; this module uses `module: esnext` +
    `moduleResolution: bundler` (typecheck only — the CLI builds it).
  - The schema object must not be a named export as well as the default
    export, or the build fails with "exporting something that is not a
    spacetime export".

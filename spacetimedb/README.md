# NemoProxy SpacetimeDB module

TypeScript module (SpacetimeDB 2.x) holding the shared state the FastAPI
backend writes and the React frontend subscribes to. Implements the
spec §5 data model (Phase A, 2026-11-08).

## Tables (spec §5)

Investigation state, session state and action execution state are kept
separate on purpose.

| Table | Rows |
|---|---|
| `message_event` | One per investigated message: `incident_id` (pk), `owner_id`, `sanitized_message`, `scenario_id`, `created_at`. The "what arrived". |
| `investigation_status` | One per incident: `incident_id` (pk), `phase` (queued / investigating / assessed / failed), `concern_level` (low / medium / high), `explanation`, `unknowns`, `version` (u64), `updated_at` |
| `evidence` | Tool results: `evidence_id` (pk), `incident_id`, `type` (tool name), `result` (human-readable summary), `source` (provenance, e.g. `backend_tool_loop`), `is_simulated`, `observed_at` |
| `session` | **PRIVATE** (`public: false`): `session_id` (pk), `owner_id`, `credential_hash`, `state` (active / compromised_sim / revoked / expired), `expiry` (u64 ms), `revoked_at` (u64 ms, 0 = not revoked). No client can subscribe to it; `credential_hash` never leaves SpacetimeDB towards a client. |
| `response_action` | Actions + receipts: `action_id` (pk), `incident_id`, `session_id`, `type`, `approval_state` (proposed / approved / rejected), `execution_state` (pending / executed / failed), `idempotency_key` (unique), `receipt` |

## Old → new mapping (breaking change)

Published 2026-11-08 with `-c=always` — only synthetic test rows
existed, data loss was fine. The v1 schema is gone.

| v1 (removed) | §5 replacement |
|---|---|
| `incident` (status, verdict, confidence_band, summary) | `message_event` + `investigation_status` joined on `incident_id`. `status` → `phase`; `confidence_band` → `concern_level`; `summary` → `explanation`. There is **no verdict column**: the backend writes the verdict as a machine-readable first line of `explanation` (`verdict=<verdict>\n<summary>`) and strips it on read-back (see `backend/spacetime_client.py` `_encode_assessment` / `_parse_assessment`, and `frontend/src/lib/sync.ts` `parseAssessment`). A row with no prefix reads back as verdict `pending` — never invent a verdict from free text. |
| `evidence_item` (source_tool, summary, raw_json) | `evidence` (`type` = old `source_tool`, `result` = old `summary`, `source` = `backend_tool_loop`). `raw_json` has **no column** in §5: it stays in the backend's in-memory mirror only, and a live read-back returns `raw_json: ""`. |
| `proposed_action` (action_type, reason, status) | `response_action` (`type` = old `action_type`, `approval_state` = old `status`, plus `execution_state`, `idempotency_key`, `receipt`). `reason` has **no column** in §5: it stays in the mirror only; a live read-back returns `reason: ""`. The revoke reason is preserved in the revoke receipt string. |
| `sandbox_session` (account_id, device_label, phone_masked, sim_freeze_enabled, revocation_reason, updated_at) | `session` (private). Device label / phone / SIM-freeze are demo-UI labels with no §5 column: they live in the backend's `_DEMO_SESSION_META`, not in SpacetimeDB. `revocation_reason` is likewise not a column; the reason is in the revoke receipt. |

## Reducers (names are exact — the backend calls them by name)

- `create_incident(incident_id, owner_id, sanitized_message, scenario_id)` — inserts `message_event` + `investigation_status` (phase `investigating`, version 0)
- `record_evidence(evidence_id, incident_id, type, result, source, is_simulated)` — `observed_at` is server-set
- `update_investigation_progress(incident_id, phase, concern_level, explanation, unknowns)` — bumps `version`, no version gate
- `publish_assessment(incident_id, expected_version, phase, concern_level, explanation, unknowns)` — throws on a stale `expected_version`; bumps `version`
- `create_session(session_id, owner_id, credential_hash, expiry)` — `expiry` is u64 ms; state `active`, `revoked_at` 0
- `rotate_session_credential(session_id, credential_hash, expiry)` — **Phase B (spec §6)**: issues (or re-issues) a session credential hash + expiry; sets state `active`, clears `revoked_at`. Throws on a `revoked` session (reset the demo run first); creates the session if missing. Backend identity only.
- `propose_action(action_id, incident_id, session_id, type, idempotency_key)` — duplicate key: no-op, no duplicate row
- `approve_action(action_id, idempotency_key)` — wrong key throws; repeat approval with the same key: no-op, receipt already stored. Backend identity only — the model cannot approve.
- `revoke_session(session_id, reason, idempotency_key)` — flips the session row **and** writes the `response_action` receipt row in one reducer (one transaction, atomic). Repeat with the same key: no-op. Revoking an already-revoked session with a new key records that key's receipt without a duplicate state change. **Phase B: requires an APPROVED proposal** — the same key must first have been proposed with `propose_action` (type `revoke_session`) and approved with `approve_action`; a direct call with no approved proposal throws (verified: HTTP 530). The backend's `revoke_session()` in `spacetime_client.py` runs propose → approve → revoke internally, so its callers are unaffected.
- `inject_compromise(session_id, incident_id, idempotency_key)` — clearly labelled **synthetic** compromise event (state `compromised_sim` + receipt row `synthetic_compromise_sim_<session>_<key>`). Throws on a revoked/expired session.
- `reset_demo_run()` — deletes all `message_event` / `investigation_status` / `evidence` / `response_action` rows; resets the demo session to `active` (re-seeds it if missing). Other sessions are left alone. **Phase B: preserves the session's `credential_hash` and expiry** (it no longer downgrades the hash to the placeholder); the backend rotates in a fresh credential right after reset.
- `ping()` — no-op connectivity check

`init` seeds the demo sandbox session `sess_demo_carrier_01`
(owner `acct_tm_94821`, fictional), the same one the backend uses in
demo mode. Its `credential_hash` is the placeholder string
`demo_hash_placeholder__not_a_real_credential` — not a hash of any real
credential — and the table is private so no client can read it.

## Access control — what is enforced, and what is not

Verified against the installed `spacetimedb` 2.14.1 package
(`spacetimedb/server` API: `schema()` + `table()` + `t.*`, reducers
registered by name; `ctx.sender`, `ctx.env`, `spacetimedb.view`,
`clientVisibilityFilter` all read from its `.d.ts`/sources).

- **Writes are backend-only.** Every reducer except `ping` calls
  `requireBackend`, which compares `ctx.sender.toHexString()` with the
  module env var `BACKEND_IDENTITY` and throws otherwise. Enforcement is
  **fail-closed**: if `BACKEND_IDENTITY` is unset, all guarded reducers
  throw. Set it at publish time from a shell variable:
  `BACKEND_IDENTITY=<hex> spacetime publish -s local -c=always nemo-proxy`
  (verified: the CLI picks the declared shell variable up and
  `spacetime env list` shows it).
- **What a caller presents as `ctx.sender` (verified live):**
  a CLI call presents the CLI identity
  (`c2001c1a0c14…`, the owner shown by `spacetime list`); an HTTP call
  presents the identity of its Bearer token (the token in
  `~/.config/spacetime/cli.toml` presents the same CLI identity, so the
  backend's HTTP calls pass the guard); an anonymous HTTP call presents
  a fresh random identity and is rejected. In this local deployment the
  backend service identity IS the CLI/owner identity (single-identity
  demo deployment); a production deployment would use a dedicated
  service identity.
- **Session privacy.** `session` is `public: false`, so no client can
  subscribe to it — it does not even appear in the generated TypeScript
  bindings. Session state reaches the UI only through the backend's
  `/api/state`, whose SQL read-back deliberately omits `credential_hash`
  (verified: no `credential_hash` key or value in `/api/state` output).
- **Identity-scoped views** expose a credential-free projection
  (`session_id`, `owner_id`, `state`, `expiry`, `revoked_at`):
  `customer_session_view` returns only rows whose `owner_id` is the
  caller's SpacetimeDB identity (index probe on `owner_id`); 
  `operator_session_view` returns all rows, but only when the caller is
  the backend service identity, otherwise `[]`. Verified live via SQL:
  as the owner identity the customer view returns the owned session and
  the operator view returns all sessions; anonymous, both return empty.
  Limitation: the demo seed's `owner_id` is a fictional account id, not
  an identity, so both views return empty for it — the frontend keeps
  using `/api/state` for session state. A `clientVisibilityFilter` RLS
  rule was NOT used: the session table is private so there is nothing
  to filter, and RLS is being deprecated in favour of views in 2.x
  (the `clientVisibilityFilter.sql(...)` API does exist in 2.14.1, with
  `:sender` SQL parameters).
- **Not enforced:** the module does not check that an `owner_id` on a
  `message_event` belongs to the caller — ownership of incidents is the
  backend's job (it generates incident ids and ignores client-supplied
  `user_id`). Client-side filtering is never access control; the only
  client-readable session data is the projected views above.

## Idempotency and versions

- `propose_action` / `approve_action` / `revoke_session` /
  `inject_compromise` take an idempotency key. A repeat with the same key
  returns the already-stored receipt without a duplicate effect (the
  module pre-checks the unique `idempotency_key` index and returns
  early, so a redelivery succeeds instead of throwing a unique
  violation). The backend generates a fresh key per call for
  compromise/revoke, and reuses the `action_id` as the key for proposed
  actions.
- `publish_assessment` takes `expected_version` and throws if it does
  not match `investigation_status.version`. The backend sends the
  mirror's version and retries once with a freshly read version.
- Reducers are single transactions: `revoke_session`'s session flip and
  receipt insert commit atomically.

## Check it

```bash
cd spacetimedb
npm install
npm run typecheck   # tsc --noEmit; passes
spacetime build     # passes
```

## Publish it (needs the SpacetimeDB CLI, on your Mac)

```bash
curl -sSf https://install.spacetimedb.com | sh
cd spacetimedb
BACKEND_IDENTITY=<backend-service-identity-hex> spacetime publish -s local -c=always nemo-proxy
```

`spacetime publish` defaults to SpacetimeDB Cloud (maincloud) — always
pass `-s local` here. Database names cannot contain underscores
(`nemo-proxy`, not `nemo_proxy`). This publish is a **breaking schema
change**: `-c=always` destroys the old data (only synthetic test rows
existed).

Then point the backend at it:

```bash
SPACETIME_HOST=http://localhost:3000   # or your SpacetimeDB Cloud host
SPACETIME_DB=nemo-proxy
SPACETIME_DB_IDENTITY=c200645bcd25d414949c4a97fc7f7eca097e43ce7dcb90af441c1d53abe8c03f
SPACETIME_TOKEN=<token>
DEMO_MODE=false
```

## Verified live (2026-11-08, local server, SpacetimeDB 2.14.1, Phase A)

- `npm run typecheck` passes; `spacetime build` succeeds.
- Published as database `nemo-proxy` (identity
  `c200645bcd25d414949c4a97fc7f7eca097e43ce7dcb90af441c1d53abe8c03f` —
  unchanged from v1), `BACKEND_IDENTITY` set to the CLI identity
  `c2001c1a0c14c3bf76c3b67ae4bb848f551900eba2fb7bf4b3b71e12b9151905`
  (confirmed with `spacetime env list`).
- `init` seeds `sess_demo_carrier_01` (active). A final republish with
  `-c=always` at the end of Phase A left the database pristine: only
  the seed session, no incidents.
- Live reducer calls via the CLI, read back with SQL:
  - `create_incident` → `message_event inc_test_01` + `investigation_status` (investigating / low / version 0)
  - `record_evidence` → `ev_test_01`, `get_domain_context`, `is_simulated=false`
  - `update_investigation_progress` → phase investigating / high / version 1
  - `publish_assessment` with `expected_version=1` → assessed / high / version 2; a repeat with stale `expected_version=1` was **rejected** (HTTP 530, row unchanged at version 2)
  - `propose_action` twice with key `key_dup_01` → **one** action row (`proposed`); `approve_action` twice with the same key → **one** receipt (`receipt_approved_act_test_01`); approve with a wrong key was rejected
  - `inject_compromise` twice with key `key_comp_01` → session `compromised_sim`, **one** receipt row (`synthetic_compromise_sim_…`)
  - `revoke_session` twice with key `key_revoke_01` → session `revoked` with `revoked_at` set, **one** receipt row, in a single call (atomic)
  - `reset_demo_run` → all incidents/evidence/actions cleared, demo session back to `active`
- Identity checks: an anonymous CLI call to `create_incident` was rejected (530); an anonymous HTTP call was rejected (530); an HTTP call with the CLI identity's Bearer token succeeded (200) for both `ping` and the guarded `create_incident`; HTTP SQL with that token can read the private `session` table (the backend's read-back path).
- Views via SQL: `customer_session_view` as the owner identity returned only the session owned by that identity; `operator_session_view` as the backend identity returned all sessions; both returned empty anonymously. Neither view returns `credential_hash`.
- Backend (one Python reducer call through the fixed client, confirmed in SpacetimeDB): backend run with `DEMO_MODE=false` against the local server, `POST /api/ingest` (phishing) → `/api/state` source `spacetimedb_live`, incident assessed / `suspected_phishing` / high, 7 evidence rows and 2 proposed actions in the live tables, version 2 (create → progress → publish). `POST /api/session/compromise` → `compromised_sim` + inject receipt; `POST /api/session/revoke` → `revoked` + revoke receipt, both confirmed with `spacetime sql`. No `credential_hash` in `/api/state`. Demo-mode run (`DEMO_MODE=true`): source `in_memory_demo`, ambiguous → `insufficient_evidence` / medium, mirror `raw_json` preserved.
- Frontend: bindings regenerated with `spacetime generate` (new tables, reducers and both views; the private `session` table is absent from the bindings), `npm run build` passes, built app serves 200 on `localhost:5173`.
- Two things the pasted Step 1 got wrong, fixed while building (v1):
  - `@spacetimedb/spacetimedb` does not exist on npm (404); the real
    package is `spacetimedb` (^2.14.1), importing `spacetimedb/server`.
  - The decorator API (`@spacetimedb.table()`, `@spacetimedb.reducer()`)
    is not the current 2.x TypeScript module API; this module uses
    `schema()` + `table()` + `t.*` with reducers registered by name.
  - `tsconfig.json`: `moduleResolution: "node"` cannot resolve the
    `spacetimedb/server` subpath; this module uses `module: esnext` +
    `moduleResolution: "bundler"` (typecheck only — the CLI builds it).
  - The schema object must not be a named export as well as the default
    export, or the build fails with "exporting something that is not a
    spacetime export".

## Verified live — Phase B (2026-11-08, spec §6, same local server)

The module was republished with `-c=always -y` (same identity
`c200645b…`; note: the publish hangs on the break-clients/delete-data
confirmation prompt without `-y` — pass `-y` for non-interactive
publishes). New reducer `rotate_session_credential`, approval-bound
`revoke_session`, and hash-preserving `reset_demo_run` — all verified
via the CLI with SQL read-back before the backend was wired to them:

- Direct `revoke_session` with no proposal → rejected (HTTP 530).
- `propose_action` → `approve_action` → `revoke_session` with the same
  key → session `revoked`, one receipt row (`approved` / `executed`).
  A replay with the same key → no-op (still one row).
- `rotate_session_credential` on a revoked session → rejected (530);
  after `reset_demo_run` (session `active`, hash preserved) it succeeds
  and stores the new hash.
- Backend end-to-end (see `BACKEND_CONTRACT.md` "Session credentials &
  protected resource" and `backend/README.md`): six-step flow through
  the real backend with cookie credential — protected 200 before
  revocation, 401 after with the same credential; expired and wrong
  credentials denied; SpacetimeDB-unreachable → 503 deny; same-key
  repeat revocation → one receipt; demo-mode run still works with the
  labelled in-memory mirror.

## What is NOT verified yet

- The live SpacetimeDB subscription has not been verified end-to-end in
  a browser against the live server (no live browser was available in
  this session): the frontend subscribes to `message_event` /
  `investigation_status` / `evidence` / `customer_session_view`, with
  BroadcastChannel only as a labelled fallback, but the subscription
  path (including view subscriptions) was verified only by build + the
  CLI/SQL checks above, not by a browser session.
- No live Nemotron call has been made (no real NVIDIA key exists); the
  live-mode backend test above ran the labelled simulated tool loop.

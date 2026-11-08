# NemoProxy — backend contract (what the frontend expects)

Verified against the rewritten backend in `backend/` and the spec §5
SpacetimeDB module in `spacetimedb/src/index.ts`, tested live in mock
mode and in live mode against a local SpacetimeDB 2.14.1 server on
2026-11-08 (Phase A). The frontend in `frontend/` matches this contract.

## Live endpoints (FastAPI, default :8000)
- `GET /api/health` → `{ status: "healthy", demo_mode, credentials_status, model_id }`
- `GET /api/scenarios` → `[{ key, id, name, raw_message, target_domain }]`,
  keys: `phishing` | `legitimate` | `ambiguous` | `injection` (Phase C)
- `POST /api/ingest` `{ scenario }` → `{ incident_id, status: "queued" }`
  (a browser-supplied `user_id` is ignored for ownership)
- `GET /api/state` → `{ incidents, evidence_items, proposed_actions, sandbox_sessions, source }`
  - `source`: `"spacetimedb_live"` | `"in_memory_demo"` | `"in_memory_fallback"`
  - incident (message_event JOIN investigation_status):
    `{ incident_id, scenario_id, status: "investigating"|"assessed"|"failed"|"incomplete",
       verdict: "suspected_phishing"|"benign_indicator"|"insufficient_evidence"|"pending",
       confidence_band: "low"|"medium"|"high", summary, redacted_message,
       unknowns, assessment,
       investigation_started_at_ms, investigation_finished_at_ms,
       investigation_duration_ms }`
    Timings (spec §10): `investigation_duration_ms` is the server-side
    pipeline wall time (redaction + Nemotron tool loop + commit), in ms;
    null until the final assessment is published. The frontend measures
    DB-to-client latency itself as the time from
    `investigation_finished_at_ms` to the result first appearing in the
    browser, and shows both numbers in the operator view only.
    `incomplete` (Phase C) = budget exhausted or model output that failed
    structured validation after one retry: partial evidence is kept, no
    verdict is produced, and no simulated verdict is substituted.
    `assessment` (Phase C) = the validated structured assessment — see
    "Structured assessment (Phase C)" below. In demo mode it is the full
    object; on a live read-back it is `null` (the §5 schema has no
    assessment column) and the key facts stay in the human-readable
    summary.
    Frontend maps `benign_indicator` → `legitimate_looking`; a `pending`
    verdict (assessed row with no recorded verdict) is treated as not ready.
    An `incomplete` incident is terminal and is shown as an incomplete
    result with its partial evidence, never as a verdict.
  - evidence item: `{ evidence_id, incident_id, source_tool, is_simulated,
    summary, raw_json }` — on a live read-back `raw_json` is `""`
    (the §5 `evidence` table has no `raw_json` column; the full payload
    lives in the backend's in-memory mirror only)
  - proposed action: `{ action_id, incident_id, action_type, reason, status,
    execution_state, idempotency_key, receipt }`
    where `status` is the `approval_state` (`proposed` / `approved` /
    `rejected`); on a live read-back `reason` is `""` (the §5
    `response_action` table has no `reason` column — the revoke reason is
    in the receipt). Note the v1 `status: "accepted"` is now `"approved"`.
    Phase B added `execution_state`, `idempotency_key` and `receipt` so
    the UI can show the committed receipt from SpacetimeDB.
  - session: `{ session_id, account_id, device_label, phone_masked,
    status: "active"|"compromised_sim"|"revoked"|"expired",
    sim_freeze_enabled, revocation_reason, updated_at }` — never contains
    `credential_hash`. Device label / phone are demo-UI labels held in
    the backend, not SpacetimeDB columns.
- `POST /api/session/compromise` → `{ session: { session_id, status: "compromised_sim", ... } }`
- `POST /api/session/revoke` `{ session_id, reason, idempotency_key? }` →
  `{ session: { session_id, status: "revoked", ... }, action_id, idempotency_key, receipt, source }`
  (Phase B: migrated to the approved flow — see below. Same caller shape
  as before, plus the receipt fields. A repeat with the same
  `idempotency_key` is a no-op: one receipt, state unchanged.)
- `POST /api/session/protect` `{ session_id, reason?, idempotency_key?, incident_id? }` →
  the customer "Protect demo account" action: the same approved revocation
  flow as `/api/session/revoke`, returning `{ session, action_id,
  idempotency_key, receipt, source }`.
- `POST /api/session/issue` → issues a fresh demo session credential and
  sets it as the HttpOnly `nemo_session` cookie (see "Session credentials"
  below). Returns `{ session_id, credential_issued: true, expires_at_ms,
  expires_in_seconds: 1800 }` — the raw credential is NOT in the body.
  503 when the session is revoked (reset first) or the session store is
  unreachable.
- `POST /api/session/reset` → resets the demo run in SpacetimeDB, flips
  the demo session back to active, invalidates the old credential, and
  issues a fresh one (new `nemo_session` cookie). Returns `{ session,
  credential_issued: true, expires_at_ms, expires_in_seconds }`.
- `GET /api/account/overview` → fictional sandbox account overview
  (`account_id`, masked phone, plan name, fictional balance/usage — all
  synthetic, labelled as such). Requires the session credential (cookie
  or `Authorization: Bearer`). 401 for missing/wrong/expired/revoked,
  503 when SpacetimeDB cannot be reached (fail-closed, never allowed
  through).
- `POST /api/session/toggle_sim_freeze` was **removed** in Phase A: the
  §5 `session` table has no SIM-freeze column (nothing in the frontend
  called it).

## Structured assessment (Phase C, spec §4)

The Nemotron verdict is NEVER extracted by substring matching on free
text. The model must return a single JSON object validated against
`StructuredAssessment` (`backend/nvidia_client.py`):

```jsonc
{
  "concern_level": "low" | "suspicious" | "high" | "inconclusive",
  "explanation": "plain-English explanation",
  "evidence_ids": ["ev_..."],          // must exist for this incident
  "missing_evidence": ["..."],         // unknowns that would change the call
  "conflicts_resolved": [{             // message vs domain vs reputation
    "claim": "...", "domain_evidence": "...",
    "reputation_evidence": "...", "resolution": "..." }],
  "recommended_next_step": "...",
  "proposed_action": "propose_session_revocation" | "propose_sim_freeze"
                   | "propose_subscriber_alert" | null,
  "recovery_step_ids": ["step_..."],   // from the reviewed catalog below
  "injection_attempt_detected": false,
  "injection_details": ""
}
```

- No 0–100 probability, no "honest confidence" number anywhere;
  concern is a band. `concern_level` maps to the backend verdict:
  `low` → `benign_indicator`/`high`, `suspicious`/`high` →
  `suspected_phishing`/`high`, `inconclusive` →
  `insufficient_evidence`/`medium`. The ambiguous scenario returns
  `inconclusive` with named unknowns rather than guessing.
- Validation: schema (Pydantic) + every `evidence_ids` entry must be an
  evidence ID recorded for the incident + recovery IDs must be in the
  catalog. Invalid output gets ONE correction retry, then the incident
  is `incomplete` — never a substring guess, never a simulated verdict.
- The validated assessment is wired into `publish_assessment` with the
  correct `expected_version` (`spacetime_client.spacetime_update_incident`
  `assessment=`), and served in `/api/state` incidents as `assessment`
  (demo mode; live read-back `null`, see above). The frontend shows it
  in the operator view (concern, cross-checks, missing evidence,
  injection flag, recovery checklist) and the customer view (plain
  language + recovery checklist + next step).
- Multi-hop / ordering is enforced in the Python dispatcher, not just
  the prompt: `propose_response_action` / `select_recovery_steps` are
  refused until evidence exists, and a final assessment is only
  accepted after `get_incident_evidence` has grounded it (the live loop
  auto-grounds once and asks for a revision; a second ungrounded answer
  is `incomplete`).
- Recovery catalog (`backend/nvidia_client.py`
  `RECOVERY_CHECKLIST_CATALOG`): review carrier account protections,
  change the account password, enable account PIN/passcode, review
  recent account activity, report the message. Selected per scenario by
  exposure (phishing/injection: all five; legitimate: recent activity +
  carrier protections; ambiguous: recent activity + report + carrier
  protections). No "SIM-porting locked" claim is made anywhere.
- Prompt-injection resistance: SMS text and tool-returned text are
  untrusted data. The dispatcher validates every tool name (allow-list),
  every argument (incident ownership, `action_type` enum, catalog step
  IDs, URL allow-list — the URL host must be exactly the incident's
  fixture domain; `check_url_reputation` itself only ever queries the
  configured Google Web Risk provider, it never fetches the URL), and
  rejects unauthorized operations with an `injection_guard` activity
  entry. The model may propose revocation but cannot approve it (no
  approve/revoke tool exists). The adversarial `injection` scenario
  (message tries to force approval, revocation, credential reveal, and
  an attacker-URL call) is refused and flagged; the simulated loop
  proposes NO action for it, the `response_action` table stays empty
  for that incident, and the session stays active.
- Budgets: max rounds (default 4), max total tool calls (default 12),
  wall-clock timeout (default 120 s) — env-overridable
  (`INVESTIGATION_MAX_ROUNDS` / `INVESTIGATION_MAX_TOOL_CALLS` /
  `INVESTIGATION_TIMEOUT_SECONDS`, see `backend/config.py`). Forcing
  exhaustion in a test: run a second backend with
  `INVESTIGATION_MAX_TOOL_CALLS=2` and ingest `phishing` — the incident
  comes back `incomplete` with partial evidence kept. A failed or
  exhausted live call is `incomplete`/`failed`, never a simulated verdict.
- Activity log: tool calls, validation retries, injection flags and
  budget exhaustion are recorded as evidence items (`source_tool`
  `assessment_validation` / `injection_guard` / `budget`) and shown in
  the operator view's activity log. No private model reasoning is logged.

## Session credentials & protected resource (Phase B, spec §6)

- Credential: random opaque token (`secrets.token_urlsafe(32)`), 30-minute
  expiry. Only its SHA-256 hash is stored — in SpacetimeDB
  (`session.credential_hash`, via the `rotate_session_credential` reducer)
  in live mode, and in a server-memory-only dict in demo mode (never in
  the in-memory `_STATE` mirror, so it can never leak through
  `/api/state`). The raw credential is handed out exactly once, in the
  HttpOnly `nemo_session` cookie (`Path=/api/account`, `SameSite=Lax`,
  `Secure=False` on local http only). It never appears in a JSON body,
  `/api/state`, server logs, or the frontend bundle (the frontend never
  reads it — the browser sends the cookie).
- Verification (`GET /api/account/overview`): the backend hashes the
  presented credential and compares it server-side against the stored
  hash, checks expiry, and checks the authoritative session state from
  SpacetimeDB (live mode) — never a React boolean, never the Python
  mirror. Usable states: `active` and `compromised_sim` (a compromised
  session is still usable until revoked — that is the point of the demo).
  Unverifiable (SpacetimeDB read fails) → 503 deny, never fail open.
  Demo mode verifies against the mirror + server-side hash dict and
  labels the result `in_memory_demo`.
- Approved revocation: every revocation runs propose_action (type
  `revoke_session`) → approve_action → revoke_session with ONE
  idempotency key. The module's `revoke_session` reducer rejects a call
  with no approved proposal for the key, and `approve_action` requires
  the backend service identity — the Nemotron tool loop can propose an
  action (`propose_response_action`) but has no path to approve one, so
  the model cannot grant itself approval.
- Lifecycle: issue on `POST /api/session/issue` (also on mount in live
  mode from the frontend, and after every reset). Reset
  (`POST /api/session/reset`) clears incidents/evidence/actions in
  SpacetimeDB, reactivates the session, drops the old hash, and issues a
  fresh credential — the old credential stops working immediately.
  Issuing a credential for a revoked session is refused (reset first);
  `rotate_session_credential` also throws on a revoked session.
- Recovery labelling: this enforces against a fictional sandbox session,
  NOT a real carrier's session. No "SIM-porting locked" claim is made
  anywhere; the customer view after revocation shows the informational
  step "Review your carrier account protections".

The backend keeps its own synthetic fixture per scenario key and redacts it
server-side; the frontend sends ONLY the scenario key, never a message or an
expected label. If the backend is unreachable, the frontend reports the
failure and offers the labelled mock — it never presents a mock result as live.

## SpacetimeDB module (spec §5)
The real module lives at `spacetimedb/src/index.ts` (tables
`message_event`, `investigation_status`, `evidence`, `session`
(private), `response_action`; identity-scoped views
`customer_session_view` / `operator_session_view`; reducers
`create_incident`, `record_evidence`, `update_investigation_progress`,
`publish_assessment`, `create_session`, `propose_action`,
`approve_action`, `revoke_session`, `inject_compromise`,
`reset_demo_run`, `ping`). Phase B (spec §6, 2026-11-08) added
`rotate_session_credential` (issue a credential hash + expiry) and made
`revoke_session` approval-bound (it throws without an approved
`revoke_session`-typed proposal for the same idempotency key) and
`reset_demo_run` hash-preserving. Republished with `-c=always -y`
(same database identity); the publish hangs on its confirmation prompt
without `-y`. The module was published live 2026-11-08 as database
`nemo-proxy` (identity
`c200645bcd25d414949c4a97fc7f7eca097e43ce7dcb90af441c1d53abe8c03f`)
on a local SpacetimeDB 2.14.1 server and every reducer was called via
the CLI and read back with SQL — see `spacetimedb/README.md`
("Verified live"). `frontend/src/spacetimedb/` mirrors those tables
(`schema.ts`) and holds the generated client bindings (`index.ts` plus
`*_table.ts` / `*_reducer.ts`); the private `session` table does not
appear in the bindings at all. The frontend subscribes to the public
§5 tables plus `customer_session_view` when `VITE_SPACETIMEDB_HOST` is
set, with BroadcastChannel only as a labelled fallback; session state
comes via `/api/state`, never via subscription. The backend's
`spacetime_client.py` keeps an in-memory store mirroring the §5 schema
and only calls live SpacetimeDB reducers when credentials are
configured and `DEMO_MODE=false`; in mock mode it is in-memory only.
Reducer calls use `POST /v1/database/<database-identity>/call/<name>`
(the old `POST /api/{db}/reducer/<name>` path returns 404 on a 2.x
server). Every reducer except `ping` requires the backend service
identity (`BACKEND_IDENTITY` module env var — fail-closed when unset);
the backend presents it via its `SPACETIME_TOKEN`.

## Notes / known mapping gaps (§5 vs the old external shape)
- The §5 `investigation_status` table has no verdict column: the backend
  writes the verdict as a `verdict=<v>` first line of `explanation` and
  strips it on read-back. The frontend's direct-subscription path parses
  the same prefix (`frontend/src/lib/sync.ts` `parseAssessment`).
- `publish_assessment` is version-gated (`expected_version`); the backend
  retries once with a freshly read version after a stale write.
- `propose_action` / `approve_action` / `revoke_session` /
  `inject_compromise` are idempotent by key; `revoke_session` flips the
  session and writes its receipt atomically in one reducer.
- A live `/api/state` read joins `message_event` +
  `investigation_status`; `evidence_items` come from `evidence`
  (`type` → `source_tool`, `result` → `summary`).

// NemoProxy SpacetimeDB module (TypeScript, SpacetimeDB 2.x) — spec §5 data model.
//
// Tables (spec §5) — investigation state, session state and action
// execution state are kept separate on purpose:
//   message_event        one row per investigated message (the "what arrived")
//   investigation_status one row per incident: phase / concern / version
//   evidence             tool results attached to an incident
//   session              carrier sessions — PRIVATE, holds credential_hash
//   response_action      proposed / approved / executed actions + receipts
//
// This module does NOT use the older decorator API (@spacetimedb.table(),
// @spacetimedb.reducer(), @spacetimedb/spacetimedb package). That package
// does not exist on npm and that API is not the current SpacetimeDB 2.x
// TypeScript module API. The current API is `spacetimedb/server` from the
// `spacetimedb` package (v2.14.1 here): schema() + table() + t.*,
// reducers registered with an explicit string name.
//
// BREAKING CHANGE (2026-11-08, Phase A): this replaces the v1 schema
// (incident / evidence_item / proposed_action / sandbox_session). Publish
// with `-c=always` — only synthetic test rows exist, data loss is fine.
// See README.md for the old→new mapping.
//
// Access control (verified against spacetimedb 2.14.1, see README.md):
// - `session` is private (`public: false`): no client can subscribe to it
//   and its `credential_hash` column is never exposed to a subscription.
//   Session state reaches the UI only through the backend's /api/state,
//   which reads the table server-side and never includes credential_hash.
// - Identity-scoped views expose a credential-free projection of a
//   session: `customer_session_view` (rows whose owner_id is the caller's
//   SpacetimeDB identity) and `operator_session_view` (all rows, but only
//   when the caller is the backend service identity). The demo seed's
//   owner_id is a fictional account id, not an identity, so both views
//   return empty for it — the frontend keeps using /api/state for session
//   state. A `clientVisibilityFilter` RLS rule was NOT used: the session
//   table is private so there is nothing to filter, and RLS is being
//   deprecated in favour of views in 2.x.
// - Writes: every reducer except `ping` requires the caller to be the
//   backend service identity. The identity is configured with the module
//   env var BACKEND_IDENTITY (declared below, set at publish time from a
//   shell variable, e.g. `BACKEND_IDENTITY=<hex> spacetime publish ...`).
//   Enforcement is fail-closed: if BACKEND_IDENTITY is unset, ALL guarded
//   reducers throw. `ctx.sender` is the identity the caller authenticated
//   as — verified live: a CLI call presents the CLI identity, an HTTP
//   call presents the identity of its Bearer token, and an anonymous
//   HTTP call presents a fresh random identity (see README.md).
//
// Idempotency / versions:
// - `propose_action`, `approve_action`, `revoke_session` and
//   `inject_compromise` take an idempotency key. A repeat delivery with
//   the same key is a no-op that leaves the already-stored receipt in
//   place; no duplicate action row and no duplicate effect. (Enforced in
//   code via the unique `idempotency_key` index + a pre-check, so a
//   redelivery succeeds instead of throwing a unique violation.)
// - `revoke_session` additionally requires an APPROVED proposal: the
//   same idempotency key must first have been proposed with
//   `propose_action` (type `revoke_session`) and approved with
//   `approve_action` (backend identity only). A direct revoke with no
//   approved proposal throws (Phase B, spec §6).
// - `rotate_session_credential` issues a new credential hash + expiry
//   for a session (Phase B); it throws on a revoked session.
// - `publish_assessment` takes `expected_version` and throws when it does
//   not match `investigation_status.version` (stale-write rejection).
// - A reducer is a single transaction: `revoke_session` flips the session
//   row and writes its `response_action` receipt row atomically.
//
// Deploy (on a machine with the SpacetimeDB CLI):
//   curl -sSf https://install.spacetimedb.com | sh
//   cd spacetimedb
//   BACKEND_IDENTITY=<backend-service-identity-hex> spacetime publish -s local -c=always nemo-proxy
// Then point the backend at it with SPACETIME_HOST / SPACETIME_DB /
// SPACETIME_DB_IDENTITY / SPACETIME_TOKEN. Live publish + live reducer
// calls were tested here on 2026-11-08 against a local SpacetimeDB
// 2.14.1 server — see README.md "Verified live".

import { schema, table, t } from 'spacetimedb/server';

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

const message_event = table(
  { name: 'message_event', public: true },
  {
    incident_id: t.string().primaryKey(),
    owner_id: t.string(),
    sanitized_message: t.string(),
    scenario_id: t.string(),
    created_at: t.timestamp(),
  },
);

const investigation_status = table(
  { name: 'investigation_status', public: true },
  {
    incident_id: t.string().primaryKey(),
    phase: t.string(), // queued, investigating, assessed, failed
    concern_level: t.string(), // low, medium, high
    explanation: t.string(),
    unknowns: t.string(),
    version: t.u64(),
    updated_at: t.timestamp(),
  },
);

const evidence = table(
  { name: 'evidence', public: true },
  {
    evidence_id: t.string().primaryKey(),
    incident_id: t.string().index(),
    type: t.string(), // tool that produced this evidence, e.g. get_domain_context
    result: t.string(), // human-readable result summary
    source: t.string(), // provenance, e.g. backend_tool_loop
    is_simulated: t.bool(),
    observed_at: t.timestamp(),
  },
);

// PRIVATE: never subscribable by clients. Holds credential_hash — that
// column must never appear in a view return type or a subscription.
// `expiry` / `revoked_at` are milliseconds since the Unix epoch (u64);
// revoked_at == 0 means "not revoked".
const session = table(
  { name: 'session', public: false },
  {
    session_id: t.string().primaryKey(),
    owner_id: t.string().index(),
    credential_hash: t.string(),
    state: t.string(), // active, compromised_sim, revoked, expired
    expiry: t.u64(),
    revoked_at: t.u64(),
  },
);

const response_action = table(
  { name: 'response_action', public: true },
  {
    action_id: t.string().primaryKey(),
    incident_id: t.string().index(),
    session_id: t.string(),
    type: t.string(), // e.g. propose_session_revocation, revoke_session, inject_compromise
    approval_state: t.string(), // proposed, approved, rejected
    execution_state: t.string(), // pending, executed, failed
    idempotency_key: t.string().unique(),
    receipt: t.string(),
  },
);

// Declared module env (set at publish time; see header). Optional at the
// type level so the module builds without it, but the reducers below
// fail closed when it is unset.
const spacetimedb = schema(
  {
    message_event,
    investigation_status,
    evidence,
    session,
    response_action,
  },
  { env: { BACKEND_IDENTITY: t.option(t.string()) } },
);

// ---------------------------------------------------------------------------
// Identity-scoped views (credential-free projections of `session`)
// ---------------------------------------------------------------------------

// Row shape returned by the session views. Deliberately NOT the session
// row: no credential_hash, ever.
const session_view_row = t.row('SessionView', {
  session_id: t.string().primaryKey(),
  owner_id: t.string(),
  state: t.string(),
  expiry: t.u64(),
  revoked_at: t.u64(),
});

function projectSession(row: {
  session_id: string;
  owner_id: string;
  state: string;
  expiry: bigint;
  revoked_at: bigint;
}): {
  session_id: string;
  owner_id: string;
  state: string;
  expiry: bigint;
  revoked_at: bigint;
} {
  return {
    session_id: row.session_id,
    owner_id: row.owner_id,
    state: row.state,
    expiry: row.expiry,
    revoked_at: row.revoked_at,
  };
}

// A customer sees only sessions whose owner_id is their own SpacetimeDB
// identity. Index probe on owner_id — no table scan.
export const customer_session_view = spacetimedb.view(
  { name: 'customer_session_view', public: true },
  t.array(session_view_row),
  (ctx) => {
    const senderHex = ctx.sender.toHexString();
    const out = [];
    for (const row of ctx.db.session.owner_id.filter(senderHex)) {
      out.push(projectSession(row));
    }
    return out;
  },
);

// An authorized operator (the backend service identity) sees every
// session, still without credential_hash. Any other caller gets [].
export const operator_session_view = spacetimedb.view(
  { name: 'operator_session_view', public: true },
  t.array(session_view_row),
  (ctx) => {
    const backendIdentity = ctx.env.BACKEND_IDENTITY;
    if (
      backendIdentity === undefined ||
      backendIdentity === null ||
      backendIdentity === '' ||
      ctx.sender.toHexString() !== backendIdentity
    ) {
      return [];
    }
    const out = [];
    for (const row of ctx.db.session.iter()) {
      out.push(projectSession(row));
    }
    return out;
  },
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Only the backend service identity may write investigation evidence and
// assessments (spec §5). Fail closed when BACKEND_IDENTITY is unset.
// The error names the actual sender hex so a misconfigured deployment can
// be diagnosed from the failed call alone.
function requireBackendSender(
  senderHex: string,
  backendIdentity: string | undefined | null,
): void {
  if (
    backendIdentity === undefined ||
    backendIdentity === null ||
    backendIdentity === ''
  ) {
    throw new Error(
      'BACKEND_IDENTITY env is not configured; backend-only writes are disabled',
    );
  }
  if (senderHex !== backendIdentity) {
    throw new Error(
      `forbidden: sender ${senderHex} is not the backend service identity`,
    );
  }
}

function requireBackend(
  ctx: { sender: { toHexString(): string }; env: { BACKEND_IDENTITY?: string | null } },
): void {
  requireBackendSender(ctx.sender.toHexString(), ctx.env.BACKEND_IDENTITY);
}

// Milliseconds since epoch for "now" (u64 columns can't use ctx.timestamp).
function nowMs(ctx: { timestamp: { microsSinceUnixEpoch: bigint } }): bigint {
  return ctx.timestamp.microsSinceUnixEpoch / 1000n;
}

function findActionByKey(
  ctx: { db: { response_action: { idempotency_key: { find(id: string): unknown } } } },
  idempotency_key: string,
): {
  action_id: string;
  incident_id: string;
  session_id: string;
  type: string;
  approval_state: string;
  execution_state: string;
  idempotency_key: string;
  receipt: string;
} | null {
  const row = ctx.db.response_action.idempotency_key.find(idempotency_key) as
    | {
        action_id: string;
        incident_id: string;
        session_id: string;
        type: string;
        approval_state: string;
        execution_state: string;
        idempotency_key: string;
        receipt: string;
      }
    | undefined;
  return row ?? null;
}

// Runs once, when the module is first published. Seeds the same demo
// sandbox session the backend's in-memory store uses in demo mode.
// The credential_hash is a placeholder for a synthetic demo session —
// it is not a hash of any real credential, and the table is private so
// no client can read it. owner_id is the fictional subscriber account,
// not a SpacetimeDB identity, so the identity-scoped views return empty
// for this seed (see header); session state for the demo flows through
// the backend's /api/state instead.
export const init = spacetimedb.init((ctx) => {
  ctx.db.session.insert({
    session_id: 'sess_demo_carrier_01',
    owner_id: 'acct_tm_94821',
    credential_hash: 'demo_hash_placeholder__not_a_real_credential',
    state: 'active',
    expiry: nowMs(ctx) + 365n * 24n * 60n * 60n * 1000n,
    revoked_at: 0n,
  });
});

// ---------------------------------------------------------------------------
// Reducers
// ---------------------------------------------------------------------------

export const create_incident = spacetimedb.reducer(
  { name: 'create_incident' },
  {
    incident_id: t.string(),
    owner_id: t.string(),
    sanitized_message: t.string(),
    scenario_id: t.string(),
  },
  (ctx, { incident_id, owner_id, sanitized_message, scenario_id }) => {
    requireBackend(ctx);
    ctx.db.message_event.insert({
      incident_id,
      owner_id,
      sanitized_message,
      scenario_id,
      created_at: ctx.timestamp,
    });
    ctx.db.investigation_status.insert({
      incident_id,
      phase: 'investigating',
      concern_level: 'low',
      explanation: 'Investigation queued. Nemotron tool loop starting.',
      unknowns: '',
      version: 0n,
      updated_at: ctx.timestamp,
    });
  },
);

export const record_evidence = spacetimedb.reducer(
  { name: 'record_evidence' },
  {
    evidence_id: t.string(),
    incident_id: t.string(),
    type: t.string(),
    result: t.string(),
    source: t.string(),
    is_simulated: t.bool(),
  },
  (ctx, { evidence_id, incident_id, type, result, source, is_simulated }) => {
    requireBackend(ctx);
    const event = ctx.db.message_event.incident_id.find(incident_id);
    if (!event) {
      throw new Error(`unknown incident ${incident_id}`);
    }
    ctx.db.evidence.insert({
      evidence_id,
      incident_id,
      type,
      result,
      source,
      is_simulated,
      observed_at: ctx.timestamp,
    });
  },
);

export const update_investigation_progress = spacetimedb.reducer(
  { name: 'update_investigation_progress' },
  {
    incident_id: t.string(),
    phase: t.string(),
    concern_level: t.string(),
    explanation: t.string(),
    unknowns: t.string(),
  },
  (ctx, { incident_id, phase, concern_level, explanation, unknowns }) => {
    requireBackend(ctx);
    const row = ctx.db.investigation_status.incident_id.find(incident_id);
    if (!row) {
      throw new Error(`unknown incident ${incident_id}`);
    }
    ctx.db.investigation_status.incident_id.update({
      ...row,
      phase,
      concern_level,
      explanation,
      unknowns,
      version: row.version + 1n,
      updated_at: ctx.timestamp,
    });
  },
);

export const publish_assessment = spacetimedb.reducer(
  { name: 'publish_assessment' },
  {
    incident_id: t.string(),
    expected_version: t.u64(),
    phase: t.string(),
    concern_level: t.string(),
    explanation: t.string(),
    unknowns: t.string(),
  },
  (
    ctx,
    { incident_id, expected_version, phase, concern_level, explanation, unknowns },
  ) => {
    requireBackend(ctx);
    const row = ctx.db.investigation_status.incident_id.find(incident_id);
    if (!row) {
      throw new Error(`unknown incident ${incident_id}`);
    }
    if (row.version !== expected_version) {
      throw new Error(
        `stale assessment for ${incident_id}: expected version ${expected_version.toString()}, current version is ${row.version.toString()}`,
      );
    }
    ctx.db.investigation_status.incident_id.update({
      ...row,
      phase,
      concern_level,
      explanation,
      unknowns,
      version: row.version + 1n,
      updated_at: ctx.timestamp,
    });
  },
);

export const create_session = spacetimedb.reducer(
  { name: 'create_session' },
  {
    session_id: t.string(),
    owner_id: t.string(),
    credential_hash: t.string(),
    expiry: t.u64(),
  },
  (ctx, { session_id, owner_id, credential_hash, expiry }) => {
    requireBackend(ctx);
    ctx.db.session.insert({
      session_id,
      owner_id,
      credential_hash,
      state: 'active',
      expiry,
      revoked_at: 0n,
    });
  },
);

export const propose_action = spacetimedb.reducer(
  { name: 'propose_action' },
  {
    action_id: t.string(),
    incident_id: t.string(),
    session_id: t.string(),
    type: t.string(),
    idempotency_key: t.string(),
  },
  (ctx, { action_id, incident_id, session_id, type, idempotency_key }) => {
    requireBackend(ctx);
    // Duplicate delivery with the same idempotency key: no-op, no
    // duplicate action row.
    if (findActionByKey(ctx, idempotency_key)) {
      return;
    }
    ctx.db.response_action.insert({
      action_id,
      incident_id,
      session_id,
      type,
      approval_state: 'proposed',
      execution_state: 'pending',
      idempotency_key,
      receipt: '',
    });
  },
);

export const approve_action = spacetimedb.reducer(
  { name: 'approve_action' },
  {
    action_id: t.string(),
    idempotency_key: t.string(),
  },
  (ctx, { action_id, idempotency_key }) => {
    requireBackend(ctx);
    const row = ctx.db.response_action.action_id.find(action_id);
    if (!row) {
      throw new Error(`unknown action ${action_id}`);
    }
    if (row.idempotency_key !== idempotency_key) {
      throw new Error(
        `idempotency key mismatch for action ${action_id}`,
      );
    }
    // Repeat approval with the same key: the receipt is already stored;
    // no duplicate effect.
    if (row.approval_state === 'approved') {
      return;
    }
    ctx.db.response_action.action_id.update({
      ...row,
      approval_state: 'approved',
      receipt: `receipt_approved_${action_id}`,
    });
  },
);

export const revoke_session = spacetimedb.reducer(
  { name: 'revoke_session' },
  {
    session_id: t.string(),
    reason: t.string(),
    idempotency_key: t.string(),
  },
  (ctx, { session_id, reason, idempotency_key }) => {
    requireBackend(ctx);
    // One reducer = one transaction: the session flip and the action
    // receipt row commit atomically.
    //
    // PHASE B (spec §6): revocation is approval-bound. The caller must
    // first create a `revoke_session`-typed proposal with
    // `propose_action` using this same idempotency key, and an operator
    // (the backend identity — `approve_action` is backend-only, so a
    // model tool call can never approve) must approve it with
    // `approve_action`. A direct `revoke_session` call with no approved
    // proposal for the key throws; the model may propose revocation but
    // cannot grant itself approval. A repeat delivery with the same key
    // after execution is a no-op: the stored receipt stays in place.
    const existing = findActionByKey(ctx, idempotency_key);
    if (!existing) {
      throw new Error(
        `revocation of session ${session_id} requires an approved proposal: no action found for idempotency key ${idempotency_key}`,
      );
    }
    if (existing.type !== 'revoke_session') {
      throw new Error(
        `idempotency key ${idempotency_key} already used for action type ${existing.type}`,
      );
    }
    if (existing.approval_state !== 'approved') {
      throw new Error(
        `revocation of session ${session_id} requires an approved proposal: action ${existing.action_id} is ${existing.approval_state}`,
      );
    }
    if (existing.execution_state === 'executed') {
      // Repeat delivery with the same key: receipt already stored.
      return;
    }
    const row = ctx.db.session.session_id.find(session_id);
    if (!row) {
      throw new Error(`unknown session ${session_id}`);
    }
    const receipt = `revoked session ${session_id} (key ${idempotency_key}): ${reason}`;
    if (row.state === 'revoked') {
      // Already revoked (e.g. by an earlier key): mark this approved
      // key executed and record its receipt without a duplicate state
      // change.
      ctx.db.response_action.action_id.update({
        ...existing,
        execution_state: 'executed',
        receipt,
      });
      return;
    }
    if (row.state === 'expired') {
      throw new Error(`session ${session_id} is expired`);
    }
    ctx.db.session.session_id.update({
      ...row,
      state: 'revoked',
      revoked_at: nowMs(ctx),
    });
    ctx.db.response_action.action_id.update({
      ...existing,
      execution_state: 'executed',
      receipt,
    });
  },
);

// Records a clearly labelled SYNTHETIC compromise event for a session
// (Phase B). This is a simulation marker, not a real breach: the session
// state becomes `compromised_sim` and a receipt row records the event.
export const inject_compromise = spacetimedb.reducer(
  { name: 'inject_compromise' },
  {
    session_id: t.string(),
    incident_id: t.string(),
    idempotency_key: t.string(),
  },
  (ctx, { session_id, incident_id, idempotency_key }) => {
    requireBackend(ctx);
    const existing = findActionByKey(ctx, idempotency_key);
    if (
      existing &&
      existing.type === 'inject_compromise' &&
      existing.execution_state === 'executed'
    ) {
      return;
    }
    if (existing && existing.type !== 'inject_compromise') {
      throw new Error(
        `idempotency key ${idempotency_key} already used for action type ${existing.type}`,
      );
    }
    const row = ctx.db.session.session_id.find(session_id);
    if (!row) {
      throw new Error(`unknown session ${session_id}`);
    }
    if (row.state === 'revoked' || row.state === 'expired') {
      throw new Error(`cannot inject compromise into ${row.state} session ${session_id}`);
    }
    const receipt = `synthetic_compromise_sim_${session_id}_${idempotency_key}`;
    if (row.state !== 'compromised_sim') {
      ctx.db.session.session_id.update({
        ...row,
        state: 'compromised_sim',
      });
    }
    if (!existing) {
      ctx.db.response_action.insert({
        action_id: `act_compromise_${idempotency_key}`,
        incident_id,
        session_id,
        type: 'inject_compromise',
        approval_state: 'approved',
        execution_state: 'executed',
        idempotency_key,
        receipt,
      });
    }
  },
);

// Issues (or re-issues) a session credential hash (Phase B, spec §6).
// The backend generates a random opaque credential, stores ONLY its
// SHA-256 hash here via this reducer, and hands the raw credential to
// the browser once, in an HttpOnly cookie — the raw value never enters
// SpacetimeDB, logs, or /api/state. `expiry` is u64 ms since epoch
// (30 minutes from issue in the backend). The session becomes `active`
// with `revoked_at` cleared: this reducer is issuance-only, called at
// startup / demo reset, never to resurrect a revoked session — it
// throws on a `revoked` session (reset the demo run first, which flips
// the session back to `active`). A missing session is created (fictional
// demo subscriber owner).
export const rotate_session_credential = spacetimedb.reducer(
  { name: 'rotate_session_credential' },
  {
    session_id: t.string(),
    credential_hash: t.string(),
    expiry: t.u64(),
  },
  (ctx, { session_id, credential_hash, expiry }) => {
    requireBackend(ctx);
    const row = ctx.db.session.session_id.find(session_id);
    if (!row) {
      ctx.db.session.insert({
        session_id,
        owner_id: 'acct_tm_94821',
        credential_hash,
        state: 'active',
        expiry,
        revoked_at: 0n,
      });
      return;
    }
    if (row.state === 'revoked') {
      throw new Error(
        `cannot issue a credential for revoked session ${session_id}; reset the demo run first`,
      );
    }
    ctx.db.session.session_id.update({
      ...row,
      credential_hash,
      expiry,
      state: 'active',
      revoked_at: 0n,
    });
  },
);

// Clears the demo run: all incidents, investigation rows, evidence and
// actions are deleted; the demo session is reset to active (re-seeded if
// missing). Only the backend service identity may call it.
// PHASE B: the reset preserves the session's credential_hash and expiry
// — it must not silently downgrade a real issued hash back to the
// placeholder. The backend issues a fresh credential (rotate) right
// after reset, so the old credential stops working.
export const reset_demo_run = spacetimedb.reducer(
  { name: 'reset_demo_run' },
  {},
  (ctx) => {
    requireBackend(ctx);
    for (const row of [...ctx.db.message_event.iter()]) {
      ctx.db.message_event.delete(row);
    }
    for (const row of [...ctx.db.investigation_status.iter()]) {
      ctx.db.investigation_status.delete(row);
    }
    for (const row of [...ctx.db.evidence.iter()]) {
      ctx.db.evidence.delete(row);
    }
    for (const row of [...ctx.db.response_action.iter()]) {
      ctx.db.response_action.delete(row);
    }
    const demo = ctx.db.session.session_id.find('sess_demo_carrier_01');
    if (demo) {
      // Preserve credential_hash and expiry (Phase B): the backend
      // rotates in a fresh credential right after reset.
      ctx.db.session.session_id.update({
        ...demo,
        state: 'active',
        revoked_at: 0n,
      });
    } else {
      ctx.db.session.insert({
        session_id: 'sess_demo_carrier_01',
        owner_id: 'acct_tm_94821',
        credential_hash: 'demo_hash_placeholder__not_a_real_credential',
        state: 'active',
        expiry: nowMs(ctx) + 365n * 24n * 60n * 60n * 1000n,
        revoked_at: 0n,
      });
    }
  },
);

// Connectivity check: callable, writes nothing, needs no auth.
export const ping = spacetimedb.reducer({ name: 'ping' }, {}, () => {
  // No-op by design — a successful call proves the module is reachable.
});

export default spacetimedb;

// NemoProxy SpacetimeDB module (TypeScript, SpacetimeDB 2.x).
//
// Tables + reducers the FastAPI backend calls. Reducer names are exact:
// backend/spacetime_client.py calls POST /api/{db}/reducer/<name> with
// create_incident, update_incident_verdict, add_evidence, propose_action.
//
// NOTE: this does NOT use the older decorator API (@spacetimedb.table(),
// @spacetimedb.reducer(), @spacetimedb/spacetimedb package). That package
// does not exist on npm and that API is not the current SpacetimeDB 2.x
// TypeScript module API. The current API is `spacetimedb/server` from the
// `spacetimedb` package (v2.14.1 here): schema({ ... }) + table() + t.*,
// reducers registered with an explicit string name.
//
// Deploy (on a machine with the SpacetimeDB CLI):
//   curl -sSf https://install.spacetimedb.com | sh
//   cd spacetimedb && spacetime publish nemo_proxy
// Then point the backend at it with SPACETIME_HOST / SPACETIME_DB /
// SPACETIME_TOKEN. Live publish + live reducer calls have NOT been tested
// here — the CLI is not installed in this workspace.

import { schema, table, t } from 'spacetimedb/server';

const incident = table(
  { name: 'incident', public: true },
  {
    incident_id: t.string().primaryKey(),
    scenario_id: t.string(),
    redacted_message: t.string(),
    status: t.string(), // queued, investigating, assessed, failed
    verdict: t.string(), // pending, suspected_phishing, insufficient_evidence, benign_indicator
    confidence_band: t.string(), // low, medium, high
    summary: t.string(),
    created_at: t.timestamp(),
  },
);

const evidence_item = table(
  { name: 'evidence_item', public: true },
  {
    evidence_id: t.string().primaryKey(),
    incident_id: t.string(),
    source_tool: t.string(),
    is_simulated: t.bool(),
    summary: t.string(),
    raw_json: t.string(),
  },
);

const proposed_action = table(
  { name: 'proposed_action', public: true },
  {
    action_id: t.string().primaryKey(),
    incident_id: t.string(),
    action_type: t.string(), // e.g. revoke_session, warn_user, none
    reason: t.string(),
    status: t.string(), // proposed, accepted, rejected
  },
);

const sandbox_session = table(
  { name: 'sandbox_session', public: true },
  {
    session_id: t.string().primaryKey(),
    account_id: t.string(),
    device_label: t.string(),
    phone_masked: t.string(),
    status: t.string(), // active, compromised_sim, revoked
    sim_freeze_enabled: t.bool(),
    revocation_reason: t.string(),
    updated_at: t.timestamp(),
  },
);

const spacetimedb = schema({
  incident,
  evidence_item,
  proposed_action,
  sandbox_session,
});

// Runs once, when the module is first published. Seeds the same demo
// sandbox session the backend's in-memory store uses in mock mode.
export const init = spacetimedb.init((ctx) => {
  ctx.db.sandbox_session.insert({
    session_id: 'sess_demo_carrier_01',
    account_id: 'acct_tm_94821',
    device_label: 'Samsung Galaxy S24 eSIM',
    phone_masked: '+1 (214) •••-4102',
    status: 'active',
    sim_freeze_enabled: false,
    revocation_reason: '',
    updated_at: ctx.timestamp,
  });
});

export const create_incident = spacetimedb.reducer(
  { name: 'create_incident' },
  {
    incident_id: t.string(),
    scenario_id: t.string(),
    redacted_message: t.string(),
  },
  (ctx, { incident_id, scenario_id, redacted_message }) => {
    ctx.db.incident.insert({
      incident_id,
      scenario_id,
      redacted_message,
      status: 'investigating',
      verdict: 'pending',
      confidence_band: 'low',
      summary: '',
      created_at: ctx.timestamp,
    });
  },
);

export const update_incident_verdict = spacetimedb.reducer(
  { name: 'update_incident_verdict' },
  {
    incident_id: t.string(),
    status: t.string(),
    verdict: t.string(),
    confidence_band: t.string(),
    summary: t.string(),
  },
  (ctx, { incident_id, status, verdict, confidence_band, summary }) => {
    const row = ctx.db.incident.incident_id.find(incident_id);
    if (!row) {
      throw new Error(`unknown incident ${incident_id}`);
    }
    ctx.db.incident.incident_id.update({
      ...row,
      status,
      verdict,
      confidence_band,
      summary,
    });
  },
);

export const add_evidence = spacetimedb.reducer(
  { name: 'add_evidence' },
  {
    evidence_id: t.string(),
    incident_id: t.string(),
    source_tool: t.string(),
    is_simulated: t.bool(),
    summary: t.string(),
    raw_json: t.string(),
  },
  (ctx, { evidence_id, incident_id, source_tool, is_simulated, summary, raw_json }) => {
    ctx.db.evidence_item.insert({
      evidence_id,
      incident_id,
      source_tool,
      is_simulated,
      summary,
      raw_json,
    });
  },
);

export const propose_action = spacetimedb.reducer(
  { name: 'propose_action' },
  {
    action_id: t.string(),
    incident_id: t.string(),
    action_type: t.string(),
    reason: t.string(),
  },
  (ctx, { action_id, incident_id, action_type, reason }) => {
    ctx.db.proposed_action.insert({
      action_id,
      incident_id,
      action_type,
      reason,
      status: 'proposed',
    });
  },
);

export const create_sandbox_session = spacetimedb.reducer(
  { name: 'create_sandbox_session' },
  {
    session_id: t.string(),
    account_id: t.string(),
    device_label: t.string(),
    phone_masked: t.string(),
  },
  (ctx, { session_id, account_id, device_label, phone_masked }) => {
    ctx.db.sandbox_session.insert({
      session_id,
      account_id,
      device_label,
      phone_masked,
      status: 'active',
      sim_freeze_enabled: false,
      revocation_reason: '',
      updated_at: ctx.timestamp,
    });
  },
);

export const trigger_compromise = spacetimedb.reducer(
  { name: 'trigger_compromise' },
  { session_id: t.string() },
  (ctx, { session_id }) => {
    const row = ctx.db.sandbox_session.session_id.find(session_id);
    if (!row) {
      throw new Error(`unknown session ${session_id}`);
    }
    ctx.db.sandbox_session.session_id.update({
      ...row,
      status: 'compromised_sim',
      updated_at: ctx.timestamp,
    });
  },
);

export const revoke_sandbox_session = spacetimedb.reducer(
  { name: 'revoke_sandbox_session' },
  {
    session_id: t.string(),
    reason: t.string(),
  },
  (ctx, { session_id, reason }) => {
    const row = ctx.db.sandbox_session.session_id.find(session_id);
    if (!row) {
      throw new Error(`unknown session ${session_id}`);
    }
    ctx.db.sandbox_session.session_id.update({
      ...row,
      status: 'revoked',
      revocation_reason: reason,
      updated_at: ctx.timestamp,
    });
  },
);

export const toggle_sim_freeze = spacetimedb.reducer(
  { name: 'toggle_sim_freeze' },
  { session_id: t.string() },
  (ctx, { session_id }) => {
    const row = ctx.db.sandbox_session.session_id.find(session_id);
    if (!row) {
      throw new Error(`unknown session ${session_id}`);
    }
    ctx.db.sandbox_session.session_id.update({
      ...row,
      sim_freeze_enabled: !row.sim_freeze_enabled,
      updated_at: ctx.timestamp,
    });
  },
);

// Connectivity check: callable, writes nothing.
export const ping = spacetimedb.reducer({ name: 'ping' }, {}, () => {
  // No-op by design — a successful call proves the module is reachable.
});

export default spacetimedb;

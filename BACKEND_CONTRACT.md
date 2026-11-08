# NemoProxy — backend contract (what the frontend expects)

Verified against `MauryaAG07/NemoProxy` main @ `06f9ed8b` (backend/main.py,
backend/incident.py, backend/spacetime_client.py) and tested live in mock
mode on 2026-11-08. The frontend in `frontend/` now matches this contract.

## Live endpoints (FastAPI, default :8000)
- `GET /api/health` → `{ status: "healthy", demo_mode, credentials_status, model_id }`
- `GET /api/scenarios` → `[{ key, id, name, raw_message, target_domain }]`,
  keys: `phishing` | `legitimate` | `ambiguous`
- `POST /api/ingest` `{ scenario }` → `{ incident_id, status: "queued" }`
  (a browser-supplied `user_id` is ignored for ownership)
- `GET /api/state` → `{ incidents, evidence_items, proposed_actions, sandbox_sessions }`
  - incident: `{ incident_id, scenario_id, status: "investigating"|"assessed",
    verdict: "suspected_phishing"|"benign_indicator"|"insufficient_evidence",
    confidence_band: "low"|"medium"|"high", summary, redacted_message }`
    Frontend maps `benign_indicator` → `legitimate_looking`.
  - evidence item: `{ evidence_id, incident_id, source_tool, is_simulated,
    summary, raw_json }`
- `POST /api/session/compromise` → `{ session: { session_id, status: "compromised_sim", ... } }`
- `POST /api/session/revoke` `{ session_id }` → `{ session: { session_id, status: "revoked", ... } }`

The backend keeps its own synthetic fixture per scenario key and redacts it
server-side; the frontend sends ONLY the scenario key, never a message or an
expected label. If the backend is unreachable, the frontend reports the
failure and offers the labelled mock — it never presents a mock result as live.

## SpacetimeDB module
`frontend/src/spacetimedb/schema.ts` mirrors the module tables/reducers.
The backend's `spacetime_client.py` keeps an in-memory store mirroring the
SpacetimeDB schema and only calls live SpacetimeDB reducers when credentials
are configured and `DEMO_MODE=false`; in mock mode it is in-memory only.

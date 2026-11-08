# NemoProxy backend (FastAPI)

Telecom smishing investigation (Nemotron tool loop), SpacetimeDB
authoritative state (spec §5), and real sandbox enforcement (spec §6,
Phase B). See `../BACKEND_CONTRACT.md` for the full frontend/backend
contract and `../spacetimedb/README.md` for the module.

## Run it

```bash
cd backend
pip install -r requirements.txt
# Live mode (real SpacetimeDB — the local server must be running):
DEMO_MODE=false \
SPACETIME_HOST=http://127.0.0.1:3000 \
SPACETIME_DB_IDENTITY=c200645bcd25d414949c4a97fc7f7eca097e43ce7dcb90af441c1d53abe8c03f \
SPACETIME_TOKEN=<token from ~/.config/spacetime/cli.toml> \
uvicorn backend.main:app --host 127.0.0.1 --port 8000
# Demo mode (in-memory mirror, labelled as such; no SpacetimeDB needed):
DEMO_MODE=true uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Run from the `nemo-proxy/` directory so `backend.main` resolves
(`backend/` is a package). No real NVIDIA key exists — live Nemotron
calls are not faked; without a key the backend runs the labelled
simulated tool loop in demo mode and marks live failures explicitly.
Live Nemotron verification was not possible here (no key; this VM's
egress proxy blocks api.nvidia.com).

## Phase C (spec §4) — structured Nemotron assessments

- The model must return a validated JSON assessment
  (`StructuredAssessment` in `nvidia_client.py`): concern level
  (`low`/`suspicious`/`high`/`inconclusive`), plain-English explanation,
  supporting evidence IDs (validated to exist for the incident),
  missing/conflicting evidence, a `conflicts_resolved` cross-check
  (message claims vs domain fixture vs reputation result), recommended
  next step, proposed action if any, recovery steps from the reviewed
  catalog, and an injection flag. No 0–100 probability, no confidence
  number. Invalid output gets one correction retry, then the incident
  is `incomplete`. The verdict is never extracted by substring matching.
- The simulated loop (demo mode) produces the SAME validated assessment,
  so the schema/validation code is exercised without a key.
- Budgets: 6 rounds, 12 tool calls, 120 s wall clock by default
  (env: `INVESTIGATION_MAX_ROUNDS`, `INVESTIGATION_MAX_TOOL_CALLS`,
  `INVESTIGATION_TIMEOUT_SECONDS`). Exhaustion → `incomplete` with
  partial evidence kept. Force it in a test: run a second backend with
  `INVESTIGATION_MAX_TOOL_CALLS=2` and ingest `phishing`.
- Scenarios: `phishing`, `legitimate`, `ambiguous`, `injection`
  (adversarial — the SMS tries to instruct the agent; it is refused and
  flagged, no action is proposed for it, and the session stays active).
- Recovery catalog: review carrier account protections, change the
  account password, enable account PIN/passcode, review recent account
  activity, report the message. No "SIM-porting locked" claim.
- Verify in demo mode: `python3 backend/verify_phase_c.py
  http://127.0.0.1:8001` (runs all four scenarios + compromise →
  revoke e2e against a backend on :8001); the budget test needs the
  low-budget second instance on :8002 as above.

## Endpoints

- `GET /api/health`, `GET /api/scenarios`, `POST /api/ingest`,
  `GET /api/state` — investigation API (see `../BACKEND_CONTRACT.md`).
- `POST /api/session/compromise` — inject a clearly labelled synthetic
  compromise event (`compromised_sim`).
- `POST /api/session/revoke` / `POST /api/session/protect` — approved
  revocation: propose → approve → revoke with one idempotency key.
  `protect` is the customer "Protect demo account" action; `revoke` is
  the operator action. Both return the session plus `action_id`,
  `idempotency_key`, `receipt`, `source`. Repeating with the same key
  is a no-op (one receipt, state unchanged).
- `POST /api/session/issue` — issue a fresh demo session credential.
- `POST /api/session/reset` — reset the demo run + issue a fresh
  credential.
- `GET /api/account/overview` — fictional sandbox account overview
  (protected resource).

## Session credentials (Phase B, spec §6)

- A credential is a random opaque token (`secrets.token_urlsafe(32)`),
  valid 30 minutes. Only its SHA-256 hash is stored: in SpacetimeDB
  (`session.credential_hash`, via `rotate_session_credential`) in live
  mode, or in a server-memory-only dict in demo mode — never in the
  in-memory state mirror, so it can never leak through `/api/state`.
- The raw credential is handed out exactly once, as the HttpOnly
  `nemo_session` cookie (`Path=/api/account`, `SameSite=Lax`,
  `Secure=False` on local http only). It never appears in a JSON body,
  `/api/state`, server logs, or the frontend bundle. Non-browser
  clients (curl) can use the cookie jar (`-c`/`-b`) or an
  `Authorization: Bearer <credential>` header instead.
- Every `GET /api/account/overview` request is verified server-side:
  hash match, unexpired, session usable (`active` or
  `compromised_sim`). Revoked / expired / wrong / missing → 401.
  If SpacetimeDB cannot be reached in live mode → 503, never fail open.
- Lifecycle: issue on `POST /api/session/issue`, on frontend mount in
  live mode, and after every reset. Reset invalidates the old
  credential immediately. Issuing for a revoked session is refused —
  reset the demo run first.
- This enforces against a **fictional sandbox session only**, not a
  real carrier's session. No "SIM-porting locked" claim is made; the
  customer view after revocation shows the informational step "Review
  your carrier account protections".

## Files

- `main.py` — FastAPI app, endpoints, cookie handling.
- `spacetime_client.py` — SpacetimeDB v1 HTTP client, in-memory
  §5 mirror, credential issue/verify, approved revocation, reset.
  The mirror stores the Phase C validated assessment per incident
  (served via `/api/state`; no §5 column exists for it live).
- `incident.py` — scenario fixtures (incl. the Phase C `injection`
  adversarial scenario), server-side redaction, pipeline
  (assessed / failed / incomplete outcomes).
- `nvidia_client.py` — Nemotron tool loop (live + labelled simulated),
  `StructuredAssessment` schema + validation, dispatcher validation
  (tool allow-list, incident ownership, URL allow-list, ordering),
  injection detection, recovery catalog, budgets.
- `config.py` — settings from env / `.env` (incl. Phase C budgets).
- `reputation.py` — URL reputation checks (Google Web Risk when
  configured, else explicitly labelled simulated fixture; the URL
  itself is never fetched — only the provider is queried).
- `verify_phase_c.py` — demo-mode verification script (all four
  scenarios + compromise → revoke e2e; run against a backend on
  :8001).

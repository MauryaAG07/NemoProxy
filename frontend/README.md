# NemoProxy frontend

React + TypeScript + Tailwind CSS, Vite. Two synchronized demo views
(Investigator + Customer), three synthetic scenarios, and a separate
sandbox session-revocation demo.

## Run (mock mode — no credentials needed)
```bash
cd frontend
npm install
npm run dev    # http://localhost:5173
```
Default is mock mode (`VITE_MOCK_MODE=true` in `.env.example` — copy to `.env`
if you want to change it). Mock verdicts are labelled MOCK everywhere.

## Run with the live backend
Start the FastAPI backend from the repo on :8000, then:
```bash
cp .env.example .env   # set VITE_MOCK_MODE=false, VITE_API_URL=http://127.0.0.1:8000
npm run dev
```
Live API (verified against main @ 06f9ed8b): `POST /api/ingest {scenario}`,
`GET /api/state` (poll until the incident is `assessed`), `POST /api/session/compromise`,
`POST /api/session/revoke`. Scenario keys: `phishing` / `legitimate` / `ambiguous`.
The frontend sends only the scenario key; the backend investigates its own
fixture and redacts it server-side.
If the backend is unreachable, the UI says so and offers the labelled mock —
it never fakes a live result.

## Build check
```bash
npm run build
npm run preview   # http://localhost:5173
```

## What is NOT live here
- No live Nemotron call in mock mode, no real reputation lookup.
- No live SpacetimeDB connection (no host/token/bindings in this build).
  The two views sync via BroadcastChannel + React state, labelled "Demo sync".
  Set `VITE_SPACETIMEDB_HOST` and add generated bindings to wire the real SDK
  (`spacetimedb` is already a dependency; see `src/spacetimedb/client.ts`).
- No credentials in the bundle. See `.env.example`.

## Structure
- `src/lib/scenarios.ts` — 3 synthetic scenarios; expected labels kept here, never sent to Nemotron
- `src/lib/mockInvestigation.ts` — labelled mock tool-loop
- `src/lib/api.ts` — backend contract, short timeout, no silent mock fallback
- `src/lib/sync.ts` — two-view sync (BroadcastChannel)
- `src/spacetimedb/` — table/reducer mirror + honest connection status
- `src/components/` — VerdictPanel, SessionPanel

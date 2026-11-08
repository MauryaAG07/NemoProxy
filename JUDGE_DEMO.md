# NemoProxy — judge demo script (~10 minutes)

What this proves: synthetic phishing is investigated with evidence and
honest uncertainty, and a sandbox session is really revoked by the
backend — not by a UI toggle. Nothing here touches a real carrier
account, a real phone, or a real SMS.

## Setup (do before the demo)

```bash
# 1. SpacetimeDB (local server on :3000; publish once — see spacetimedb/README.md)
spacetime start
# 2. Backend (from nemo-proxy/; needs SPACETIME_TOKEN — the CLI identity
#    JWT from ~/.config/spacetime/cli.toml — or use DEMO_MODE=true)
DEMO_MODE=false SPACETIME_HOST=http://127.0.0.1:3000 \
  SPACETIME_DB_IDENTITY=c200645bcd25d414949c4a97fc7f7eca097e43ce7dcb90af441c1d53abe8c03f \
  SPACETIME_TOKEN=<from ~/.config/spacetime/cli.toml> \
  uvicorn backend.main:app --host 127.0.0.1 --port 8000
# 3. Frontend (Vite dev server on :5173)
cd frontend && npm install && npm run dev
# Open http://localhost:5173/?mode=live (or ?mode=mock for the labelled mock)
```

Check `GET /api/health` first: `"status": "healthy"`. If the backend is in
demo mode the header says so — say it out loud; never present a demo-mode
result as a live Nemotron result.

## Walkthrough

**0:00 — The setup (30 s).** Say: "Everything is synthetic — fictional
people, `.example` domains, a fictional sandbox account. The backend
redacts the message server-side before any third-party call."
Expected: header shows mode + SpacetimeDB status; customer view says
"NemoProxy demo ready" with a dismissible practice card about suspicious
login requests.

**0:30 — Phishing scenario (90 s).** Pick "Suspicious carrier billing
message" → Investigate. Say: "The model doesn't classify in one shot —
it calls tools: domain fixture, reputation, session status, then a
validated structured assessment." Expected: verdict `suspected_phishing`,
evidence IDs cited, recovery checklist in the customer view. Point at the
timings box (operator view): server investigation ms and DB→browser ms.

**2:00 — Legitimate control (60 s).** Pick the clinic reminder →
Investigate. Expected: `legitimate_looking`, no revocation proposed.
Say: "A low-concern message never revokes anything by itself."

**3:00 — Ambiguous (60 s).** Pick the package message → Investigate.
Expected: `insufficient_evidence`, concern `inconclusive`, named
unknowns. Say: "When the evidence conflicts, it says so instead of guessing."

**4:00 — Injection attempt (90 s).** Pick the adversarial message →
Investigate. Say: "This SMS tries to order the agent around — approve a
revocation, reveal the credential." Expected: flagged and refused,
`suspected_phishing`, **zero** actions proposed for that incident, session
still active. Tap the message link in the customer view: the inert link
opens the warning panel instead of navigating. Say: "Analysis is not
complete yet" appears while the check is still running.

**5:30 — Six-step revocation (2 min).** Say: "Receiving a bad message does
not itself steal a session — this is a separate, controlled event."
1. Operator: "Test protected resource" → 200 (fictional account overview).
2. "Simulate session compromise (sandbox)" → session `compromised_sim`.
3. Customer view: "Protect demo account".
4. Backend verifies authorization and revokes that session (receipt shown).
5. "Test protected resource" again → **401** with the same credential.
6. Both views show the committed outcome from SpacetimeDB.
Say: "The model can propose revocation, but it cannot approve it — the
approval is bound to this action and session."

**7:30 — Wrap-up (30 s).** "Reset demo run" restores the active session
and a fresh credential. Point out the footer: what the demo does *not*
claim (no production carrier integration, no proven reverse-proxy
detection).

## If a live service is unavailable

- **No NVIDIA key / API unreachable:** run `DEMO_MODE=true` (or
  `?mode=mock`). The header and every result are labelled simulated; the
  demo-mode loop produces the same *validated* assessment, so the
  validation is still exercised — but say plainly it is not a live model
  call.
- **SpacetimeDB down:** the backend serves `in_memory_fallback` and the
  protected endpoint answers **503** (fail-closed, never fail-open).
  Say so; don't present the mirror as live state.
- **Reputation provider unavailable:** the tool returns the labelled
  simulated fixture with provenance; a negative lookup means "not listed
  by this provider", never "safe".

## Known limits (say these if asked)

Live Nemotron and live reputation have not been verified here (no key;
this environment's network blocks api.nvidia.com). The local SpacetimeDB
server is not durable — treat it as a demo database. The in-chat demo
artifact is the older mock frontend, not this build.

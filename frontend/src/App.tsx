import { useEffect, useRef, useState } from 'react'
import VerdictPanel from './components/VerdictPanel'
import SessionPanel, { type ProtectedTestResult, type ProtectInfo } from './components/SessionPanel'
import PracticeCard from './components/PracticeCard'
import LinkWarningPanel from './components/LinkWarningPanel'
import { SCENARIOS, getScenario } from './lib/scenarios'
import { redactPreview } from './lib/redaction'
import { runMockInvestigation } from './lib/mockInvestigation'
import {
  createIncident,
  fetchIncidentResult,
  fetchIncidentTiming,
  fetchScenarios,
  checkBackend,
  revokeSessionLive,
  simulateCompromiseLive,
  protectDemoAccountLive,
  testProtectedResourceLive,
  issueSessionCredentialLive,
  resetDemoRunLive,
  fetchSessionStateLive,
  setMode,
  MOCK_MODE,
} from './lib/api'
import { useSharedState } from './lib/sync'
import type { SandboxSession } from './lib/types'

function requestedActionFor(key: string): string {
  if (key === 'phishing') return 'Pay an overdue bill via a link'
  if (key === 'legitimate') return 'View a billing statement (no payment request in message)'
  if (key === 'injection') return 'Approve a revocation / reveal a credential (instructed by the message — refused)'
  return 'Claim a voucher via a link'
}

/** Timings (spec §10), shown in the OPERATOR view only. Both numbers are
 * measured, never fabricated: investigationMs is the backend's
 * server-side pipeline wall time; dbLatencyMs is the time from the
 * server committing the assessment to this browser first seeing the
 * result. Null = not measured / unavailable (shown as such). */
interface TimingInfo {
  investigationMs: number | null
  investigationNote: string
  dbLatencyMs: number | null
  dbNote: string
}

const URL_RE = /(https?:\/\/[^\s]+)/

/** Format a measured ms value: whole ms above 100, one decimal below
 * (the demo-mode simulated loop runs in under a millisecond). */
function fmtMs(ms: number): string {
  return ms >= 100 ? `${Math.round(ms).toLocaleString()} ms` : `${ms.toFixed(1)} ms`
}

/** Render the synthetic message with its link as an inert button — it
 * opens the warning panel, never navigates anywhere. */
function renderMessageWithInertLink(
  text: string,
  onLinkClick: (url: string) => void,
) {
  return text.split(URL_RE).map((part, i) =>
    URL_RE.test(part) ? (
      <button
        key={i}
        type="button"
        onClick={() => onLinkClick(part)}
        aria-label={`Suspicious link (does not navigate): ${part}`}
        className="break-all font-medium text-sky-300 underline hover:text-sky-200"
      >
        {part}
      </button>
    ) : (
      <span key={i}>{part}</span>
    ),
  )
}

export default function App() {
  const { state, update, spacetimeStatus, syncSource } = useSharedState()
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id)
  const [step, setStep] = useState('')
  const [busy, setBusy] = useState(false)
  const [liveError, setLiveError] = useState('')
  const [backendMessages, setBackendMessages] = useState<Record<string, string>>({})
  const [backendHealthy, setBackendHealthy] = useState<boolean | null>(null)
  const [backendDemoMode, setBackendDemoMode] = useState<boolean | null>(null)
  const [scenariosLoading, setScenariosLoading] = useState(false)
  // Phase B (§6): protected-resource test result + committed revocation receipt.
  const [protectedResult, setProtectedResult] = useState<ProtectedTestResult | null>(null)
  const [protectInfo, setProtectInfo] = useState<ProtectInfo | null>(null)
  // Cheap wins: practice card dismissal, link-warning panel, timings.
  const [practiceDismissed, setPracticeDismissed] = useState(false)
  const [warnedUrl, setWarnedUrl] = useState<string | null>(null)
  const [timingInfo, setTimingInfo] = useState<TimingInfo | null>(null)
  const ingestStartedAtRef = useRef(0)
  const timingDoneForRef = useRef('')
  const scenario = getScenario(scenarioId)
  const incident = state.incident
  // In live mode the backend investigates its own fixture for the scenario
  // key; show that message instead of the frontend's local copy.
  const displayText = !MOCK_MODE && backendMessages[scenario.backendKey]
    ? backendMessages[scenario.backendKey]
    : scenario.text

  useEffect(() => {
    if (!MOCK_MODE) {
      checkBackend().then((h) => {
        setBackendHealthy(h.healthy)
        setBackendDemoMode(h.demoMode)
        // Phase B: make sure this browser holds a current demo session
        // credential (HttpOnly cookie) so "Test protected resource"
        // works. The raw credential never enters JS state — only the
        // cookie holds it. A failure here is not fatal: the test button
        // reports 401 and the reset control re-issues.
        if (h.healthy) void issueSessionCredentialLive()
      })
      setScenariosLoading(true)
      fetchScenarios()
        .then((list) => {
          if (list) {
            setBackendMessages(Object.fromEntries(list.map((s) => [s.key, s.raw_message])))
          }
        })
        .finally(() => setScenariosLoading(false))
    }
  }, [])

  // Timings (spec §10): when an incident first completes in this
  // browser, measure DB-to-client latency as the time from the server
  // committing the assessment (investigation_finished_at_ms from
  // /api/state) to this browser first seeing the completed result.
  // The SpacetimeDB subscription path and the /api/state polling path
  // both end here, so this covers both. Mock mode has no database, so
  // its DB latency is honestly "not applicable" and its investigation
  // time is the local simulated run, labelled as such.
  useEffect(() => {
    if (!incident || incident.status !== 'complete' || !incident.result) return
    if (timingDoneForRef.current === incident.id) return
    timingDoneForRef.current = incident.id
    const seenAt = Date.now()
    if (MOCK_MODE) {
      setTimingInfo({
        investigationMs: ingestStartedAtRef.current
          ? seenAt - ingestStartedAtRef.current
          : null,
        investigationNote: 'mock investigation (simulated local delays, not a real model call)',
        dbLatencyMs: null,
        dbNote: 'not applicable — mock mode has no database',
      })
      return
    }
    void fetchIncidentTiming(incident.id).then((t) => {
      let dbLatency: number | null = null
      if (t?.investigationFinishedAtMs) {
        const d = seenAt - t.investigationFinishedAtMs
        if (d >= 0 && d < 120_000) dbLatency = d
      }
      setTimingInfo({
        investigationMs: t?.investigationDurationMs ?? null,
        investigationNote:
          'server-side pipeline: redaction + Nemotron tool loop + commit',
        dbLatencyMs: dbLatency,
        dbNote:
          syncSource === 'spacetimedb'
            ? 'via live SpacetimeDB subscription'
            : 'via /api/state polling',
      })
    })
  }, [incident, syncSource])

  async function investigate(useMock: boolean) {
    setBusy(true)
    setLiveError('')
    setStep('')
    setTimingInfo(null)
    timingDoneForRef.current = ''
    ingestStartedAtRef.current = Date.now()
    const incidentId = useMock
      ? `mock-${crypto.randomUUID().slice(0, 8)}`
      : (await createIncident(scenario.backendKey)) ?? ''
    if (!useMock && !incidentId) {
      setLiveError(
        'Backend unreachable — no incident was created and no live result was faked. Run the labelled mock instead, or start the FastAPI backend on :8000.',
      )
      setBusy(false)
      return
    }
    update((p) => ({
      ...p,
      incident: { id: incidentId, scenarioId, status: 'investigating', createdAt: Date.now() },
    }))

    if (useMock) {
      const result = await runMockInvestigation(incidentId, scenarioId, setStep)
      update((p) => ({
        ...p,
        incident: p.incident ? { ...p.incident, status: 'complete', result } : p.incident,
      }))
      setStep('')
      setBusy(false)
      return
    }

    // Live path: poll GET /api/state; never fall back silently to mock.
    setStep('Waiting for the backend investigation…')
    for (let i = 0; i < 130; i++) {
      await new Promise((r) => setTimeout(r, 1000))
      const result = await fetchIncidentResult(
        incidentId,
        scenario.sender,
        requestedActionFor(scenario.backendKey),
      )
      if (result) {
        update((p) => ({
          ...p,
          incident: p.incident ? { ...p.incident, status: 'complete', result } : p.incident,
        }))
        setStep('')
        setBusy(false)
        return
      }
    }
    setLiveError('Backend did not return a result in time. Nothing was faked — try again or run the labelled mock.')
    update((p) => ({
      ...p,
      incident: p.incident ? { ...p.incident, status: 'error', error: 'Backend timeout' } : p.incident,
    }))
    setBusy(false)
  }

  async function simulateSession() {
    if (MOCK_MODE) {
      const session: SandboxSession = {
        id: `sandbox-${crypto.randomUUID().slice(0, 8)}`,
        accountLabel: 'Demo account alex@example.com (fictional, sandbox only)',
        state: 'compromised',
        createdAt: Date.now(),
        mode: 'mock',
      }
      update((p) => ({ ...p, session }))
      return
    }
    setBusy(true)
    setLiveError('')
    const session = await simulateCompromiseLive()
    setBusy(false)
    if (!session) {
      setLiveError('Backend unreachable — no session compromise was simulated. Start the backend on :8000.')
      return
    }
    update((p) => ({ ...p, session }))
  }

  async function revokeSession() {
    if (!state.session) return
    if (MOCK_MODE) {
      update((p) => ({
        ...p,
        session: p.session
          ? { ...p.session, state: 'revoked', revokedAt: Date.now(), mode: 'mock' }
          : p.session,
      }))
      return
    }
    setBusy(true)
    setLiveError('')
    const session = await revokeSessionLive(state.session.id)
    setBusy(false)
    if (!session) {
      setLiveError('Backend unreachable — the session was NOT revoked. Start the backend on :8000 and try again.')
      return
    }
    update((p) => ({ ...p, session }))
    // Show the committed SpacetimeDB row, not just the endpoint reply.
    void refreshSessionFromState()
  }

  /** Re-read the session from GET /api/state (SpacetimeDB rows in live
   * mode) so both views show the committed outcome, not local state. */
  async function refreshSessionFromState() {
    const committed = await fetchSessionStateLive()
    if (committed) update((p) => ({ ...p, session: committed }))
  }

  /** Operator: test the protected resource before/after revocation. */
  async function testProtected() {
    if (MOCK_MODE) {
      const s = state.session
      setProtectedResult({
        status: s && s.state !== 'revoked' ? 200 : 401,
        summary:
          s && s.state !== 'revoked'
            ? '200 · fictional account acct_tm_94821 · Magenta Plus — fictional sandbox plan · balance $85.00 · data 18.4/50 GB (mock)'
            : '401 · Session has been revoked. (mock)',
        source: 'mock',
        at: Date.now(),
      })
      return
    }
    setBusy(true)
    setLiveError('')
    const result = await testProtectedResourceLive()
    setBusy(false)
    if (!result) {
      setLiveError('Backend unreachable — the protected resource could not be tested. Start the backend on :8000.')
      return
    }
    setProtectedResult({ ...result, at: Date.now() })
  }

  /** Customer: "Protect demo account" — the approved propose → approve
   * → revoke flow for this session, one idempotency key. */
  async function protectAccount() {
    if (!state.session) return
    if (MOCK_MODE) {
      update((p) => ({
        ...p,
        session: p.session
          ? { ...p.session, state: 'revoked', revokedAt: Date.now(), mode: 'mock' }
          : p.session,
      }))
      setProtectInfo({
        actionId: 'mock-act-protect',
        idempotencyKey: 'mock-key-protect',
        receipt: 'Mock revocation — no live SpacetimeDB receipt.',
      })
      return
    }
    setBusy(true)
    setLiveError('')
    const result = await protectDemoAccountLive(state.session.id)
    setBusy(false)
    if (!result) {
      setLiveError('Backend unreachable or revocation refused — the session was NOT revoked. Start the backend on :8000 and try again.')
      return
    }
    setProtectInfo({
      actionId: result.actionId,
      idempotencyKey: result.idempotencyKey,
      receipt: result.receipt,
    })
    update((p) => ({ ...p, session: result.session }))
    // Both views show the committed SpacetimeDB outcome.
    void refreshSessionFromState()
  }

  /** Reset the demo run: fresh session + new credential. */
  async function resetDemo() {
    if (MOCK_MODE) {
      const session: SandboxSession = {
        id: 'sess_demo_carrier_01',
        accountLabel: 'Demo account alex@example.com (fictional, sandbox only)',
        state: 'active',
        createdAt: Date.now(),
        mode: 'mock',
      }
      update((p) => ({ ...p, session }))
      setProtectedResult(null)
      setProtectInfo(null)
      return
    }
    setBusy(true)
    setLiveError('')
    const session = await resetDemoRunLive()
    setBusy(false)
    if (!session) {
      setLiveError('Backend unreachable — the demo run was NOT reset. Start the backend on :8000 and try again.')
      return
    }
    update((p) => ({ ...p, session }))
    setProtectedResult(null)
    setProtectInfo(null)
  }

  return (
    <div className="min-h-screen text-slate-100">
      <header className="border-b border-slate-700 bg-slate-900 px-4 py-4">
        <h1 className="text-2xl font-bold">NemoProxy</h1>
        <p className="text-sm text-slate-300">
          Investigates synthetic phishing texts, explains evidence and uncertainty, and
          demonstrates sandbox session revocation. Fictional carrier environment — no
          production carrier integration, no real SMS interception, no proven
          reverse-proxy detection.
        </p>
        <div className="mt-2 flex flex-wrap gap-2 text-xs">
          <span className="rounded-full bg-amber-500 px-2 py-1 font-bold text-black">
            {MOCK_MODE ? 'MOCK MODE — simulated Nemotron / reputation' : 'LIVE MODE — backend required'}
          </span>
          <button
            onClick={() => setMode(MOCK_MODE ? 'live' : 'mock')}
            className="rounded-full bg-sky-600 px-2 py-1 font-semibold text-white hover:bg-sky-500"
          >
            Switch to {MOCK_MODE ? 'live backend' : 'mock'} mode
          </button>
          {!MOCK_MODE && (
            <span className="rounded-full bg-slate-700 px-2 py-1">
              Backend: {backendHealthy === null ? 'checking…' : backendHealthy ? 'reachable on :8000' : 'NOT reachable'}
              {backendDemoMode === true ? ' · demo mode: simulated Nemotron' : ''}
            </span>
          )}
          <span className="rounded-full bg-slate-700 px-2 py-1">
            SpacetimeDB:{' '}
            {spacetimeStatus === 'connected'
              ? 'connected (nemo-proxy)'
              : spacetimeStatus === 'not_configured'
                ? 'not configured — demo sync only'
                : spacetimeStatus}
          </span>
          <span className="rounded-full bg-slate-700 px-2 py-1">
            {syncSource === 'spacetimedb'
              ? 'Live SpacetimeDB sync: two views below share one incident'
              : 'Demo sync: two views below share one incident (open a 2nd tab to see cross-tab sync)'}
          </span>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-4 px-4 py-4">
        <section className="rounded-xl border border-slate-700 bg-slate-900 p-4">
          <h2 className="text-lg font-bold">1 · Pick a synthetic scenario</h2>
          <div className="mt-3 grid gap-2 md:grid-cols-2 lg:grid-cols-4">
            {SCENARIOS.map((s) => (
              <button
                key={s.id}
                onClick={() => setScenarioId(s.id)}
                className={`rounded-lg border p-3 text-left ${
                  s.id === scenarioId ? 'border-sky-400 bg-slate-800' : 'border-slate-700 bg-slate-800/50'
                }`}
              >
                <span className="text-xs font-bold uppercase text-sky-300">{s.tag}</span>
                <span className="block font-semibold">{s.title}</span>
                <span className="block text-xs text-slate-400">{s.sender}</span>
              </button>
            ))}
          </div>
          <div className="mt-3 rounded-lg bg-slate-800 p-3 text-sm">
            <p className="text-slate-400">
              Message as received (synthetic, fictional)
              {!MOCK_MODE && backendMessages[scenario.backendKey] ? ' — backend fixture' : ''}:
            </p>
            <p className="mt-1">
              {scenariosLoading
                ? 'Loading backend fixture…'
                : displayText}
            </p>
            {MOCK_MODE ? (
              <>
                <p className="mt-3 text-slate-400">What is sent onward (server-side redaction preview):</p>
                <p className="mt-1 text-slate-200">{redactPreview(scenario.text)}</p>
              </>
            ) : (
              <p className="mt-3 text-xs text-slate-400">
                Live mode sends only the scenario key ({scenario.backendKey}) to POST /api/ingest.
                The backend redacts its own fixture message server-side before any third-party
                call — not on-device processing, not complete anonymisation.
              </p>
            )}
            <p className="mt-2 text-xs text-slate-400">
              Only synthetic content is submitted in this demo.
            </p>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              onClick={() => investigate(MOCK_MODE)}
              disabled={busy}
              className="rounded-lg bg-sky-600 px-4 py-2 font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {MOCK_MODE ? 'Investigate (mock)' : 'Investigate (live backend)'}
            </button>
            {!MOCK_MODE && (
              <button
                onClick={() => investigate(true)}
                disabled={busy}
                className="rounded-lg bg-slate-700 px-4 py-2 font-semibold hover:bg-slate-600 disabled:opacity-50"
              >
                Run labelled mock instead
              </button>
            )}
          </div>
          {step && <p className="mt-2 text-sm text-sky-300">{step}</p>}
          {liveError && (
            <p className="mt-2 rounded-lg bg-red-900/50 p-2 text-sm text-red-200">{liveError}</p>
          )}
          {incident && (
            <p className="mt-2 text-sm text-slate-300">
              Incident <code className="rounded bg-slate-800 px-1">{incident.id}</code> · Status:{' '}
              {incident.status}
            </p>
          )}
          {incident && (
            <div className="mt-2 rounded-lg border border-slate-700 bg-slate-800 p-3 text-xs text-slate-300">
              <p className="font-semibold text-slate-100">
                Timings — operator view only (measured, never fabricated)
              </p>
              <p className="mt-1">
                AI investigation (server):{' '}
                <strong className="text-slate-100">
                  {timingInfo
                    ? timingInfo.investigationMs !== null
                      ? fmtMs(timingInfo.investigationMs)
                      : 'unavailable — backend did not report timings'
                    : incident.status === 'complete'
                      ? 'measuring…'
                      : 'not measured yet'}
                </strong>
                {timingInfo && (
                  <span className="text-slate-400"> · {timingInfo.investigationNote}</span>
                )}
              </p>
              <p className="mt-1">
                Database → this browser:{' '}
                <strong className="text-slate-100">
                  {timingInfo
                    ? timingInfo.dbLatencyMs !== null
                      ? fmtMs(timingInfo.dbLatencyMs)
                      : 'unavailable'
                    : incident.status === 'complete'
                      ? 'measuring…'
                      : 'not measured yet'}
                </strong>
                {timingInfo && (
                  <span className="text-slate-400">
                    {' '}
                    · {timingInfo.dbNote} — time from the server committing the assessment to
                    this browser first seeing the result
                  </span>
                )}
              </p>
            </div>
          )}
        </section>

        {!incident && (
          <section>
            <h2 className="mb-2 text-lg font-bold">2 · Customer view — before anything arrives</h2>
            <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
              <p className="text-2xl font-bold">NemoProxy demo ready.</p>
              <p className="mt-2 text-sm text-slate-300">
                No message has arrived yet. Pick a scenario above and start an investigation —
                the message will appear here, in the customer’s view, as it would on a phone.
              </p>
              {!practiceDismissed ? (
                <PracticeCard onDismiss={() => setPracticeDismissed(true)} />
              ) : (
                <button
                  type="button"
                  onClick={() => setPracticeDismissed(false)}
                  className="mt-3 rounded-lg bg-slate-700 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-600"
                >
                  Show the practice message again
                </button>
              )}
            </div>
          </section>
        )}

        {incident && (
          <section>
            <h2 className="mb-2 text-lg font-bold">2 · Two synchronized views — same incident</h2>
            <div className="grid gap-4 lg:grid-cols-2">
              <div>
                <p className="mb-1 text-sm font-semibold text-sky-300">View A — Investigator</p>
                {incident.result ? (
                  <VerdictPanel result={incident.result} />
                ) : (
                  <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
                    <p className="text-lg font-bold">⏳ Analysis in progress…</p>
                    <p className="mt-2 text-sm text-slate-300">
                      {step || 'The investigation is running. Evidence and the assessment will appear here when they are ready — nothing is shown before it exists.'}
                    </p>
                  </div>
                )}
              </div>
              <div>
                <p className="mb-1 text-sm font-semibold text-emerald-300">View B — Customer (plain language)</p>
                <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
                  <p className="text-xs font-bold uppercase text-slate-400">
                    Incoming message (synthetic — as it would appear on the phone)
                  </p>
                  <p className="mt-1 text-slate-100">
                    {renderMessageWithInertLink(displayText, (u) => setWarnedUrl(u))}
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    The link above is inert — tapping it opens a warning here, it never takes
                    you to the linked site.
                  </p>
                  {warnedUrl && (
                    <LinkWarningPanel
                      linkUrl={warnedUrl}
                      claimedOrg={scenario.sender}
                      analysis={
                        incident.result
                          ? {
                              finished: true,
                              verdict: incident.result.verdict,
                              incomplete: !!incident.result.incomplete,
                            }
                          : { finished: false }
                      }
                      onClose={() => setWarnedUrl(null)}
                    />
                  )}
                  {!incident.result ? (
                    <p className="mt-3 text-sm text-amber-200">
                      ⏳ Analysis is unfinished — we’re still checking this message, so don’t
                      act on it yet.
                    </p>
                  ) : incident.result.incomplete ? (
                    <p className="mt-3 text-2xl font-bold">
                      ⏳ We couldn’t finish checking this one.
                    </p>
                  ) : (
                    <p className="mt-3 text-2xl font-bold">
                      {incident.result.verdict === 'suspected_phishing'
                        ? '⛔ Don’t click — this looks like a scam.'
                        : incident.result.verdict === 'insufficient_evidence'
                          ? '⏳ Not sure yet — don’t click, check another way.'
                          : '✅ Looks okay — but stay careful.'}
                    </p>
                  )}
                  {incident.result && (
                    <>
                  <p className="mt-2 text-slate-200">{incident.result.summary}</p>
                  <p className="mt-2 text-sm text-amber-200">
                    What we don’t know: {incident.result.uncertainty}
                  </p>
                  {incident.result.assessment?.injection_attempt_detected && (
                    <p className="mt-2 rounded-lg bg-red-900/60 p-2 text-sm text-red-100">
                      ⚠️ This message also tried to tell the security checker what to do. That
                      instruction was ignored — nothing was approved, revoked, or revealed because of it.
                    </p>
                  )}
                  {incident.result.assessment?.recommended_next_step && (
                    <p className="mt-2 text-sm text-slate-200">
                      <strong>What to do next:</strong>{' '}
                      {incident.result.assessment.recommended_next_step}
                    </p>
                  )}
                  {incident.result.recoverySteps && incident.result.recoverySteps.length > 0 && (
                    <div className="mt-3">
                      <p className="font-semibold text-slate-100">Recovery checklist</p>
                      <ul className="mt-1 list-disc pl-5 text-sm text-slate-200">
                        {incident.result.recoverySteps.map((s) => (
                          <li key={s.id}>{s.label}</li>
                        ))}
                      </ul>
                      <p className="mt-1 text-xs text-slate-400">
                        Informational steps only — this demo does not change any real carrier account.
                      </p>
                    </div>
                  )}
                  <p className="mt-2 text-xs text-slate-400">
                    {incident.result.mode === 'mock'
                      ? 'This is a simulated demo verdict, not a live Nemotron result.'
                      : incident.result.mode === 'live-demo'
                        ? 'Live backend verdict, but the backend is in demo mode — its Nemotron result is simulated.'
                        : 'Live backend verdict.'}{' '}
                    If you’re unsure, check in the official app — never through the link in the message.
                  </p>
                    </>
                  )}
                </div>
              </div>
            </div>
            {incident.result && (
              <p className="mt-2 text-xs text-slate-400">
                Expected label for this scenario (kept separate from agent input, never sent to
                Nemotron): <strong>{scenario.expectedVerdict}</strong> — {scenario.expectedNote}
              </p>
            )}
          </section>
        )}

        <SessionPanel
          session={state.session}
          busy={busy}
          onSimulate={simulateSession}
          onRevoke={revokeSession}
          onTestProtected={testProtected}
          protectedResult={protectedResult}
          onProtect={protectAccount}
          protectInfo={protectInfo}
          onReset={resetDemo}
        />

        <footer className="rounded-xl border border-slate-700 bg-slate-900 p-4 text-xs text-slate-400">
          <strong className="text-slate-200">What this demo does not claim:</strong> no production
          carrier integration, no universal 2FA bypass, no real SMS interception, no proven
          reverse-proxy detection, no real banking / SIM-porting integration. Domain age, hosting
          and brand mismatch are phishing indicators, not proof a reverse proxy exists or a
          session was stolen. The protected-resource test enforces against the fictional
          sandbox session only, with a random expiring credential — it never touches a real
          carrier account. Interrupted backend jobs do not automatically resume after a restart.
        </footer>
      </main>
    </div>
  )
}

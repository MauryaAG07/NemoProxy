import type { SandboxSession } from '../lib/types'

export interface ProtectedTestResult {
  status: number
  summary: string
  source?: string
  at: number
}

export interface ProtectInfo {
  actionId: string
  idempotencyKey: string
  receipt: string
}

interface Props {
  session: SandboxSession | null
  busy: boolean
  onSimulate: () => void
  onRevoke: () => void
  // Phase B (spec §6): real sandbox enforcement controls.
  onTestProtected: () => void
  protectedResult: ProtectedTestResult | null
  onProtect: () => void
  protectInfo: ProtectInfo | null
  onReset: () => void
}

// Session compromise is a SEPARATE demo from the SMS verdict (spec §2).
// Receiving a malicious message does not mean a session was stolen.
// This panel only ever touches a fictional sandbox account, and the
// enforcement below is against that sandbox session — NOT a real
// carrier's session. No SIM-porting lock is claimed anywhere here:
// after a revocation the customer is pointed to review their real
// carrier account's own protections instead.
export default function SessionPanel({
  session,
  busy,
  onSimulate,
  onRevoke,
  onTestProtected,
  protectedResult,
  onProtect,
  protectInfo,
  onReset,
}: Props) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
      <h2 className="text-lg font-bold text-slate-100">Sandbox session — separate demo</h2>
      <p className="mt-1 text-sm text-slate-300">
        A controlled, simulated session-compromise event on a fictional sandbox account.
        Receiving a suspicious message does <strong>not</strong> mean a session was stolen.
        Enforcement below is against the fictional sandbox session only — not a real
        carrier&apos;s session.
      </p>
      {!session && (
        <button
          onClick={onSimulate}
          disabled={busy}
          className="mt-3 rounded-lg bg-violet-600 px-4 py-2 font-semibold text-white hover:bg-violet-500 disabled:opacity-50"
        >
          Simulate session compromise (sandbox)
        </button>
      )}
      {session && (
        <div className="mt-3 space-y-2 text-sm">
          <p className="text-slate-200">
            Account: <strong>{session.accountLabel}</strong> · Session{' '}
            <code className="rounded bg-slate-800 px-1">{session.id}</code>
          </p>
          <p>
            State:{' '}
            <span
              className={`rounded-full px-3 py-1 font-bold ${
                session.state === 'revoked'
                  ? 'bg-emerald-600 text-white'
                  : session.state === 'compromised'
                    ? 'bg-red-600 text-white'
                    : session.state === 'active'
                      ? 'bg-sky-600 text-white'
                      : 'bg-slate-600 text-white'
              }`}
            >
              {session.state === 'revoked'
                ? 'REVOKED — enforced in sandbox'
                : session.state === 'compromised'
                  ? `COMPROMISED${session.mode === 'mock' ? ' (simulated)' : ''}`
                  : session.state === 'active'
                    ? 'ACTIVE'
                    : 'NO SESSION'}
            </span>{' '}
            <span className="rounded-full bg-slate-700 px-2 py-1 text-xs text-slate-200">
              {session.mode === 'mock' ? 'MOCK' : 'LIVE'}
            </span>
          </p>
          {session.state === 'compromised' && (
            <p className="text-red-200">
              Controlled simulated compromise event on the fictional sandbox account — this
              does not mean a real session was stolen.
            </p>
          )}
          {session.state === 'compromised' && (
            <button
              onClick={onProtect}
              disabled={busy}
              className="rounded-lg bg-emerald-600 px-4 py-2 font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              Protect demo account
            </button>
          )}
          {(session.state === 'compromised' || session.state === 'active') && (
            <button
              onClick={onRevoke}
              disabled={busy}
              className="rounded-lg bg-slate-700 px-4 py-2 font-semibold text-white hover:bg-slate-600 disabled:opacity-50"
            >
              Revoke session (operator, sandbox)
            </button>
          )}
          {session.state === 'revoked' && session.revokedAt && (
            <p className="text-emerald-300">
              Revoked at {new Date(session.revokedAt).toLocaleTimeString()}. The sandbox session
              can no longer be used in this demo.
            </p>
          )}
          {session.state === 'revoked' && protectInfo && (
            <div className="rounded-lg bg-slate-800 p-3 text-xs text-slate-300">
              <p className="font-semibold text-slate-100">Committed revocation receipt (from SpacetimeDB)</p>
              <p className="mt-1 break-all">Receipt: {protectInfo.receipt}</p>
              <p>Action: <code className="rounded bg-slate-700 px-1">{protectInfo.actionId}</code></p>
              <p>Idempotency key: <code className="rounded bg-slate-700 px-1">{protectInfo.idempotencyKey}</code></p>
            </div>
          )}
          {session.state === 'revoked' && (
            <div className="rounded-lg bg-slate-800 p-3 text-xs text-slate-300">
              <p className="font-semibold text-slate-100">Recovery — informational only</p>
              <ul className="mt-1 list-disc pl-5">
                <li>Review your carrier account protections — check the PIN, port-out freeze and account alerts in the official carrier app.</li>
              </ul>
              <p className="mt-1 text-slate-400">
                This demo revokes only the fictional sandbox session; it does not lock a SIM
                port or change any real carrier account.
              </p>
            </div>
          )}

          <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-3">
            <p className="font-semibold text-slate-100">
              Operator — test protected resource (fictional account overview)
            </p>
            <p className="mt-1 text-xs text-slate-400">
              Calls GET /api/account/overview with the sandbox session credential (HttpOnly
              cookie — the credential itself is never shown). Expect 200 while the session
              is active, 401 after revocation with the same credential.
            </p>
            <button
              onClick={onTestProtected}
              disabled={busy}
              className="mt-2 rounded-lg bg-sky-600 px-4 py-2 font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
            >
              Test protected resource
            </button>
            {protectedResult && (
              <p className="mt-2 rounded-lg bg-slate-800 p-2 text-xs">
                <span
                  className={`font-bold ${
                    protectedResult.status === 200 ? 'text-emerald-300' : 'text-red-300'
                  }`}
                >
                  {protectedResult.status}
                </span>{' '}
                <span className="text-slate-200">{protectedResult.summary}</span>
                {protectedResult.source && (
                  <span className="block text-slate-400">
                    Verified via: {protectedResult.source} ·{' '}
                    {new Date(protectedResult.at).toLocaleTimeString()}
                  </span>
                )}
              </p>
            )}
          </div>

          <button
            onClick={onReset}
            disabled={busy}
            className="rounded-lg bg-slate-700 px-4 py-2 font-semibold text-white hover:bg-slate-600 disabled:opacity-50"
          >
            Reset demo run (fresh session + new credential)
          </button>
          <p className="text-xs text-slate-400">
            Reset clears the demo run in SpacetimeDB, reactivates the sandbox session and
            issues a fresh credential; the old credential stops working immediately.
          </p>
        </div>
      )}
    </div>
  )
}

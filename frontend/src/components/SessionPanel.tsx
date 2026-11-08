import type { SandboxSession } from '../lib/types'

interface Props {
  session: SandboxSession | null
  busy: boolean
  onSimulate: () => void
  onRevoke: () => void
}

// Session compromise is a SEPARATE demo from the SMS verdict (spec §2).
// Receiving a malicious message does not mean a session was stolen.
// This panel only ever touches a fictional sandbox account.
export default function SessionPanel({ session, busy, onSimulate, onRevoke }: Props) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
      <h2 className="text-lg font-bold text-slate-100">Sandbox session — separate demo</h2>
      <p className="mt-1 text-sm text-slate-300">
        A controlled, simulated session-compromise event on a fictional sandbox account.
        Receiving a suspicious message does <strong>not</strong> mean a session was stolen.
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
                session.state === 'revoked' ? 'bg-emerald-600 text-white' : 'bg-red-600 text-white'
              }`}
            >
              {session.state === 'revoked' ? 'REVOKED — enforced in sandbox' : 'ACTIVE — compromised (simulated)'}
            </span>{' '}
            <span className="rounded-full bg-slate-700 px-2 py-1 text-xs text-slate-200">
              {session.mode === 'mock' ? 'MOCK' : 'LIVE'}
            </span>
          </p>
          {session.state === 'active' && (
            <button
              onClick={onRevoke}
              disabled={busy}
              className="rounded-lg bg-emerald-600 px-4 py-2 font-semibold text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              Revoke session (sandbox)
            </button>
          )}
          {session.state === 'revoked' && session.revokedAt && (
            <p className="text-emerald-300">
              Revoked at {new Date(session.revokedAt).toLocaleTimeString()}. The sandbox session
              can no longer be used in this demo.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

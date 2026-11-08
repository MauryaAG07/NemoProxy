import type { InvestigationResult, Verdict } from '../lib/types'

const VERDICT_STYLE: Record<Verdict, { label: string; cls: string }> = {
  suspected_phishing: {
    label: 'Suspected phishing',
    cls: 'bg-red-600 text-white',
  },
  insufficient_evidence: {
    label: 'Insufficient evidence',
    cls: 'bg-amber-500 text-black',
  },
  legitimate_looking: {
    label: 'Legitimate-looking',
    cls: 'bg-emerald-600 text-white',
  },
}

const CONCERN_LABEL: Record<string, string> = {
  low: 'Low concern',
  suspicious: 'Suspicious',
  high: 'High concern',
  inconclusive: 'Inconclusive',
}

export default function VerdictPanel({ result }: { result: InvestigationResult }) {
  const v = VERDICT_STYLE[result.verdict]
  const a = result.assessment ?? null
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
      {result.incomplete && (
        <p className="mb-3 rounded-lg bg-amber-900/60 p-3 text-sm text-amber-100">
          <strong>Incomplete investigation — no verdict produced.</strong>{' '}
          {result.incompleteReason ||
            'The investigation ran out of budget before a validated assessment could be produced.'}{' '}
          The partial evidence below was kept; nothing was substituted for the missing verdict.
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full px-3 py-1 text-sm font-bold ${v.cls}`}>{v.label}</span>
        <span className="rounded-full bg-slate-700 px-2 py-1 text-xs text-slate-200">
          Confidence: {result.confidence}
        </span>
        {a && (
          <span className="rounded-full bg-slate-700 px-2 py-1 text-xs text-slate-200">
            Concern: {CONCERN_LABEL[a.concern_level] ?? a.concern_level}
          </span>
        )}
        <span className="rounded-full bg-slate-700 px-2 py-1 text-xs text-slate-200">
          {result.mode === 'mock'
            ? 'MOCK — simulated'
            : result.mode === 'live-demo'
              ? 'LIVE — backend (demo mode: simulated Nemotron)'
              : 'LIVE — backend / Nemotron'}
        </span>
      </div>
      {a?.injection_attempt_detected && (
        <p className="mt-3 rounded-lg bg-red-900/60 p-3 text-sm text-red-100">
          <strong>⚠️ Injection attempt refused and flagged.</strong>{' '}
          {a.injection_details ||
            'The message tried to instruct the agent.'}{' '}
          No action from the message text was executed — no approval, no revocation, no credential reveal.
        </p>
      )}
      <p className="mt-3 text-slate-100">{result.summary}</p>
      <p className="mt-2 text-sm text-amber-200">
        <strong>Uncertainty:</strong> {result.uncertainty}
      </p>
      <p className="mt-2 text-sm text-slate-300">
        Claimed organisation: <strong>{result.claimedOrg}</strong> · Requested action:{' '}
        <strong>{result.requestedAction}</strong>
      </p>
      {result.reputationUrlNote && (
        <p className="mt-2 text-xs text-slate-400">{result.reputationUrlNote}</p>
      )}
      {a && a.conflicts_resolved.length > 0 && (
        <>
          <h3 className="mt-4 font-semibold text-slate-100">Cross-checks — message vs domain vs reputation</h3>
          <ul className="mt-2 space-y-2">
            {a.conflicts_resolved.map((c, i) => (
              <li key={i} className="rounded-lg bg-slate-800 p-3 text-sm text-slate-300">
                <p><strong className="text-slate-100">Claim:</strong> {c.claim}</p>
                <p className="mt-1"><strong className="text-slate-100">Domain:</strong> {c.domain_evidence}</p>
                <p className="mt-1"><strong className="text-slate-100">Reputation:</strong> {c.reputation_evidence}</p>
                <p className="mt-1"><strong className="text-slate-100">Resolution:</strong> {c.resolution}</p>
              </li>
            ))}
          </ul>
        </>
      )}
      {a && a.missing_evidence.length > 0 && (
        <div className="mt-3">
          <h3 className="font-semibold text-slate-100">Missing / conflicting evidence</h3>
          <ul className="mt-1 list-disc pl-5 text-sm text-slate-300">
            {a.missing_evidence.map((m, i) => (
              <li key={i}>{m}</li>
            ))}
          </ul>
        </div>
      )}
      {a && a.recommended_next_step && (
        <p className="mt-3 text-sm text-slate-200">
          <strong>Recommended next step:</strong> {a.recommended_next_step}
        </p>
      )}
      {result.recoverySteps && result.recoverySteps.length > 0 && (
        <div className="mt-3">
          <h3 className="font-semibold text-slate-100">Recovery checklist</h3>
          <ul className="mt-1 list-disc pl-5 text-sm text-slate-300">
            {result.recoverySteps.map((s) => (
              <li key={s.id}>{s.label}</li>
            ))}
          </ul>
          <p className="mt-1 text-xs text-slate-400">
            Informational steps only — this demo does not change any real carrier account.
          </p>
        </div>
      )}
      <h3 className="mt-4 font-semibold text-slate-100">
        Activity log — tool calls, evidence and outcomes (no model reasoning)
      </h3>
      <ul className="mt-2 space-y-2">
        {result.evidence.map((e) => (
          <li key={e.id} className="rounded-lg bg-slate-800 p-3 text-sm">
            <div className="flex justify-between gap-2">
              <strong className="text-slate-100">{e.label}</strong>
              <span className="shrink-0 rounded bg-slate-700 px-2 py-0.5 text-xs text-slate-200">
                {e.source === 'simulated' ? 'Simulated fixture' : 'Live source'}
              </span>
            </div>
            <p className="mt-1 text-slate-300">{e.detail}</p>
            <p className="mt-1 text-xs text-slate-400">Does not prove: {e.limitation}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}

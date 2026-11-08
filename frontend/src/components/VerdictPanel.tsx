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

export default function VerdictPanel({ result }: { result: InvestigationResult }) {
  const v = VERDICT_STYLE[result.verdict]
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full px-3 py-1 text-sm font-bold ${v.cls}`}>{v.label}</span>
        <span className="rounded-full bg-slate-700 px-2 py-1 text-xs text-slate-200">
          Confidence: {result.confidence}
        </span>
        <span className="rounded-full bg-slate-700 px-2 py-1 text-xs text-slate-200">
          {result.mode === 'mock'
            ? 'MOCK — simulated'
            : result.mode === 'live-demo'
              ? 'LIVE — backend (demo mode: simulated Nemotron)'
              : 'LIVE — backend / Nemotron'}
        </span>
      </div>
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
      <h3 className="mt-4 font-semibold text-slate-100">Evidence</h3>
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

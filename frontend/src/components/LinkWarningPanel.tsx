// Link-click warning panel (spec §7, Customer view, During state).
// The synthetic message's link is inert — it never navigates anywhere.
// Clicking it opens this panel instead. It explains in plain language why
// the link looks suspicious, what clicking a real one could do, and what
// to do instead. If the investigation is unfinished it says so plainly.
// It works in mock and live mode alike (frontend-only; no backend call).
// Dismissible, with a large labeled close control.

export type WarningAnalysisState =
  | { finished: false }
  | { finished: true; verdict: 'suspected_phishing' | 'insufficient_evidence' | 'legitimate_looking'; incomplete: boolean }

interface Props {
  /** The link the user tapped (shown as text only — never a live href). */
  linkUrl: string
  /** The organisation the message claimed to be from. */
  claimedOrg: string
  analysis: WarningAnalysisState
  onClose: () => void
}

export default function LinkWarningPanel({ linkUrl, claimedOrg, analysis, onClose }: Props) {
  let host = linkUrl
  try {
    host = new URL(linkUrl).host
  } catch {
    // Not a parseable URL — show the raw text.
  }
  return (
    <div
      role="alertdialog"
      aria-label="Warning: suspicious link"
      className="mt-3 rounded-lg border border-red-500 bg-red-950/60 p-4"
    >
      <p className="text-lg font-bold text-red-100">⛔ Stop — don’t tap this link</p>
      <p className="mt-2 text-sm text-red-100">
        You tapped the link in the message, but nothing happened: the link is inert in
        this demo and nothing was sent to <code className="rounded bg-red-900 px-1">{host}</code>.
        A real link like this would have taken you to a stranger’s website.
      </p>
      <p className="mt-2 text-sm font-semibold text-red-100">Why this link looks suspicious</p>
      <ul className="mt-1 list-disc pl-5 text-sm text-slate-100">
        <li>
          The address (<code className="rounded bg-slate-800 px-1">{host}</code>) does not
          match {claimedOrg}’s real website.
        </li>
        <li>The message pressures you to act fast instead of giving you time to check.</li>
        <li>It asks you to log in or pay through the link, rather than in the official app.</li>
      </ul>
      <p className="mt-2 text-sm font-semibold text-red-100">What a real click could do</p>
      <p className="mt-1 text-sm text-slate-100">
        It could open a fake login page that looks like your carrier’s and copies
        whatever password or code you type — which is how an attacker can take over
        an account or a session.
      </p>
      <p className="mt-2 text-sm font-semibold text-red-100">What to do instead</p>
      <p className="mt-1 text-sm text-slate-100">
        Close this message, open the carrier’s official app yourself (or type its real
        address), and check your account there. Report the message as spam if your
        phone offers that.
      </p>
      {analysis.finished ? (
        <p className="mt-3 rounded-lg bg-slate-800 p-2 text-sm text-slate-100">
          Our check has finished:{' '}
          {analysis.incomplete
            ? 'we couldn’t finish the investigation, so this link stays unproven — don’t trust it.'
            : analysis.verdict === 'suspected_phishing'
              ? 'this message looks like a scam. Do not use the link.'
              : analysis.verdict === 'insufficient_evidence'
                ? 'we couldn’t decide on the evidence available. Don’t use the link unless you can confirm it another way.'
                : 'this message looks okay on the evidence available — but stay careful, and still prefer the official app.'}
        </p>
      ) : (
        <p className="mt-3 rounded-lg bg-slate-800 p-2 text-sm text-amber-200">
          Analysis is not complete yet — we haven’t finished checking this message, so
          we can’t say whether this link is safe. Treat it as unproven until the check
          finishes.
        </p>
      )}
      <button
        type="button"
        onClick={onClose}
        aria-label="Close link warning"
        className="mt-3 rounded-lg bg-red-600 px-4 py-2 font-semibold text-white hover:bg-red-500"
      >
        Close warning
      </button>
    </div>
  )
}

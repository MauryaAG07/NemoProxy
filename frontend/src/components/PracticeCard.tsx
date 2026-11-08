// Practice card (spec §7, Customer view, Before state).
// One optional practice message about suspicious login requests, shown
// before any investigation starts. Plain language, clearly labelled as
// practice/demo, dismissible. It shows NO fabricated background-block
// count and makes NO claim that the real phone is protected — this is a
// practice example only, not a real message and not real protection.
export default function PracticeCard({ onDismiss }: { onDismiss: () => void }) {
  return (
    <div className="mt-3 rounded-lg border border-amber-500/60 bg-amber-950/40 p-4">
      <p className="flex flex-wrap items-center gap-2 text-sm font-bold text-amber-200">
        <span className="rounded-full bg-amber-500 px-2 py-0.5 text-xs font-bold text-black">
          PRACTICE — DEMO ONLY
        </span>
        Spot a suspicious login request
      </p>
      <p className="mt-2 text-sm text-slate-200">
        A real carrier will never text you a link and ask you to log in to fix your
        account. A suspicious login request usually arrives out of the blue, pressures
        you to act fast (“your line will be suspended”), and links to a web address
        that doesn’t match the company’s real site.
      </p>
      <p className="mt-2 text-sm text-slate-200">
        If you get one: don’t tap the link. Open the company’s official app yourself,
        or call the number printed on your bill — never the number in the message.
      </p>
      <p className="mt-2 text-xs text-slate-400">
        This is a practice example, not a real message. Nothing on this page protects
        your real phone or blocks real messages.
      </p>
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss practice message"
        className="mt-3 rounded-lg bg-slate-700 px-4 py-2 font-semibold text-white hover:bg-slate-600"
      >
        Dismiss practice message
      </button>
    </div>
  )
}

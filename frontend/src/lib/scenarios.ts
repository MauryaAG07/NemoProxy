import type { Verdict } from './types'

// Three selectable synthetic scenarios (spec §2).
// All people, accounts and domains are fictional. Domains use the
// reserved .example TLD, so they cannot be mistaken for real senders.
// EXPECTED LABELS ARE KEPT HERE, SEPARATE FROM AGENT INPUTS.
// The frontend sends only the scenario id + redacted text to the backend;
// it never sends `expectedVerdict` to Nemotron.

export interface Scenario {
  id: string
  title: string
  tag: string
  sender: string
  /** Synthetic message text, as "received" in the fictional carrier demo. */
  text: string
  expectedVerdict: Verdict
  expectedNote: string
}

export const SCENARIOS: Scenario[] = [
  {
    id: 'carrier-billing',
    title: 'Suspicious carrier billing message',
    tag: 'Suspicious',
    sender: 'NorthStar Mobile (claimed)',
    text: 'NorthStar Mobile: Your bill of $87.40 is overdue. Pay now to avoid service suspension: https://northstar-billing.example/pay?acct=NM-4821 — reply STOP to opt out.',
    expectedVerdict: 'suspected_phishing',
    expectedNote:
      'Link domain does not match the carrier’s known domain, urgency + payment request, and the billing link is on a look-alike host. Indicators only — not proof of a reverse proxy or a stolen session.',
  },
  {
    id: 'clinic-reminder',
    title: 'Legitimate-looking control message',
    tag: 'Control',
    sender: 'City Clinic (fictional)',
    text: 'City Clinic reminder: Hi Alex, your appointment is Tue 10:30 AM at 400 Example Ave. Reply C to confirm or call (555) 010-0142. No link in this message.',
    expectedVerdict: 'legitimate_looking',
    expectedNote:
      'No link, no payment or credential request, no urgency, and the callback number is consistent with the clinic. “Legitimate-looking” is not proof the sender is genuine.',
  },
  {
    id: 'package-ambiguous',
    title: 'Ambiguous message, conflicting evidence',
    tag: 'Ambiguous',
    sender: 'Unknown short-code (claimed delivery)',
    text: 'Your package could not be delivered. Update your address to reschedule: https://track-parcel.example/r/8f2k — Ref #PKG-9917. A second, different tracking link arrived minutes later.',
    expectedVerdict: 'insufficient_evidence',
    expectedNote:
      'A delivery link plus a conflicting second link, no verifiable sender, and no independent confirmation. There is not enough evidence to call this phishing or legitimate.',
  },
]

export function getScenario(id: string): Scenario {
  return SCENARIOS.find((s) => s.id === id) ?? SCENARIOS[0]
}

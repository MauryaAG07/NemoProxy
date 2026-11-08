import { getScenario } from './scenarios'
import type { InvestigationResult } from './types'

// Labelled mock investigation (spec §1: do not silently replace a failed
// live service with fabricated success). This runs ONLY when the backend
// is unreachable or VITE_MOCK_MODE=true, and every result it returns is
// marked mode:'mock' and shown in the UI as "MOCK — simulated".
// It mirrors the bounded Nemotron tool loop in shape only:
//  1. identify claimed org + requested action
//  2. select tools (reputation / brand-domain comparison — simulated fixtures)
//  3. assess from structured evidence, with uncertainty stated.
// It does NOT claim a live Nemotron call, a real reputation lookup, or
// proof of a reverse proxy / session theft.

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms))

export async function runMockInvestigation(
  incidentId: string,
  scenarioId: string,
  onStep: (step: string) => void,
): Promise<InvestigationResult> {
  const s = getScenario(scenarioId)
  onStep('Identifying claimed organisation and requested action…')
  await delay(600)
  onStep('Selecting tools: domain comparison + reputation check (simulated fixture)…')
  await delay(700)
  onStep('Assessing evidence — verdict is from the simulated fixture, not a live model…')
  await delay(700)

  const base = {
    incidentId,
    mode: 'mock' as const,
    claimedOrg: s.sender,
    requestedAction:
      scenarioId === 'carrier-billing'
        ? 'Pay an overdue bill via a link'
        : scenarioId === 'clinic-reminder'
          ? 'Confirm an appointment (no link, no payment)'
          : 'Update a delivery address via a link',
  }

  if (scenarioId === 'carrier-billing') {
    return {
      ...base,
      verdict: 'suspected_phishing',
      confidence: 'medium',
      summary:
        'Suspected phishing: urgent payment request with a link whose domain does not match the claimed carrier.',
      uncertainty:
        'Domain age, hosting and brand mismatch are indicators, not proof of a reverse proxy or a stolen session. A real reputation lookup was not run in mock mode.',
      evidence: [
        { id: 'e1', label: 'Brand / domain mismatch', detail: 'Link host northstar-billing.example is not the carrier’s known domain.', source: 'simulated', limitation: 'Does not prove the site is malicious, or that it is a proxy.' },
        { id: 'e2', label: 'Urgency + payment request', detail: '“Pay now to avoid suspension” pressures a quick click.', source: 'simulated', limitation: 'Legitimate bills also use urgency; urgency alone is not proof.' },
        { id: 'e3', label: 'Hosting / registration fixture', detail: 'Simulated fixture: recently-registered look-alike host (labelled simulated).', source: 'simulated', limitation: 'No real registration age was verified; do not cite this as actual age.' },
      ],
      reputationUrlNote: 'Reputation result, if any, applies to the redacted/modified URL, not the original.',
    }
  }
  if (scenarioId === 'clinic-reminder') {
    return {
      ...base,
      verdict: 'legitimate_looking',
      confidence: 'medium',
      summary: 'Legitimate-looking: no link, no payment or credential request, and no urgency.',
      uncertainty: '“Legitimate-looking” is not proof the sender is genuine — a spoofed reminder can look the same.',
      evidence: [
        { id: 'e1', label: 'No link or payment request', detail: 'Message asks only to confirm by reply or phone.', source: 'simulated', limitation: 'Absence of a link does not prove legitimacy.' },
        { id: 'e2', label: 'No urgency / threat', detail: 'No suspension, lockout, or deadline language.', source: 'simulated', limitation: 'Tone alone is weak evidence.' },
      ],
    }
  }
  return {
    ...base,
    verdict: 'insufficient_evidence',
    confidence: 'low',
    summary: 'Insufficient evidence: a delivery link plus a conflicting second link, with no verifiable sender.',
    uncertainty: 'Cannot call this phishing or legitimate on the evidence available. Independent confirmation (e.g. checking the order in the carrier/shop app, not via the link) would change this.',
    evidence: [
      { id: 'e1', label: 'Conflicting links', detail: 'Two different tracking links arrived for the same parcel.', source: 'simulated', limitation: 'Conflict is suspicious but does not prove either link is malicious.' },
      { id: 'e2', label: 'Unverifiable sender', detail: 'Short-code sender cannot be matched to a known delivery service.', source: 'simulated', limitation: 'Unknown sender is not proof of phishing.' },
      { id: 'e3', label: 'Missing evidence', detail: 'No order number that matches a known order, no brand/domain comparison available.', source: 'simulated', limitation: 'Missing evidence is a reason to wait, not a verdict.' },
    ],
  }
}

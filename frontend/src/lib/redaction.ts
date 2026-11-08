// Client-side PREVIEW of redaction only. The authoritative redaction
// happens server-side in backend/redaction.py BEFORE any third-party call
// (spec §3). This preview shows the user what will be sent, using the
// same placeholder style, and never logs the raw message.

export function redactPreview(text: string): string {
  return text
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[EMAIL REDACTED]')
    .replace(/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[PHONE REDACTED]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN REDACTED]')
    .replace(/(\?|&)(acct|token|session|code)=[^&\s]+/gi, '$1$2=[REDACTED]')
}

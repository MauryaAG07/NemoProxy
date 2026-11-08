import re
import uuid
import json
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from typing import Dict, Any, Tuple

from .config import settings
from .reputation import check_url_reputation
from .spacetime_client import (
    spacetime_create_incident,
    spacetime_update_incident,
    spacetime_add_evidence,
    spacetime_propose_action,
    get_sandbox_session
)
from .nvidia_client import run_nemotron_investigation

logger = logging.getLogger("nemo_proxy.incident")

# Ground truth scenario catalog (Expected labels stored separately from agent inputs)
SCENARIO_CATALOG: Dict[str, Dict[str, Any]] = {
    "phishing": {
        "id": "scenario_phishing_01",
        "name": "Suspicious Billing SMS (Urgent Payment)",
        "expected_label": "suspected_phishing",  # NEVER sent to Nemotron!
        "raw_message": (
            "T-Mobile Notice: Critical billing issue on line 214-555-0199 for user alex.mercer@gmail.com (SSN: 987-65-4321). "
            "Immediate payment required to prevent line termination. Review balance and authenticate immediately at "
            "https://t-mobile-billing-secure.com/auth/pay?session_token=sec_9f828a109e&account_ref=849204"
        ),
        "domain_fixture": {
            "domain": "t-mobile-billing-secure.com",
            "is_simulated": True,
            "domain_age_days": 3,
            "registered_date": "2026-11-04 (Simulated Fixture)",
            "registrar": "Privacy Protect, LLC (Hostinger)",
            "hosting_asn": "AS16276 (OVH SAS)",
            "hosting_provider": "Budget VPS / Cloud",
            "brand_alignment": "Deceptive match: Uses 't-mobile' brand string in domain name, but registrant and ASN have no affiliation with T-Mobile USA, Inc. (Official ASN: AS21928)",
            "reverse_proxy_indicator_note": "Indicator of deception: Brand mismatch and 3-day domain age indicate phishing risk. Note: Domain age alone does not technically prove reverse-proxy architecture or session theft."
        }
    },
    "legitimate": {
        "id": "scenario_legitimate_02",
        "name": "Legitimate Control SMS (Payment Receipt)",
        "expected_label": "benign_indicator",  # NEVER sent to Nemotron!
        "raw_message": (
            "T-Mobile: Alex, your monthly recurring payment of $85.00 for line 214-555-0199 was processed successfully. "
            "View your itemized billing statement at https://my.t-mobile.com/billing/statement?cycle=202611"
        ),
        "domain_fixture": {
            "domain": "my.t-mobile.com",
            "is_simulated": True,
            "domain_age_days": 9860,
            "registered_date": "1999-10-18 (Simulated Fixture)",
            "registrar": "MarkMonitor, Inc.",
            "hosting_asn": "AS21928 (T-Mobile USA, Inc.)",
            "hosting_provider": "Official Enterprise Infrastructure",
            "brand_alignment": "Verified authentic: my.t-mobile.com is an official authenticated sub-domain registered directly to T-Mobile USA, Inc.",
            "reverse_proxy_indicator_note": "Authentic official carrier host with multi-decade registration history."
        }
    },
    "ambiguous": {
        "id": "scenario_ambiguous_03",
        "name": "Ambiguous Affiliate SMS (Conflicting Evidence)",
        "expected_label": "insufficient_evidence",  # NEVER sent to Nemotron!
        "raw_message": (
            "T-Mobile Rewards: Line 214-555-0199 has been selected for an accessories voucher. Details sent to alex.mercer@gmail.com. "
            "Claim your partner voucher at https://tmobile-promotions.partner-rewards.net/claim?promo_code=FALL26"
        ),
        "domain_fixture": {
            "domain": "tmobile-promotions.partner-rewards.net",
            "is_simulated": True,
            "domain_age_days": 145,
            "registered_date": "2026-06-15 (Simulated Fixture)",
            "registrar": "Cloudflare, Inc.",
            "hosting_asn": "AS13335 (Cloudflare CDN / AWS)",
            "hosting_provider": "Cloudflare Reverse Proxy / CDN",
            "brand_alignment": "Ambiguous affiliate: Apex domain is 'partner-rewards.net' with carrier name prepended. May be an authorized partner vendor or an unvetted marketing campaign.",
            "reverse_proxy_indicator_note": "Conflicting evidence: Moderate domain age, unlisted on threat feeds, third-party apex domain. Insufficient evidence to classify as malicious or safe."
        }
    }
}

# Regex patterns for server-side PII scrubbing
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_REGEX = re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

def sanitize_url(raw_url: str) -> Tuple[str, bool, str]:
    """
    Strips sensitive tokens/credentials from URL query parameters.
    Returns: (sanitized_url, was_modified, domain)
    """
    try:
        parsed = urlparse(raw_url)
        domain = parsed.netloc.lower()
        if not domain and parsed.path:
            domain = parsed.path.split('/')[0]

        was_modified = False
        if parsed.query:
            query_dict = parse_qs(parsed.query, keep_blank_values=True)
            sensitive_keys = {'session_token', 'token', 'auth', 'account_ref', 'uid', 'key', 'secret', 'code', 'promo_code'}
            new_query = {}
            for k, vals in query_dict.items():
                if k.lower() in sensitive_keys:
                    new_query[k] = ['[REDACTED_TOKEN]']
                    was_modified = True
                else:
                    new_query[k] = vals
            encoded_query = urlencode(new_query, doseq=True)
            encoded_query = unquote(encoded_query)
            sanitized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, encoded_query, parsed.fragment))
            return sanitized, was_modified, domain
        return raw_url, False, domain
    except Exception:
        return raw_url, False, ""

def redact_message(message: str) -> Dict[str, Any]:
    """
    Applies server-side redaction before third-party calls.
    Returns sanitized text, redacted items manifest, and URL metadata.
    """
    redacted_items = []

    # 1. Redact Emails
    def _email_sub(match):
        redacted_items.append({"type": "email", "placeholder": "[REDACTED_EMAIL]"})
        return "[REDACTED_EMAIL]"
    step1 = EMAIL_REGEX.sub(_email_sub, message)

    # 2. Redact Phone Numbers
    def _phone_sub(match):
        redacted_items.append({"type": "phone", "placeholder": "[REDACTED_PHONE]"})
        return "[REDACTED_PHONE]"
    step2 = PHONE_REGEX.sub(_phone_sub, step1)

    # 3. Redact SSNs
    def _ssn_sub(match):
        redacted_items.append({"type": "ssn", "placeholder": "[REDACTED_SSN]"})
        return "[REDACTED_SSN]"
    step3 = SSN_REGEX.sub(_ssn_sub, step2)

    # 4. Sanitize URLs
    detected_urls = []
    def _url_sub(match):
        orig_url = match.group(0)
        sanitized_url, was_modified, domain = sanitize_url(orig_url)
        detected_urls.append({
            "original_url": orig_url,
            "sanitized_url": sanitized_url,
            "domain": domain,
            "was_modified": was_modified,
            "reputation_disclaimer": (
                "Reputation query evaluated against sanitized URL; sensitive embedded parameters removed."
                if was_modified else "Reputation query evaluated on standard URL."
            )
        })
        return sanitized_url

    sanitized_message = URL_REGEX.sub(_url_sub, step3)

    return {
        "sanitized_message": sanitized_message,
        "redacted_items": redacted_items,
        "detected_urls": detected_urls,
        "pipeline_description": "Server-side redaction before third-party calls (not on-device processing or complete anonymization)."
    }

async def execute_investigation_pipeline(incident_id: str, scenario_key: str):
    """
    Executes the full asynchronous investigation task:
    1. Loads scenario fixture (keeping expected verdict strictly decoupled from Nemotron).
    2. Performs server-side redaction.
    3. Records incident and redaction evidence in SpacetimeDB.
    4. Runs Nemotron's 6-tool bounded investigation loop.
    5. Commits evidence items, proposed actions, and honest verdict to SpacetimeDB.
    """
    scenario = SCENARIO_CATALOG.get(scenario_key)
    if not scenario:
        logger.error(f"Scenario {scenario_key} not found")
        return

    raw_message = scenario["raw_message"]

    # Step 1: Server-Side Redaction
    redaction_result = redact_message(raw_message)
    sanitized_msg = redaction_result["sanitized_message"]

    # Step 2: Initialize SpacetimeDB Incident
    await spacetime_create_incident(
        incident_id=incident_id,
        scenario_id=scenario["id"],
        redacted_message=sanitized_msg
    )

    # Step 3: Record Redaction Telemetry as Evidence
    ev_redact_id = f"ev_redact_{uuid.uuid4().hex[:8]}"
    await spacetime_add_evidence(
        evidence_id=ev_redact_id,
        incident_id=incident_id,
        source_tool="server_side_sanitizer",
        is_simulated=False,
        summary=f"Redacted {len(redaction_result['redacted_items'])} sensitive identifier(s) and scrubbed query credentials before Nemotron call.",
        raw_json=redaction_result
    )

    # Step 4: Extract Primary URL & Domain
    primary_domain = scenario["domain_fixture"]["domain"]
    primary_url = None
    if redaction_result["detected_urls"]:
        primary_url = redaction_result["detected_urls"][0]["sanitized_url"]

    # Step 5: Execute Nemotron Bounded Tool-Calling Loop
    logger.info(f"Dispatching Nemotron investigation for incident {incident_id}...")
    investigation_result = await run_nemotron_investigation(
        incident_id=incident_id,
        sanitized_message=sanitized_msg,
        primary_domain=primary_domain,
        domain_fixture=scenario["domain_fixture"],
        primary_url=primary_url,
        scenario_key=scenario_key
    )

    # Step 6: Commit Final Verdict to SpacetimeDB
    await spacetime_update_incident(
        incident_id=incident_id,
        status="assessed",
        verdict=investigation_result["verdict"],
        confidence_band=investigation_result["confidence_band"],
        summary=investigation_result["summary"]
    )
    logger.info(f"Incident {incident_id} completed with verdict: {investigation_result['verdict']}")

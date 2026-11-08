import os
import json
import uuid
import logging
from typing import Dict, Any, List, Optional
import httpx

from .config import settings
from .reputation import check_url_reputation
from .spacetime_client import (
    spacetime_add_evidence,
    spacetime_propose_action,
    get_sandbox_session,
    get_current_state
)

logger = logging.getLogger("nemo_proxy.nvidia")

RECOVERY_CHECKLIST_CATALOG = [
    {"id": "step_revoke_tokens", "label": "Revoke active carrier web and app tokens", "recommended": True},
    {"id": "step_enable_sim_lock", "label": "Enable SIM protection / Port-out freeze", "recommended": True},
    {"id": "step_rotate_pin", "label": "Rotate carrier account PIN and password", "recommended": True},
    {"id": "step_review_call_forwarding", "label": "Verify unconditional call forwarding rules", "recommended": False},
    {"id": "step_notify_device", "label": "Send security push alert to primary registered device", "recommended": True}
]

INVESTIGATION_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_domain_context",
            "description": "Retrieve infrastructure registration age, registrar, ASN, and brand affiliation for a domain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Fully qualified domain name to inspect"}
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_url_reputation",
            "description": "Query URL reputation provider (Google Web Risk). Note: Unlisted status does not guarantee safety.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to inspect for reputation flags"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_incident_evidence",
            "description": "Query all correlated evidence items currently recorded for this incident in SpacetimeDB.",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string", "description": "Authoritative incident ID"}
                },
                "required": ["incident_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_sandbox_session_status",
            "description": "Retrieve the current sandbox session status and SIM freeze status of the simulated carrier subscriber.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "propose_response_action",
            "description": "Propose an incident mitigation action (e.g. revoke session, freeze SIM) without executing it.",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string"},
                    "action_type": {"type": "string", "enum": ["propose_session_revocation", "propose_sim_freeze", "propose_subscriber_alert"]},
                    "reason": {"type": "string", "description": "Evidence-backed rationale for proposing this action"}
                },
                "required": ["incident_id", "action_type", "reason"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "select_recovery_steps",
            "description": "Select relevant recovery steps from the reviewed carrier security checklist catalog.",
            "parameters": {
                "type": "object",
                "properties": {
                    "step_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of step IDs to recommend"
                    }
                },
                "required": ["step_ids"]
            }
        }
    }
]

async def dispatch_tool_execution(
    tool_name: str,
    args: Dict[str, Any],
    incident_id: str,
    domain_fixture: Dict[str, Any],
    scenario_key: str
) -> Dict[str, Any]:
    """Executes an individual tool call and records it in authoritative SpacetimeDB storage."""
    evidence_id = f"ev_{tool_name}_{uuid.uuid4().hex[:8]}"

    if tool_name == "get_domain_context":
        domain = args.get("domain", domain_fixture.get("domain", "unknown"))
        result = {
            "domain": domain,
            "domain_age_days": domain_fixture.get("domain_age_days"),
            "registered_date": domain_fixture.get("registered_date"),
            "registrar": domain_fixture.get("registrar"),
            "hosting_asn": domain_fixture.get("hosting_asn"),
            "brand_alignment": domain_fixture.get("brand_alignment"),
            "reverse_proxy_indicator_note": domain_fixture.get("reverse_proxy_indicator_note"),
            "is_simulated": domain_fixture.get("is_simulated", True)
        }
        summary = f"Domain '{domain}' inspected: Age {result['domain_age_days']} days, Registrar: {result['registrar']}. {result['brand_alignment']}"
        await spacetime_add_evidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            source_tool="get_domain_context",
            is_simulated=result["is_simulated"],
            summary=summary,
            raw_json=result
        )
        return {"evidence_id": evidence_id, "result": result}

    elif tool_name == "check_url_reputation":
        url = args.get("url", "")
        rep_data = await check_url_reputation(url, scenario_type=scenario_key)
        summary = f"Reputation Provider ({rep_data['provider']}): Verdict '{rep_data['verdict']}'. {rep_data['explanation']}"
        await spacetime_add_evidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            source_tool="check_url_reputation",
            is_simulated=rep_data["is_simulated"],
            summary=summary,
            raw_json=rep_data
        )
        return {"evidence_id": evidence_id, "result": rep_data}

    elif tool_name == "get_incident_evidence":
        current_state = get_current_state()
        items = [e for e in current_state["evidence_items"] if e["incident_id"] == incident_id]
        return {"evidence_id": evidence_id, "evidence_count": len(items), "items": items}

    elif tool_name == "get_sandbox_session_status":
        sess = get_sandbox_session()
        summary = f"Sandbox subscriber status: {sess.get('status')} on {sess.get('device_label')}. SIM Freeze: {sess.get('sim_freeze_enabled')}."
        await spacetime_add_evidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            source_tool="get_sandbox_session_status",
            is_simulated=True,
            summary=summary,
            raw_json=sess
        )
        return {"evidence_id": evidence_id, "session": sess}

    elif tool_name == "propose_response_action":
        action_type = args.get("action_type", "propose_session_revocation")
        reason = args.get("reason", "Suspicious smishing indicators observed.")
        action_id = f"act_{uuid.uuid4().hex[:8]}"
        await spacetime_propose_action(
            action_id=action_id,
            incident_id=incident_id,
            action_type=action_type,
            reason=reason
        )
        await spacetime_add_evidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            source_tool="propose_response_action",
            is_simulated=True,
            summary=f"Proposed action '{action_type}': {reason}",
            raw_json={"action_id": action_id, "action_type": action_type, "reason": reason}
        )
        return {"evidence_id": evidence_id, "action_id": action_id, "status": "proposed"}

    elif tool_name == "select_recovery_steps":
        step_ids = args.get("step_ids", ["step_revoke_tokens", "step_enable_sim_lock", "step_rotate_pin"])
        selected = [item for item in RECOVERY_CHECKLIST_CATALOG if item["id"] in step_ids]
        summary = f"Selected {len(selected)} recovery checklist items for subscriber guidance."
        await spacetime_add_evidence(
            evidence_id=evidence_id,
            incident_id=incident_id,
            source_tool="select_recovery_steps",
            is_simulated=True,
            summary=summary,
            raw_json={"selected_steps": selected}
        )
        return {"evidence_id": evidence_id, "selected_steps": selected}

    else:
        return {"error": f"Unknown tool {tool_name}"}


async def run_nemotron_investigation(
    incident_id: str,
    sanitized_message: str,
    primary_domain: str,
    domain_fixture: Dict[str, Any],
    primary_url: Optional[str],
    scenario_key: str
) -> Dict[str, Any]:
    """
    Executes a bounded investigation loop.
    If NVIDIA Nemotron API key is configured and not in DEMO_MODE, queries the hosted model.
    Otherwise executes the bounded tool workflow deterministically, labeling each fixture result.
    """
    use_live_nemotron = settings.has_nvidia_creds() and not settings.demo_mode

    if use_live_nemotron:
        try:
            return await _run_live_nemotron_loop(
                incident_id=incident_id,
                sanitized_message=sanitized_message,
                primary_domain=primary_domain,
                domain_fixture=domain_fixture,
                primary_url=primary_url,
                scenario_key=scenario_key
            )
        except Exception as e:
            logger.error(f"Live Nemotron API call failed ({e}). Falling back to bounded simulation loop with explicit labeling.")

    # Bounded simulation workflow (reproducible, honest, citing evidence IDs)
    return await _run_simulated_bounded_loop(
        incident_id=incident_id,
        sanitized_message=sanitized_message,
        primary_domain=primary_domain,
        domain_fixture=domain_fixture,
        primary_url=primary_url,
        scenario_key=scenario_key
    )


async def _run_simulated_bounded_loop(
    incident_id: str,
    sanitized_message: str,
    primary_domain: str,
    domain_fixture: Dict[str, Any],
    primary_url: Optional[str],
    scenario_key: str
) -> Dict[str, Any]:
    """
    Executes the exact 6-step bounded tool workflow:
    1. Inspects domain context.
    2. Inspects URL reputation.
    3. Checks sandbox session status.
    4. Proposes response actions.
    5. Selects recovery checklist items.
    6. Produces honest assessment distinguishing suspected phishing vs insufficient evidence vs compromise.
    """
    # 1. Domain Context Tool
    dom_res = await dispatch_tool_execution(
        "get_domain_context",
        {"domain": primary_domain},
        incident_id,
        domain_fixture,
        scenario_key
    )
    dom_ev_id = dom_res["evidence_id"]

    # 2. URL Reputation Tool
    rep_ev_id = None
    if primary_url:
        rep_res = await dispatch_tool_execution(
            "check_url_reputation",
            {"url": primary_url},
            incident_id,
            domain_fixture,
            scenario_key
        )
        rep_ev_id = rep_res["evidence_id"]

    # 3. Sandbox Session Status Tool
    sess_res = await dispatch_tool_execution(
        "get_sandbox_session_status",
        {},
        incident_id,
        domain_fixture,
        scenario_key
    )
    sess_ev_id = sess_res["evidence_id"]

    # 4. Propose Actions Tool
    if scenario_key == "phishing":
        await dispatch_tool_execution(
            "propose_response_action",
            {
                "incident_id": incident_id,
                "action_type": "propose_session_revocation",
                "reason": "Deceptive billing domain with brand mismatch poses credential/session theft risk."
            },
            incident_id,
            domain_fixture,
            scenario_key
        )
        await dispatch_tool_execution(
            "propose_response_action",
            {
                "incident_id": incident_id,
                "action_type": "propose_sim_freeze",
                "reason": "Proactive protection against potential SIM-swap or takeover."
            },
            incident_id,
            domain_fixture,
            scenario_key
        )
    elif scenario_key == "ambiguous":
        await dispatch_tool_execution(
            "propose_response_action",
            {
                "incident_id": incident_id,
                "action_type": "propose_subscriber_alert",
                "reason": "Unverified affiliate link requires cautionary subscriber advisory without destructive revocation."
            },
            incident_id,
            domain_fixture,
            scenario_key
        )

    # 5. Recovery Checklist Tool
    await dispatch_tool_execution(
        "select_recovery_steps",
        {"step_ids": ["step_revoke_tokens", "step_enable_sim_lock", "step_rotate_pin", "step_notify_device"]},
        incident_id,
        domain_fixture,
        scenario_key
    )

    # 6. Generate Honest Verdict & Assessment
    evidence_citations = [dom_ev_id]
    if rep_ev_id:
        evidence_citations.append(rep_ev_id)
    evidence_citations.append(sess_ev_id)

    if scenario_key == "phishing":
        verdict = "suspected_phishing"
        confidence_band = "high"
        summary = (
            f"Assessment based on [{', '.join(evidence_citations)}]: Claimed carrier billing notification directs to "
            f"unaffiliated domain '{primary_domain}' registered 3 days ago. "
            f"UNCERTAINTY BOUNDARY: Domain registration age and brand mismatch are strong indicators of smishing; "
            f"they do not provide mathematical proof that a reverse-proxy server is actively running or that the user's "
            f"session has already been exfiltrated. Session revocation is proposed as an authoritative defensive countermeasure."
        )
    elif scenario_key == "legitimate":
        verdict = "benign_indicator"
        confidence_band = "high"
        summary = (
            f"Assessment based on [{', '.join(evidence_citations)}]: Message references official enterprise carrier portal "
            f"'{primary_domain}' (age {domain_fixture.get('domain_age_days')} days, registered to MarkMonitor). "
            f"No brand mismatch or deceptive urgency detected."
        )
    else:  # ambiguous
        verdict = "insufficient_evidence"
        confidence_band = "medium"
        summary = (
            f"Assessment based on [{', '.join(evidence_citations)}]: Message points to third-party subdomain "
            f"'{primary_domain}'. Domain age is moderate ({domain_fixture.get('domain_age_days')} days) and provider "
            f"reputation is unlisted. UNCERTAINTY BOUNDARY: Domain mismatch could indicate an unauthorized smishing attempt "
            f"OR an authorized promotional affiliate vendor. Evidence is insufficient to verify safety or prove malicious intent."
        )

    return {
        "verdict": verdict,
        "confidence_band": confidence_band,
        "summary": summary,
        "evidence_citations": evidence_citations
    }


async def _run_live_nemotron_loop(
    incident_id: str,
    sanitized_message: str,
    primary_domain: str,
    domain_fixture: Dict[str, Any],
    primary_url: Optional[str],
    scenario_key: str
) -> Dict[str, Any]:
    """Live Nemotron tool-calling loop using OpenAI-compatible API."""
    api_key = settings.nvidia_api_key
    base_url = settings.nvidia_base_url.rstrip('/')
    model_id = settings.nvidia_model_id
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    system_prompt = (
        "You are NemoProxy, an autonomous AI telecom security analyst investigating synthetic SMS messages. "
        "Your task: Identify claimed organizations and requested actions, then invoke tools to evaluate domain context, "
        "reputation, and sandbox session state. "
        "CRITICAL POLICY: Distinguish between Suspected Phishing, Insufficient Evidence, and Benign Indicators. "
        "Acknowledge uncertainty: domain age and brand mismatch are phishing indicators, NOT proof that a reverse proxy "
        "exists or that a session was stolen. Cite evidence IDs in your final assessment."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Investigate SMS for Incident {incident_id}: '{sanitized_message}'. Primary domain: '{primary_domain}'."}
    ]

    max_rounds = 4
    for round_idx in range(max_rounds):
        payload = {
            "model": model_id,
            "messages": messages,
            "tools": INVESTIGATION_TOOLS,
            "tool_choice": "auto"
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{base_url}/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]
        msg = choice["message"]
        tool_calls = msg.get("tool_calls")

        if tool_calls:
            messages.append(msg)
            for tc in tool_calls:
                fn_name = tc["function"]["name"]
                fn_args = json.loads(tc["function"]["arguments"] or "{}")
                tool_output = await dispatch_tool_execution(
                    fn_name,
                    fn_args,
                    incident_id,
                    domain_fixture,
                    scenario_key
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "name": fn_name,
                    "content": json.dumps(tool_output)
                })
        else:
            final_text = msg.get("content", "")
            verdict = "insufficient_evidence"
            confidence = "medium"
            if "suspected phishing" in final_text.lower():
                verdict = "suspected_phishing"
                confidence = "high"
            elif "benign" in final_text.lower() or "legitimate" in final_text.lower():
                verdict = "benign_indicator"
                confidence = "high"

            return {
                "verdict": verdict,
                "confidence_band": confidence,
                "summary": final_text,
                "evidence_citations": []
            }

    return await _run_simulated_bounded_loop(
        incident_id, sanitized_message, primary_domain, domain_fixture, primary_url, scenario_key
    )

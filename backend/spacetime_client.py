import time
import json
import logging
from typing import Dict, Any, List, Optional
import httpx
from .config import settings

logger = logging.getLogger("nemo_proxy.spacetime")

# Authoritative In-Memory State Store (Mirrors SpacetimeDB schema exactly)
# If live SpacetimeDB is connected, changes are dispatched to both local cache and SpacetimeDB reducer endpoints.
_STATE = {
    "incidents": {},         # Dict[str, Dict]
    "evidence_items": [],    # List[Dict]
    "proposed_actions": [],  # List[Dict]
    "sandbox_sessions": {
        "sess_demo_carrier_01": {
            "session_id": "sess_demo_carrier_01",
            "account_id": "acct_tm_94821",
            "device_label": "Samsung Galaxy S24 (eSIM - T-Mobile)",
            "phone_masked": "+1 (214) •••-4102",
            "status": "active",  # "active" | "compromised_sim" | "revoked"
            "sim_freeze_enabled": False,
            "updated_at": int(time.time() * 1000)
        }
    }
}

async def spacetime_create_incident(incident_id: str, scenario_id: str, redacted_message: str):
    record = {
        "incident_id": incident_id,
        "scenario_id": scenario_id,
        "redacted_message": redacted_message,
        "status": "investigating",
        "verdict": "pending",
        "confidence_band": "low",
        "summary": "Investigation queued. Nemotron tool loop starting.",
        "created_at": int(time.time() * 1000)
    }
    _STATE["incidents"][incident_id] = record

    if settings.has_spacetime_creds() and not settings.demo_mode:
        url = f"{settings.spacetime_host.rstrip('/')}/api/{settings.spacetime_db}/reducer/create_incident"
        headers = {"Authorization": f"Bearer {settings.spacetime_token}", "Content-Type": "application/json"}
        payload = {"incident_id": incident_id, "scenario_id": scenario_id, "redacted_message": redacted_message}
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(url, json=payload, headers=headers)
        except Exception as e:
            logger.warning(f"SpacetimeDB call failed: {e}. Preserving in-memory authoritative state.")

async def spacetime_update_incident(incident_id: str, status: str, verdict: str, confidence_band: str, summary: str):
    if incident_id in _STATE["incidents"]:
        _STATE["incidents"][incident_id].update({
            "status": status,
            "verdict": verdict,
            "confidence_band": confidence_band,
            "summary": summary
        })

    if settings.has_spacetime_creds() and not settings.demo_mode:
        url = f"{settings.spacetime_host.rstrip('/')}/api/{settings.spacetime_db}/reducer/update_incident_verdict"
        headers = {"Authorization": f"Bearer {settings.spacetime_token}", "Content-Type": "application/json"}
        payload = {
            "incident_id": incident_id,
            "status": status,
            "verdict": verdict,
            "confidence_band": confidence_band,
            "summary": summary
        }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(url, json=payload, headers=headers)
        except Exception as e:
            logger.warning(f"SpacetimeDB call failed: {e}")

async def spacetime_add_evidence(
    evidence_id: str,
    incident_id: str,
    source_tool: str,
    is_simulated: bool,
    summary: str,
    raw_json: Any
):
    item = {
        "evidence_id": evidence_id,
        "incident_id": incident_id,
        "source_tool": source_tool,
        "is_simulated": is_simulated,
        "summary": summary,
        "raw_json": json.dumps(raw_json) if not isinstance(raw_json, str) else raw_json,
        "created_at": int(time.time() * 1000)
    }
    _STATE["evidence_items"].append(item)

    if settings.has_spacetime_creds() and not settings.demo_mode:
        url = f"{settings.spacetime_host.rstrip('/')}/api/{settings.spacetime_db}/reducer/add_evidence"
        headers = {"Authorization": f"Bearer {settings.spacetime_token}", "Content-Type": "application/json"}
        payload = item
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(url, json=payload, headers=headers)
        except Exception as e:
            logger.warning(f"SpacetimeDB call failed: {e}")

async def spacetime_propose_action(
    action_id: str,
    incident_id: str,
    action_type: str,
    reason: str
):
    item = {
        "action_id": action_id,
        "incident_id": incident_id,
        "action_type": action_type,
        "reason": reason,
        "status": "proposed"
    }
    _STATE["proposed_actions"].append(item)

    if settings.has_spacetime_creds() and not settings.demo_mode:
        url = f"{settings.spacetime_host.rstrip('/')}/api/{settings.spacetime_db}/reducer/propose_action"
        headers = {"Authorization": f"Bearer {settings.spacetime_token}", "Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(url, json=item, headers=headers)
        except Exception as e:
            logger.warning(f"SpacetimeDB call failed: {e}")

def get_current_state() -> Dict[str, Any]:
    """Returns authoritative snapshot for React UI synchronization."""
    return {
        "incidents": list(_STATE["incidents"].values()),
        "evidence_items": _STATE["evidence_items"],
        "proposed_actions": _STATE["proposed_actions"],
        "sandbox_sessions": list(_STATE["sandbox_sessions"].values())
    }

def get_sandbox_session(session_id: str = "sess_demo_carrier_01") -> Dict[str, Any]:
    return _STATE["sandbox_sessions"].get(session_id, {})

def trigger_compromise(session_id: str = "sess_demo_carrier_01"):
    sess = _STATE["sandbox_sessions"].get(session_id)
    if sess:
        sess["status"] = "compromised_sim"
        sess["updated_at"] = int(time.time() * 1000)
    return sess

def revoke_session(session_id: str = "sess_demo_carrier_01", reason: str = "Operator enforced session invalidation"):
    sess = _STATE["sandbox_sessions"].get(session_id)
    if sess:
        sess["status"] = "revoked"
        sess["updated_at"] = int(time.time() * 1000)
        sess["revocation_reason"] = reason
    return sess

def toggle_sim_freeze(session_id: str = "sess_demo_carrier_01"):
    sess = _STATE["sandbox_sessions"].get(session_id)
    if sess:
        sess["sim_freeze_enabled"] = not sess["sim_freeze_enabled"]
        sess["updated_at"] = int(time.time() * 1000)
    return sess

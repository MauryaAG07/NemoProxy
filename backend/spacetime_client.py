import time
import json
import logging
from typing import Dict, Any, List, Optional
import httpx
from .config import settings

logger = logging.getLogger("nemo_proxy.spacetime")

# In-memory mirror of the SpacetimeDB schema. In demo mode this IS the
# state shown by GET /api/state (labelled as such). In live mode the
# mirror is kept for resilience, but GET /api/state reads back from
# SpacetimeDB itself; the mirror is only a fallback if that read fails.
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

# SQL read-back queries for live mode (SpacetimeDB 2.x HTTP API).
_LIVE_QUERIES = {
    "incidents": (
        "SELECT incident_id, scenario_id, redacted_message, status, verdict,"
        " confidence_band, summary, created_at FROM incident"
    ),
    "evidence_items": (
        "SELECT evidence_id, incident_id, source_tool, is_simulated, summary,"
        " raw_json FROM evidence_item"
    ),
    "proposed_actions": (
        "SELECT action_id, incident_id, action_type, reason, status FROM proposed_action"
    ),
    "sandbox_sessions": (
        "SELECT session_id, account_id, device_label, phone_masked, status,"
        " sim_freeze_enabled, revocation_reason, updated_at FROM sandbox_session"
    ),
}

# Columns the module stores as SpacetimeDB timestamps. The SQL API returns
# them as single-element arrays [micros_since_unix_epoch]; normalize to ms.
_TIMESTAMP_COLUMNS = {"created_at", "updated_at"}

_warned_no_identity = False


def _live_enabled() -> bool:
    """True only when live SpacetimeDB calls can actually be addressed.

    The SpacetimeDB 2.x v1 endpoint addresses databases by identity, not by
    name, so a configured identity is required. If live mode was requested
    (DEMO_MODE=false + token set) but no identity is configured, warn once
    and fall back to the in-memory store — never silently claim a live
    write happened.
    """
    global _warned_no_identity
    if settings.demo_mode:
        return False
    if not settings.has_spacetime_creds():
        return False
    if not settings.has_spacetime_identity():
        if not _warned_no_identity:
            logger.warning(
                "Live SpacetimeDB requested but SPACETIME_DB_IDENTITY is not set; "
                "reducer calls cannot be addressed. Falling back to the in-memory "
                "store (labelled as such in /api/state)."
            )
            _warned_no_identity = True
        return False
    return True


def _reducer_url(reducer_name: str) -> str:
    # SpacetimeDB 2.x: POST {host}/v1/database/{identity}/call/{reducer}
    # with a JSON object of the reducer's arguments. The old
    # {host}/api/{db}/reducer/{name} path returns 404 on a 2.x server.
    return (
        f"{settings.spacetime_host.rstrip('/')}/v1/database/"
        f"{settings.spacetime_db_identity}/call/{reducer_name}"
    )


def _sql_url() -> str:
    return (
        f"{settings.spacetime_host.rstrip('/')}/v1/database/"
        f"{settings.spacetime_db_identity}/sql"
    )


def _headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if settings.spacetime_token:
        headers["Authorization"] = f"Bearer {settings.spacetime_token}"
    return headers


def _spacetime_http_client() -> httpx.AsyncClient:
    """httpx client for SpacetimeDB calls.

    trust_env=False: the SpacetimeDB host is a local/private address that
    must never go through an egress proxy, and httpx's default trust_env
    parsing of proxy env vars (e.g. bracketed IPv6 entries in NO_PROXY)
    can raise InvalidURL before any request is made.
    """
    return httpx.AsyncClient(timeout=5, trust_env=False)


async def _call_reducer(reducer_name: str, payload: Dict[str, Any]) -> bool:
    """Call one SpacetimeDB reducer. Returns True on success, False on any
    failure (logged). Callers never treat a False here as a live write."""
    try:
        async with _spacetime_http_client() as client:
            resp = await client.post(_reducer_url(reducer_name), json=payload, headers=_headers())
            resp.raise_for_status()
        return True
    except Exception as e:
        logger.warning(f"SpacetimeDB reducer '{reducer_name}' call failed: {e}. In-memory state preserved.")
        return False


def _normalize_row(columns: List[str], row: List[Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for col, value in zip(columns, row):
        if col in _TIMESTAMP_COLUMNS and isinstance(value, list) and value and isinstance(value[0], (int, float)):
            out[col] = int(value[0] // 1000)
        else:
            out[col] = value
    return out


async def _query_sql(query: str) -> Optional[List[Dict[str, Any]]]:
    """Run one SQL query against the live database. Returns rows as dicts,
    or None if the query failed."""
    try:
        async with _spacetime_http_client() as client:
            resp = await client.post(_sql_url(), content=query, headers=_headers())
            resp.raise_for_status()
            data = resp.json()
        if not data:
            return []
        result = data[0]
        columns = [el["name"].get("some") for el in result["schema"]["elements"]]
        return [_normalize_row(columns, row) for row in result.get("rows", [])]
    except Exception as e:
        logger.warning(f"SpacetimeDB SQL read-back failed: {e}")
        return None


async def spacetime_create_incident(incident_id: str, scenario_id: str, redacted_message: str):
    record = {
        "incident_id": incident_id,
        "scenario_id": scenario_id,
        "redacted_message": redacted_message,
        "status": "investigating",
        "verdict": "pending",
        "confidence_band": "low",
        "summary": "Investigation queued. Nemotron tool loop starting.",
        "created_at": int(time.time() * 1000),
        "live_failure": False,
    }
    _STATE["incidents"][incident_id] = record

    if _live_enabled():
        await _call_reducer("create_incident", {
            "incident_id": incident_id,
            "scenario_id": scenario_id,
            "redacted_message": redacted_message,
        })


async def spacetime_update_incident(
    incident_id: str,
    status: str,
    verdict: str,
    confidence_band: str,
    summary: str,
    live_failure: bool = False,
):
    if incident_id in _STATE["incidents"]:
        _STATE["incidents"][incident_id].update({
            "status": status,
            "verdict": verdict,
            "confidence_band": confidence_band,
            "summary": summary,
            "live_failure": live_failure,
        })

    if _live_enabled():
        # The module's update_incident_verdict reducer has no live_failure
        # field; the flag lives in the mirror and is merged into /api/state.
        await _call_reducer("update_incident_verdict", {
            "incident_id": incident_id,
            "status": status,
            "verdict": verdict,
            "confidence_band": confidence_band,
            "summary": summary,
        })


async def spacetime_add_evidence(
    evidence_id: str,
    incident_id: str,
    source_tool: str,
    is_simulated: bool,
    summary: str,
    raw_json: Any
):
    raw_json_str = raw_json if isinstance(raw_json, str) else json.dumps(raw_json)
    item = {
        "evidence_id": evidence_id,
        "incident_id": incident_id,
        "source_tool": source_tool,
        "is_simulated": is_simulated,
        "summary": summary,
        "raw_json": raw_json_str,
        "created_at": int(time.time() * 1000)
    }
    _STATE["evidence_items"].append(item)

    if _live_enabled():
        # Send ONLY the fields the module's add_evidence reducer declares.
        # In particular, do NOT send created_at — the module has no such
        # column and rejects undeclared fields.
        await _call_reducer("add_evidence", {
            "evidence_id": evidence_id,
            "incident_id": incident_id,
            "source_tool": source_tool,
            "is_simulated": is_simulated,
            "summary": summary,
            "raw_json": raw_json_str,
        })


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

    if _live_enabled():
        # Send ONLY the fields the module's propose_action reducer declares.
        # The module sets status="proposed" itself; do NOT send status.
        await _call_reducer("propose_action", {
            "action_id": action_id,
            "incident_id": incident_id,
            "action_type": action_type,
            "reason": reason,
        })


async def get_current_state() -> Dict[str, Any]:
    """Snapshot for the two-pane React UI.

    Live mode: read the four tables back from SpacetimeDB and label the
    response source "spacetimedb_live". If that read fails, fall back to
    the in-memory mirror and label it "in_memory_fallback" — never present
    the mirror as live data. Demo mode: the in-memory mirror, labelled
    "in_memory_demo".
    """
    if _live_enabled():
        live: Dict[str, Any] = {"source": "spacetimedb_live"}
        ok = True
        for key, query in _LIVE_QUERIES.items():
            rows = await _query_sql(query)
            if rows is None:
                ok = False
                break
            live[key] = rows
        if ok:
            # Merge mirror-only flags (e.g. live_failure) into live rows.
            for incident in live["incidents"]:
                mirror = _STATE["incidents"].get(incident.get("incident_id"), {})
                incident["live_failure"] = bool(mirror.get("live_failure", False))
            return live
        logger.warning("SpacetimeDB read-back failed; serving in-memory fallback state.")

    source = "in_memory_demo" if settings.demo_mode else "in_memory_fallback"
    return {
        "source": source,
        "incidents": list(_STATE["incidents"].values()),
        "evidence_items": _STATE["evidence_items"],
        "proposed_actions": _STATE["proposed_actions"],
        "sandbox_sessions": list(_STATE["sandbox_sessions"].values())
    }


async def get_sandbox_session(session_id: str = "sess_demo_carrier_01") -> Dict[str, Any]:
    if _live_enabled():
        # Filter in Python, never interpolate a request-supplied id into SQL.
        rows = await _query_sql(_LIVE_QUERIES["sandbox_sessions"])
        if rows:
            for row in rows:
                if row.get("session_id") == session_id:
                    return row
    return _STATE["sandbox_sessions"].get(session_id, {})


async def ensure_demo_session() -> None:
    """Create the demo sandbox session in SpacetimeDB on startup if it does
    not exist there yet. Live mode only; a no-op in demo mode."""
    if not _live_enabled():
        return
    existing = await get_sandbox_session()
    if existing:
        return
    seed = _STATE["sandbox_sessions"]["sess_demo_carrier_01"]
    ok = await _call_reducer("create_sandbox_session", {
        "session_id": seed["session_id"],
        "account_id": seed["account_id"],
        "device_label": seed["device_label"],
        "phone_masked": seed["phone_masked"],
    })
    if ok:
        logger.info("Created demo sandbox session sess_demo_carrier_01 in SpacetimeDB.")
    else:
        logger.warning("Could not create demo sandbox session in SpacetimeDB; session endpoints will use the in-memory mirror.")


async def trigger_compromise(session_id: str = "sess_demo_carrier_01"):
    sess = _STATE["sandbox_sessions"].get(session_id)
    if sess:
        sess["status"] = "compromised_sim"
        sess["updated_at"] = int(time.time() * 1000)
    if _live_enabled():
        await _call_reducer("trigger_compromise", {"session_id": session_id})
    return sess


async def revoke_session(session_id: str = "sess_demo_carrier_01", reason: str = "Operator enforced session invalidation"):
    sess = _STATE["sandbox_sessions"].get(session_id)
    if sess:
        sess["status"] = "revoked"
        sess["updated_at"] = int(time.time() * 1000)
        sess["revocation_reason"] = reason
    if _live_enabled():
        await _call_reducer("revoke_sandbox_session", {"session_id": session_id, "reason": reason})
    return sess


async def toggle_sim_freeze(session_id: str = "sess_demo_carrier_01"):
    sess = _STATE["sandbox_sessions"].get(session_id)
    if sess:
        sess["sim_freeze_enabled"] = not sess["sim_freeze_enabled"]
        sess["updated_at"] = int(time.time() * 1000)
    if _live_enabled():
        await _call_reducer("toggle_sim_freeze", {"session_id": session_id})
    return sess

import time
import json
import logging
import uuid
import re
import secrets
import hashlib
import hmac
from typing import Dict, Any, List, Optional, Tuple
import httpx
from .config import settings

logger = logging.getLogger("nemo_proxy.spacetime")

# In-memory mirror of the SpacetimeDB spec §5 schema. In demo mode this IS
# the state shown by GET /api/state (labelled as such). In live mode the
# mirror is kept for resilience, but GET /api/state reads back from
# SpacetimeDB itself; the mirror is only a fallback if that read fails.
#
# The mirror stores the NEW tables (message_event, investigation_status,
# evidence, response_action, session). GET /api/state maps them back onto
# the stable external key shape (incidents / evidence_items /
# proposed_actions / sandbox_sessions) — see get_current_state().
#
# Two deliberate gaps between the §5 tables and the old external shape:
# - The §5 evidence table has no raw_json column and no summary column:
#   the mirror keeps raw_json (and the summary, as `result`) so demo mode
#   shows the same detail as before; a live read-back returns summary
#   from `result` and raw_json as ''.
# - The §5 response_action table has no reason column: the mirror keeps
#   reason so demo mode shows it; a live read-back returns reason as ''.
# - The §5 investigation_status table has no verdict column: the backend
#   writes the verdict as a machine-readable first line of `explanation`
#   ("verdict=<verdict>\n<summary>") and strips it again on live
#   read-back, so the stored explanation stays human-readable and the
#   verdict round-trips. Rows written out-of-band without that prefix
#   read back with verdict "pending" (see _parse_assessment).
# - The §5 session table has no device label / phone / SIM-freeze
#   columns: those demo-UI labels live in _DEMO_SESSION_META below, not
#   in SpacetimeDB. The mirror session rows NEVER contain credential_hash.
_STATE = {
    "message_events": {},        # Dict[incident_id, Dict]
    "investigation_statuses": {},  # Dict[incident_id, Dict]
    "evidence": [],              # List[Dict] (new-table fields + raw_json)
    "response_actions": [],      # List[Dict] (new-table fields + reason)
    "sessions": {},              # Dict[session_id, Dict] (never credential_hash)
}

# Demo-UI labels for the fictional demo session. NOT session state and
# NOT stored in SpacetimeDB (the §5 session table has no such columns).
_DEMO_SESSION_META = {
    "sess_demo_carrier_01": {
        "account_id": "acct_tm_94821",
        "device_label": "Samsung Galaxy S24 (eSIM - T-Mobile)",
        "phone_masked": "+1 (214) •••-4102",
        "sim_freeze_enabled": False,
    }
}

# The §5 demo session's owner. The same owner_id is used for incidents
# created by the pipeline (the investigated messages belong to this
# fictional subscriber).
_DEMO_OWNER_ID = "acct_tm_94821"
# Placeholder stored as credential_hash for the synthetic demo session.
# It is not a hash of any real credential, and it is never served to
# clients (the session table is private; /api/state never includes it).
# Phase B: on first credential issue the backend replaces this with the
# SHA-256 hash of a random credential (see issue_session_credential);
# until then NO credential validates against it, so protected requests
# fail closed.
_DEMO_CREDENTIAL_HASH = "demo_hash_placeholder__not_a_real_credential"

# --- Phase B (spec §6): demo session credentials -------------------------
# Credential lifetime: 30 minutes from issue. The RAW credential is
# generated here, hashed, and handed to exactly one caller (main.py,
# which puts it in an HttpOnly cookie). The raw value is NEVER stored,
# NEVER logged, and NEVER placed in _STATE or any API response.
# Only the hash lives on: in SpacetimeDB (live mode, via the
# rotate_session_credential reducer) or in _CREDENTIAL_HASHES (demo
# mode, server memory only — deliberately kept OUT of _STATE so it can
# never leak through /api/state).
_SESSION_TTL_MS = 30 * 60 * 1000
_CREDENTIAL_HASHES: Dict[str, Dict[str, Any]] = {}  # session_id -> {"hash", "expiry_ms"}
_DEMO_SESSION_ID = "sess_demo_carrier_01"


def _hash_credential(raw_credential: str) -> str:
    return hashlib.sha256(raw_credential.encode("utf-8")).hexdigest()

_STATE["sessions"]["sess_demo_carrier_01"] = {
    "session_id": "sess_demo_carrier_01",
    "owner_id": _DEMO_OWNER_ID,
    "state": "active",  # "active" | "compromised_sim" | "revoked" | "expired"
    "expiry": int(time.time() * 1000) + 365 * 24 * 3600 * 1000,
    "revoked_at": 0,
    "revocation_reason": "",
    "updated_at": int(time.time() * 1000),
}

# SQL read-back queries for live mode (SpacetimeDB 2.x HTTP API).
# NOTE: the session query deliberately omits credential_hash — it must
# never leave SpacetimeDB towards a client.
_LIVE_QUERIES = {
    "message_events": (
        "SELECT incident_id, owner_id, sanitized_message, scenario_id, created_at"
        " FROM message_event"
    ),
    "investigation_statuses": (
        "SELECT incident_id, phase, concern_level, explanation, unknowns, version,"
        " updated_at FROM investigation_status"
    ),
    "evidence": (
        "SELECT evidence_id, incident_id, type, result, source, is_simulated,"
        " observed_at FROM evidence"
    ),
    "response_actions": (
        "SELECT action_id, incident_id, session_id, type, approval_state,"
        " execution_state, idempotency_key, receipt FROM response_action"
    ),
    "sessions": (
        "SELECT session_id, owner_id, state, expiry, revoked_at FROM session"
    ),
}

# Phase B: server-side credential verification read. Unlike
# _LIVE_QUERIES["sessions"] this INCLUDES credential_hash — it is used
# ONLY inside verify_session_credential, server-side, to compare hashes.
# The hash value is never returned, logged, or placed in any response.
_LIVE_AUTH_SESSION_QUERY = (
    "SELECT session_id, owner_id, state, expiry, revoked_at,"
    " credential_hash FROM session"
)

# Columns the module stores as SpacetimeDB timestamps. The SQL API returns
# them as single-element arrays [micros_since_unix_epoch]; normalize to ms.
_TIMESTAMP_COLUMNS = {"created_at", "updated_at", "observed_at"}

_VERDICT_PREFIX_RE = re.compile(r"^verdict=([a-z_]+)\n", re.MULTILINE)

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


def _encode_assessment(verdict: str, summary: str) -> str:
    """Encode the verdict into the investigation_status.explanation column
    (which has no dedicated verdict column in the §5 schema) as a
    machine-readable first line. _parse_assessment reverses this."""
    return f"verdict={verdict}\n{summary}"


def _parse_assessment(explanation: str) -> Dict[str, str]:
    """Split a stored explanation back into verdict + summary. Rows
    written out-of-band without the prefix read back as verdict
    "pending" — never invent a verdict from free text."""
    m = _VERDICT_PREFIX_RE.match(explanation or "")
    if m:
        return {"verdict": m.group(1), "summary": explanation[m.end():]}
    return {"verdict": "pending", "summary": explanation or ""}


def _mirror_incident(incident_id: str) -> Dict[str, Any]:
    """Joined external incident shape for one mirror incident."""
    event = _STATE["message_events"].get(incident_id, {})
    status = _STATE["investigation_statuses"].get(incident_id, {})
    return {
        "incident_id": incident_id,
        "scenario_id": event.get("scenario_id", ""),
        "redacted_message": event.get("sanitized_message", ""),
        "status": status.get("phase", "investigating"),
        "verdict": status.get("verdict", "pending"),
        "confidence_band": status.get("concern_level", "low"),
        "summary": status.get("explanation", ""),
        "unknowns": status.get("unknowns", ""),
        # Phase C: the validated structured assessment (concern_level,
        # explanation, evidence_ids, conflicts_resolved, recovery_steps,
        # injection flag). Present in demo mode; a live read-back has no
        # column for it in the §5 schema, so live rows carry null here
        # and the key facts stay in the human-readable summary.
        "assessment": status.get("assessment"),
        "created_at": event.get("created_at", int(time.time() * 1000)),
        "live_failure": bool(status.get("live_failure", False)),
    }


def _mirror_evidence_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "evidence_id": item["evidence_id"],
        "incident_id": item["incident_id"],
        "source_tool": item["type"],
        "is_simulated": item["is_simulated"],
        "summary": item["result"],
        "raw_json": item.get("raw_json", ""),
    }


def _mirror_action_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "action_id": item["action_id"],
        "incident_id": item["incident_id"],
        "action_type": item["type"],
        "reason": item.get("reason", ""),
        "status": item["approval_state"],
        # Phase B: the committed receipt / execution state / key, so the
        # UI can show what SpacetimeDB actually recorded.
        "execution_state": item.get("execution_state", "pending"),
        "idempotency_key": item.get("idempotency_key", ""),
        "receipt": item.get("receipt", ""),
    }


def _mirror_session(sess: Dict[str, Any]) -> Dict[str, Any]:
    meta = _DEMO_SESSION_META.get(sess["session_id"], {})
    return {
        "session_id": sess["session_id"],
        "account_id": meta.get("account_id", sess.get("owner_id", "")),
        "device_label": meta.get("device_label", "Sandbox device"),
        "phone_masked": meta.get("phone_masked", ""),
        "status": sess["state"],
        "sim_freeze_enabled": bool(meta.get("sim_freeze_enabled", False)),
        "revocation_reason": sess.get("revocation_reason", ""),
        "updated_at": sess.get("updated_at", int(time.time() * 1000)),
    }


async def spacetime_create_incident(incident_id: str, scenario_id: str, redacted_message: str,
                                     owner_id: str = _DEMO_OWNER_ID):
    now_ms = int(time.time() * 1000)
    _STATE["message_events"][incident_id] = {
        "incident_id": incident_id,
        "owner_id": owner_id,
        "sanitized_message": redacted_message,
        "scenario_id": scenario_id,
        "created_at": now_ms,
    }
    _STATE["investigation_statuses"][incident_id] = {
        "incident_id": incident_id,
        "phase": "investigating",
        "concern_level": "low",
        "explanation": "Investigation queued. Nemotron tool loop starting.",
        "unknowns": "",
        "verdict": "pending",
        "version": 0,
        "updated_at": now_ms,
        "live_failure": False,
    }

    if _live_enabled():
        await _call_reducer("create_incident", {
            "incident_id": incident_id,
            "owner_id": owner_id,
            "sanitized_message": redacted_message,
            "scenario_id": scenario_id,
        })


async def spacetime_update_progress(
    incident_id: str,
    phase: str,
    concern_level: str,
    explanation: str,
    unknowns: str = "",
):
    """Record investigation progress (no version gate — only the final
    publish_assessment is version-checked)."""
    status = _STATE["investigation_statuses"].get(incident_id)
    if status is not None:
        status.update({
            "phase": phase,
            "concern_level": concern_level,
            "explanation": explanation,
            "unknowns": unknowns,
            "version": int(status.get("version", 0)) + 1,
            "updated_at": int(time.time() * 1000),
        })

    if _live_enabled():
        await _call_reducer("update_investigation_progress", {
            "incident_id": incident_id,
            "phase": phase,
            "concern_level": concern_level,
            "explanation": explanation,
            "unknowns": unknowns,
        })


async def _get_live_version(incident_id: str) -> Optional[int]:
    """Read the current investigation_status.version from SpacetimeDB,
    for a single retry after a stale publish_assessment."""
    rows = await _query_sql(
        "SELECT version FROM investigation_status WHERE incident_id = '" +
        incident_id.replace("'", "") + "'"
    )
    if rows:
        try:
            return int(rows[0].get("version", 0))
        except (TypeError, ValueError):
            return None
    return None


async def spacetime_update_incident(
    incident_id: str,
    status: str,
    verdict: str,
    confidence_band: str,
    summary: str,
    live_failure: bool = False,
    assessment: Optional[Dict[str, Any]] = None,
    unknowns: str = "",
):
    """Publish the final assessment. The module's publish_assessment
    rejects stale writes, so this sends the mirror's expected version and
    retries once with a freshly read version if the first attempt fails.

    Phase C: ``assessment`` is the validated structured assessment dict
    (stored in the in-memory mirror and served via /api/state; the §5
    investigation_status table has no assessment column, so the live
    reducer call still carries only phase/concern/explanation/unknowns).
    ``status`` may be "assessed", "failed" or "incomplete" (budget
    exhausted / unvalidatable output — partial evidence kept, no verdict).
    """
    mirror = _STATE["investigation_statuses"].get(incident_id, {})
    expected_version = int(mirror.get("version", 0))

    if _live_enabled():
        ok = await _call_reducer("publish_assessment", {
            "incident_id": incident_id,
            "expected_version": expected_version,
            "phase": status,
            "concern_level": confidence_band,
            "explanation": _encode_assessment(verdict, summary),
            "unknowns": unknowns,
        })
        if not ok:
            fresh = await _get_live_version(incident_id)
            if fresh is not None and fresh != expected_version:
                ok = await _call_reducer("publish_assessment", {
                    "incident_id": incident_id,
                    "expected_version": fresh,
                    "phase": status,
                    "concern_level": confidence_band,
                    "explanation": _encode_assessment(verdict, summary),
                    "unknowns": unknowns,
                })
                if ok:
                    expected_version = fresh
        if not ok:
            logger.warning(
                f"SpacetimeDB publish_assessment failed for {incident_id}; "
                "in-memory state preserved (labelled as fallback in /api/state)."
            )

    if incident_id in _STATE["investigation_statuses"]:
        _STATE["investigation_statuses"][incident_id].update({
            "phase": status,
            "verdict": verdict,
            "concern_level": confidence_band,
            "explanation": summary,
            "unknowns": unknowns,
            "assessment": assessment,
            "version": expected_version + 1,
            "updated_at": int(time.time() * 1000),
            "live_failure": live_failure,
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
        "type": source_tool,
        "result": summary,
        "source": "backend_tool_loop",
        "is_simulated": is_simulated,
        "observed_at": int(time.time() * 1000),
        "raw_json": raw_json_str,
    }
    _STATE["evidence"].append(item)

    if _live_enabled():
        # Send ONLY the fields the module's record_evidence reducer
        # declares. The §5 evidence table has no raw_json column; the
        # full payload stays in the mirror only.
        await _call_reducer("record_evidence", {
            "evidence_id": evidence_id,
            "incident_id": incident_id,
            "type": source_tool,
            "result": summary,
            "source": "backend_tool_loop",
            "is_simulated": is_simulated,
        })


async def spacetime_propose_action(
    action_id: str,
    incident_id: str,
    action_type: str,
    reason: str,
    session_id: str = "sess_demo_carrier_01",
    idempotency_key: Optional[str] = None,
) -> bool:
    """Propose an action. Returns True when the proposal is recorded
    (live reducer success, or demo-mode mirror update)."""
    # The idempotency key defaults to the action_id: redelivering the
    # same proposed action is a no-op in the module, not a duplicate row.
    # Phase B revocations pass an explicit key so propose → approve →
    # revoke all share the SAME key, binding the approval to that
    # specific action and session.
    key = idempotency_key or action_id
    item = {
        "action_id": action_id,
        "incident_id": incident_id,
        "session_id": session_id,
        "type": action_type,
        "approval_state": "proposed",
        "execution_state": "pending",
        "idempotency_key": key,
        "receipt": "",
        "reason": reason,
    }
    if not any(a.get("idempotency_key") == key for a in _STATE["response_actions"]):
        _STATE["response_actions"].append(item)

    if _live_enabled():
        # The §5 response_action table has no reason column; the reason
        # stays in the mirror only.
        return await _call_reducer("propose_action", {
            "action_id": action_id,
            "incident_id": incident_id,
            "session_id": session_id,
            "type": action_type,
            "idempotency_key": key,
        })
    return True


async def spacetime_approve_action(action_id: str, idempotency_key: str) -> bool:
    """Operator/backend approval of a proposed action (Phase B, spec §6).

    Only the backend calls this — it requires the backend service
    identity in SpacetimeDB, and the Nemotron tool loop has no path to
    it: the model can propose an action (propose_response_action) but
    cannot approve one. Returns True when the approval is recorded
    (live reducer success, or demo-mode mirror update). A repeat
    approval with the same key is a no-op in the module.
    """
    existing = next(
        (a for a in _STATE["response_actions"] if a.get("idempotency_key") == idempotency_key),
        None,
    )
    if existing is not None and existing.get("approval_state") != "approved":
        existing["approval_state"] = "approved"
        existing["receipt"] = f"receipt_approved_{action_id}"

    if _live_enabled():
        return await _call_reducer("approve_action", {
            "action_id": action_id,
            "idempotency_key": idempotency_key,
        })
    return True


async def get_current_state() -> Dict[str, Any]:
    """Snapshot for the two-pane React UI.

    Live mode: read the five §5 tables back from SpacetimeDB, join
    message_event + investigation_status into incidents, and label the
    response source "spacetimedb_live". If that read fails, fall back to
    the in-memory mirror and label it "in_memory_fallback" — never present
    the mirror as live data. Demo mode: the in-memory mirror, labelled
    "in_memory_demo".
    """
    if _live_enabled():
        live: Dict[str, Any] = {"source": "spacetimedb_live"}
        rows: Dict[str, Optional[List[Dict[str, Any]]]] = {}
        ok = True
        for key, query in _LIVE_QUERIES.items():
            rows[key] = await _query_sql(query)
            if rows[key] is None:
                ok = False
                break
        if ok:
            assert rows["message_events"] is not None
            assert rows["investigation_statuses"] is not None
            assert rows["evidence"] is not None
            assert rows["response_actions"] is not None
            assert rows["sessions"] is not None
            statuses = {r["incident_id"]: r for r in rows["investigation_statuses"]}
            incidents = []
            for event in rows["message_events"]:
                st = statuses.get(event["incident_id"], {})
                parsed = _parse_assessment(str(st.get("explanation", "")))
                mirror = _STATE["investigation_statuses"].get(event["incident_id"], {})
                incidents.append({
                    "incident_id": event["incident_id"],
                    "scenario_id": event.get("scenario_id", ""),
                    "redacted_message": event.get("sanitized_message", ""),
                    "status": st.get("phase", "investigating"),
                    "verdict": parsed["verdict"],
                    "confidence_band": st.get("concern_level", "low"),
                    "summary": parsed["summary"],
                    "unknowns": st.get("unknowns", ""),
                    # No assessment column in the §5 schema — live rows
                    # carry null; the mirror (demo mode) carries the full
                    # validated assessment. Key facts stay in the summary.
                    "assessment": mirror.get("assessment"),
                    "created_at": event.get("created_at", 0),
                    # Merge mirror-only flags (e.g. live_failure) into live rows.
                    "live_failure": bool(mirror.get("live_failure", False)),
                })
            live["incidents"] = incidents
            live["evidence_items"] = [
                {
                    "evidence_id": r["evidence_id"],
                    "incident_id": r["incident_id"],
                    "source_tool": r["type"],
                    "is_simulated": r["is_simulated"],
                    "summary": r["result"],
                    "raw_json": "",
                }
                for r in rows["evidence"]
            ]
            live["proposed_actions"] = [
                {
                    "action_id": r["action_id"],
                    "incident_id": r["incident_id"],
                    "action_type": r["type"],
                    "reason": "",
                    "status": r["approval_state"],
                    "execution_state": r["execution_state"],
                    "idempotency_key": r["idempotency_key"],
                    "receipt": r["receipt"],
                }
                for r in rows["response_actions"]
            ]
            live["sandbox_sessions"] = [
                _mirror_session({
                    "session_id": r["session_id"],
                    "owner_id": r.get("owner_id", ""),
                    "state": r["state"],
                    "expiry": r.get("expiry", 0),
                    "revoked_at": r.get("revoked_at", 0),
                    "revocation_reason": "",
                    "updated_at": int(time.time() * 1000),
                })
                for r in rows["sessions"]
            ]
            return live
        logger.warning("SpacetimeDB read-back failed; serving in-memory fallback state.")

    source = "in_memory_demo" if settings.demo_mode else "in_memory_fallback"
    return {
        "source": source,
        "incidents": [_mirror_incident(iid) for iid in _STATE["message_events"]],
        "evidence_items": [_mirror_evidence_item(e) for e in _STATE["evidence"]],
        "proposed_actions": [_mirror_action_item(a) for a in _STATE["response_actions"]],
        "sandbox_sessions": [_mirror_session(s) for s in _STATE["sessions"].values()],
    }


async def get_sandbox_session(session_id: str = "sess_demo_carrier_01") -> Dict[str, Any]:
    if _live_enabled():
        # Filter in Python, never interpolate a request-supplied id into SQL.
        rows = await _query_sql(_LIVE_QUERIES["sessions"])
        if rows:
            for row in rows:
                if row.get("session_id") == session_id:
                    return _mirror_session({
                        "session_id": row["session_id"],
                        "owner_id": row.get("owner_id", ""),
                        "state": row["state"],
                        "expiry": row.get("expiry", 0),
                        "revoked_at": row.get("revoked_at", 0),
                        "revocation_reason": "",
                        "updated_at": int(time.time() * 1000),
                    })
    sess = _STATE["sessions"].get(session_id)
    return _mirror_session(sess) if sess else {}


async def ensure_demo_session() -> None:
    """Create the demo sandbox session in SpacetimeDB on startup if it does
    not exist there yet. Live mode only; a no-op in demo mode."""
    if not _live_enabled():
        return
    existing = await get_sandbox_session()
    if existing:
        return
    seed = _STATE["sessions"]["sess_demo_carrier_01"]
    ok = await _call_reducer("create_session", {
        "session_id": seed["session_id"],
        "owner_id": seed["owner_id"],
        "credential_hash": _DEMO_CREDENTIAL_HASH,
        "expiry": seed["expiry"],
    })
    if ok:
        logger.info("Created demo sandbox session sess_demo_carrier_01 in SpacetimeDB.")
    else:
        logger.warning("Could not create demo sandbox session in SpacetimeDB; session endpoints will use the in-memory mirror.")


async def trigger_compromise(session_id: str = "sess_demo_carrier_01"):
    """Controlled simulated compromise event (module reducer
    inject_compromise). Kept strictly distinct from SMS receipt."""
    key = f"comp_{uuid.uuid4().hex[:8]}"
    sess = _STATE["sessions"].get(session_id)
    if sess:
        sess["state"] = "compromised_sim"
        sess["updated_at"] = int(time.time() * 1000)
    # Mirror the receipt row the module writes, so /api/state shows it
    # even if the live read-back is unavailable.
    if not any(a.get("idempotency_key") == key for a in _STATE["response_actions"]):
        _STATE["response_actions"].append({
            "action_id": f"act_compromise_{key}",
            "incident_id": "",
            "session_id": session_id,
            "type": "inject_compromise",
            "approval_state": "approved",
            "execution_state": "executed",
            "idempotency_key": key,
            "receipt": f"synthetic_compromise_sim_{session_id}_{key}",
            "reason": "Simulated reverse-proxy attacker intercepting carrier cookie.",
        })
    if _live_enabled():
        await _call_reducer("inject_compromise", {
            "session_id": session_id,
            "incident_id": "",
            "idempotency_key": key,
        })
    return _mirror_session(sess) if sess else {}


async def _get_live_action_by_key(idempotency_key: str) -> Optional[Dict[str, Any]]:
    """Read one response_action row back from SpacetimeDB by key (Phase B:
    confirms the committed receipt after a revocation). None if the
    read fails or no row matches."""
    rows = await _query_sql(
        "SELECT action_id, incident_id, session_id, type, approval_state,"
        " execution_state, idempotency_key, receipt FROM response_action"
    )
    if rows is None:
        return None
    return next((r for r in rows if r.get("idempotency_key") == idempotency_key), None)


async def issue_session_credential(
    session_id: str = _DEMO_SESSION_ID,
) -> Optional[Dict[str, Any]]:
    """Issue a fresh random, expiring opaque demo session credential
    (Phase B, spec §6).

    Generates with secrets.token_urlsafe, stores ONLY its SHA-256 hash —
    in SpacetimeDB via the rotate_session_credential reducer (live mode)
    and in the server-only _CREDENTIAL_HASHES dict (both modes, never in
    _STATE) — and returns the RAW credential to the single caller
    (main.py, which puts it in an HttpOnly cookie). The raw value must
    never be logged or placed in any API response; the caller is
    responsible for that.

    Returns {"raw_credential", "session_id", "expiry_ms",
    "expires_in_seconds"} or None when issuance is refused/failed:
    the session is revoked (reset the demo run first), or the live
    rotate call failed — in live mode a credential that could not be
    stored in SpacetimeDB is never handed out, so verification can
    never disagree with issuance.
    """
    current = await get_sandbox_session(session_id)
    if current and current.get("status") == "revoked":
        logger.warning(
            f"Refusing to issue a credential for revoked session {session_id}; reset the demo run first."
        )
        return None

    raw_credential = secrets.token_urlsafe(32)
    digest = _hash_credential(raw_credential)
    expiry_ms = int(time.time() * 1000) + _SESSION_TTL_MS

    if _live_enabled():
        ok = await _call_reducer("rotate_session_credential", {
            "session_id": session_id,
            "credential_hash": digest,
            "expiry": expiry_ms,
        })
        if not ok:
            logger.warning(
                f"rotate_session_credential failed for {session_id}; no credential issued."
            )
            return None

    _CREDENTIAL_HASHES[session_id] = {"hash": digest, "expiry_ms": expiry_ms}
    sess = _STATE["sessions"].get(session_id)
    if sess and sess.get("state") != "revoked":
        sess["state"] = "active"
        sess["revoked_at"] = 0
        sess["expiry"] = expiry_ms
        sess["updated_at"] = int(time.time() * 1000)
    return {
        "raw_credential": raw_credential,
        "session_id": session_id,
        "expiry_ms": expiry_ms,
        "expires_in_seconds": _SESSION_TTL_MS // 1000,
    }


async def verify_session_credential(
    session_id: str,
    presented_credential: Optional[str],
) -> Dict[str, Any]:
    """Validate a presented demo session credential (Phase B, spec §6).

    Checks, in order: a credential was presented; its SHA-256 hash
    matches the stored credential_hash; it has not expired; the session
    is in a usable state (active, or compromised_sim — a compromised
    session is still technically usable until revoked, which is the
    point of the demo). The authoritative check is ALWAYS a server-side
    SpacetimeDB read in live mode — never the React UI, never the
    in-memory mirror. The mirror + _CREDENTIAL_HASHES are consulted
    only in demo mode, and the result says so (source
    "in_memory_demo").

    If the session status cannot be verified in live mode (the
    SpacetimeDB read fails), the result is 503 DENY — never fail open.

    Returns {"ok", "status" (200/401/503), "reason", "source",
    "session_state", "expiry_ms"}. The presented credential and any
    hash are never included in the result.
    """
    now_ms = int(time.time() * 1000)
    if not presented_credential:
        return {"ok": False, "status": 401, "reason": "No session credential presented.",
                "source": "spacetimedb_live" if _live_enabled() else "in_memory_demo",
                "session_state": "unknown", "expiry_ms": 0}

    if _live_enabled():
        rows = await _query_sql(_LIVE_AUTH_SESSION_QUERY)
        if rows is None:
            return {"ok": False, "status": 503,
                    "reason": "SpacetimeDB session store unreachable; protected operation denied (fail-closed, not allowed through).",
                    "source": "spacetimedb_live", "session_state": "unknown", "expiry_ms": 0}
        row = next((r for r in rows if r.get("session_id") == session_id), None)
        if row is None:
            return {"ok": False, "status": 401, "reason": f"Unknown session {session_id}.",
                    "source": "spacetimedb_live", "session_state": "unknown", "expiry_ms": 0}
        stored_hash = str(row.get("credential_hash") or "")
        if not stored_hash or not hmac.compare_digest(
            _hash_credential(presented_credential), stored_hash
        ):
            return {"ok": False, "status": 401, "reason": "Credential does not match this session.",
                    "source": "spacetimedb_live", "session_state": str(row.get("state", "unknown")),
                    "expiry_ms": int(row.get("expiry") or 0)}
        expiry_ms = int(row.get("expiry") or 0)
        if now_ms > expiry_ms:
            return {"ok": False, "status": 401, "reason": "Session credential has expired.",
                    "source": "spacetimedb_live", "session_state": str(row.get("state", "unknown")),
                    "expiry_ms": expiry_ms}
        state = str(row.get("state", "unknown"))
        if state == "revoked":
            return {"ok": False, "status": 401, "reason": "Session has been revoked.",
                    "source": "spacetimedb_live", "session_state": state, "expiry_ms": expiry_ms}
        if state not in ("active", "compromised_sim"):
            return {"ok": False, "status": 401, "reason": f"Session is not usable (state: {state}).",
                    "source": "spacetimedb_live", "session_state": state, "expiry_ms": expiry_ms}
        return {"ok": True, "status": 200, "reason": "Credential verified against SpacetimeDB.",
                "source": "spacetimedb_live", "session_state": state, "expiry_ms": expiry_ms}

    # Demo mode: the in-memory mirror + server-only hash dict, labelled.
    entry = _CREDENTIAL_HASHES.get(session_id)
    sess = _STATE["sessions"].get(session_id)
    if entry is None or sess is None:
        return {"ok": False, "status": 401, "reason": "No credential has been issued for this session.",
                "source": "in_memory_demo", "session_state": str(sess.get("state")) if sess else "unknown",
                "expiry_ms": 0}
    if not hmac.compare_digest(_hash_credential(presented_credential), str(entry["hash"])):
        return {"ok": False, "status": 401, "reason": "Credential does not match this session.",
                "source": "in_memory_demo", "session_state": str(sess.get("state")),
                "expiry_ms": int(entry["expiry_ms"])}
    if now_ms > int(entry["expiry_ms"]):
        return {"ok": False, "status": 401, "reason": "Session credential has expired.",
                "source": "in_memory_demo", "session_state": str(sess.get("state")),
                "expiry_ms": int(entry["expiry_ms"])}
    state = str(sess.get("state"))
    if state == "revoked":
        return {"ok": False, "status": 401, "reason": "Session has been revoked.",
                "source": "in_memory_demo", "session_state": state,
                "expiry_ms": int(entry["expiry_ms"])}
    if state not in ("active", "compromised_sim"):
        return {"ok": False, "status": 401, "reason": f"Session is not usable (state: {state}).",
                "source": "in_memory_demo", "session_state": state,
                "expiry_ms": int(entry["expiry_ms"])}
    return {"ok": True, "status": 200, "reason": "Credential verified against the in-memory demo store.",
            "source": "in_memory_demo", "session_state": state,
            "expiry_ms": int(entry["expiry_ms"])}


async def revoke_session(
    session_id: str = _DEMO_SESSION_ID,
    reason: str = "Operator enforced session invalidation",
    idempotency_key: Optional[str] = None,
    incident_id: str = "",
) -> Dict[str, Any]:
    """Enforce session revocation through the APPROVED flow (Phase B,
    spec §6): propose_action (type "revoke_session") → approve_action →
    revoke_session, all with the SAME idempotency key, so the approval
    is bound to this specific action and session. The model may propose
    revocation but cannot approve it: approve_action is backend-only
    (SpacetimeDB requireBackend), and the Nemotron tool loop has no
    path to it. The module's revoke_session reducer itself rejects a
    call with no approved proposal for the key.

    A repeat call with the same key is a no-op end to end (one receipt
    row, state unchanged): propose/approve/revoke each de-duplicate on
    the key, in the module and in the mirror.

    Returns {"session", "action_id", "idempotency_key", "receipt",
    "source"}. Raises RuntimeError when a live step fails — the caller
    maps that to 503 and the session is NOT treated as revoked.
    """
    key = idempotency_key or f"revoke_{uuid.uuid4().hex[:8]}"
    action_id = f"act_{key}"
    receipt = f"revoked session {session_id} (key {key}): {reason}"

    ok = await spacetime_propose_action(
        action_id, incident_id, "revoke_session", reason,
        session_id=session_id, idempotency_key=key,
    )
    if _live_enabled() and not ok:
        raise RuntimeError(f"propose_action failed for revocation key {key}; session not revoked.")
    ok = await spacetime_approve_action(action_id, key)
    if _live_enabled() and not ok:
        raise RuntimeError(f"approve_action failed for revocation key {key}; session not revoked.")
    if _live_enabled():
        ok = await _call_reducer("revoke_session", {
            "session_id": session_id,
            "reason": reason,
            "idempotency_key": key,
        })
        if not ok:
            raise RuntimeError(f"revoke_session reducer failed for key {key}; session not revoked.")
        # Confirm the committed receipt from SpacetimeDB itself.
        committed = await _get_live_action_by_key(key)
        if committed is not None:
            receipt = str(committed.get("receipt") or receipt)

    # Mirror: flip the session and mark this key's action executed.
    # Idempotent by key — a replay finds the row already executed.
    sess = _STATE["sessions"].get(session_id)
    if sess:
        sess["state"] = "revoked"
        sess["revoked_at"] = int(time.time() * 1000)
        sess["revocation_reason"] = reason
        sess["updated_at"] = int(time.time() * 1000)
    row = next(
        (a for a in _STATE["response_actions"] if a.get("idempotency_key") == key),
        None,
    )
    if row is not None:
        row["approval_state"] = "approved"
        row["execution_state"] = "executed"
        row["receipt"] = receipt
    return {
        "session": _mirror_session(sess) if sess else {},
        "action_id": action_id,
        "idempotency_key": key,
        "receipt": receipt,
        "source": "spacetimedb_live" if _live_enabled() else "in_memory_demo",
    }


async def reset_demo_session(session_id: str = _DEMO_SESSION_ID) -> bool:
    """Reset the demo run (Phase B): clear incidents / investigation
    rows / evidence / actions (live reset_demo_run reducer + mirror)
    and flip the demo session back to active. The old credential is
    invalidated — its server-side hash is dropped here, and the live
    row keeps its hash only until the caller issues a fresh credential
    right after reset (rotate). Returns False when the live reset
    failed; the caller must not issue a credential on a failed reset.
    """
    if _live_enabled():
        ok = await _call_reducer("reset_demo_run", {})
        if not ok:
            return False
    _STATE["message_events"].clear()
    _STATE["investigation_statuses"].clear()
    _STATE["evidence"].clear()
    _STATE["response_actions"].clear()
    _CREDENTIAL_HASHES.pop(session_id, None)
    sess = _STATE["sessions"].get(session_id)
    if sess:
        sess["state"] = "active"
        sess["revoked_at"] = 0
        sess["revocation_reason"] = ""
        sess["updated_at"] = int(time.time() * 1000)
    return True

import uuid
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .config import settings
from .incident import SCENARIO_CATALOG, execute_investigation_pipeline, redact_message
from .spacetime_client import (
    get_current_state,
    get_sandbox_session,
    trigger_compromise,
    revoke_session,
    ensure_demo_session,
    issue_session_credential,
    verify_session_credential,
    reset_demo_session,
)

# Phase B (spec §6): the demo session credential lives in this HttpOnly
# cookie only. It is set by POST /api/session/issue (and reset) and
# sent back only to /api/account/* (Path=/api/account). The raw
# credential never appears in a JSON body, /api/state, or server logs.
# Secure=False because the demo runs over local http; a production
# deployment must set Secure=True. SameSite=Lax is sufficient here
# because the Vite dev server and the backend share the localhost site.
_SESSION_COOKIE = "nemo_session"

# In-memory rate limiter (slowapi default storage). Applied to /api/ingest.
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Live mode only: make sure the demo sandbox session exists in
    # SpacetimeDB before serving requests. No-op in demo mode.
    await ensure_demo_session()
    yield


app = FastAPI(
    title="NemoProxy Backend API",
    description="Telecom smishing investigation, Nemotron tool loop, and SpacetimeDB authoritative state management.",
    version="0.1.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS: explicit origin list only. allow_origins=["*"] together with
# allow_credentials=True is invalid and browsers reject it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_demo_key(x_demo_key: Optional[str] = Header(None)):
    """Optional shared-key protection for the demo write endpoints.

    If DEMO_API_KEY is set, /api/ingest and the session endpoints require
    it as an X-Demo-Key header (401 otherwise). If unset, the endpoints
    stay open for the demo — this is a hackathon prototype, not a
    production service, and the endpoints only act on synthetic fixtures
    and a fictional sandbox session.
    """
    if settings.demo_api_key and x_demo_key != settings.demo_api_key:
        raise HTTPException(status_code=401, detail="Missing or invalid X-Demo-Key header.")
    return None


class IngestRequest(BaseModel):
    scenario: str = Field(..., description="One of: 'phishing', 'legitimate', 'ambiguous', 'injection'")
    user_id: Optional[str] = Field(None, description="Client-provided hint; ignored for server-side ownership")

class RevokeRequest(BaseModel):
    session_id: str = "sess_demo_carrier_01"
    # Free-text input is length-limited by settings.max_message_len.
    reason: str = Field(
        "Operator enforced session revocation following investigation.",
        max_length=settings.max_message_len,
    )
    # Optional client-supplied idempotency key. Repeating a revocation
    # with the same key is a no-op (one receipt, state unchanged).
    idempotency_key: Optional[str] = None


class ProtectRequest(BaseModel):
    """Customer 'Protect demo account' request (Phase B, spec §6)."""
    session_id: str = "sess_demo_carrier_01"
    reason: str = Field(
        "Customer chose 'Protect demo account' after a synthetic compromise event.",
        max_length=settings.max_message_len,
    )
    idempotency_key: Optional[str] = None
    incident_id: str = ""


# Fictional carrier account overview (Phase B, spec §6). ALL synthetic:
# no real carrier data, no real account. Served only to a request that
# presents a valid demo session credential for the sandbox session.
_FICTIONAL_ACCOUNT_OVERVIEW = {
    "account_id": "acct_tm_94821",
    "phone_masked": "+1 (214) •••-4102",
    "plan_name": "Magenta Plus — fictional sandbox plan",
    "balance_due_usd": 85.00,
    "data_used_gb": 18.4,
    "data_allowance_gb": 50.0,
    "lines": 1,
    "synthetic": True,
    "notice": (
        "Fictional sandbox account overview — synthetic data only, not a "
        "real carrier account. Enforcement here is against the fictional "
        "sandbox session only, not a real carrier session."
    ),
}


def _extract_session_credential(request: Request) -> Optional[str]:
    """Session credential from the HttpOnly cookie, or an Authorization:
    Bearer header (curl / non-browser clients). The raw value is used
    only for hashing inside verify_session_credential — never logged."""
    cookie_value = request.cookies.get(_SESSION_COOKIE)
    if cookie_value:
        return cookie_value
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return None


def _set_session_cookie(response: Response, issued: dict) -> None:
    response.set_cookie(
        _SESSION_COOKIE,
        issued["raw_credential"],
        max_age=issued["expires_in_seconds"],
        httponly=True,
        samesite="lax",
        path="/api/account",
        secure=False,  # local-http demo only; production must use Secure=True
    )

@app.get("/api/health")
def get_health():
    return {
        "status": "healthy",
        "demo_mode": settings.demo_mode,
        "credentials_status": {
            "nvidia_nemotron_configured": settings.has_nvidia_creds(),
            "spacetime_token_configured": settings.has_spacetime_creds(),
            "spacetime_identity_configured": settings.has_spacetime_identity(),
            "web_risk_configured": settings.has_web_risk_creds(),
        },
        "model_id": settings.nvidia_model_id,
        "notice": (
            "Running in DEMO_MODE=true with explicitly labeled fixtures. "
            "Drop credentials into .env to enable live third-party calls."
            if settings.demo_mode else "Live verification mode active."
        )
    }

@app.get("/api/scenarios")
def list_scenarios():
    """Returns scenarios without leaking internal expected labels to client agent context.

    The message is the server-side REDACTED message (emails, phone numbers,
    SSNs and URL secrets stripped) — the raw fixture is never served.
    The "raw_message" key name is kept for compatibility with the existing
    React frontend; its value is the redacted message.
    """
    results = []
    for key, sc in SCENARIO_CATALOG.items():
        redacted = redact_message(sc["raw_message"])["sanitized_message"]
        results.append({
            "key": key,
            "id": sc["id"],
            "name": sc["name"],
            "raw_message": redacted,
            "is_redacted": True,
            "target_domain": sc["domain_fixture"]["domain"]
        })
    return results

@app.post("/api/ingest")
@limiter.limit("30/minute")
async def ingest_scenario(request: Request, req: IngestRequest, bg_tasks: BackgroundTasks, _key: None = Depends(require_demo_key)):
    if req.scenario not in SCENARIO_CATALOG:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario '{req.scenario}'. Must be one of: {list(SCENARIO_CATALOG.keys())}"
        )

    # Server-generated incident ID (never trust client for authority)
    incident_id = f"inc_{uuid.uuid4().hex[:8]}"

    # Asynchronous single-process task runner
    bg_tasks.add_task(execute_investigation_pipeline, incident_id, req.scenario)

    return {
        "incident_id": incident_id,
        "scenario": req.scenario,
        "status": "queued",
        "pipeline": "server_side_redaction_before_third_party_calls",
        "notice": "Single-process prototype runner: Interrupted tasks do not auto-resume on server restart."
    }

@app.get("/api/state")
async def get_authoritative_state():
    """Authoritative SpacetimeDB table snapshots synchronized for the two-pane interface.

    The response carries a "source" field: "spacetimedb_live" when read back
    from SpacetimeDB, "in_memory_demo" in demo mode, or
    "in_memory_fallback" if the live read failed.
    """
    return await get_current_state()

@app.post("/api/session/compromise")
async def simulate_compromise(_key: None = Depends(require_demo_key)):
    """Controlled simulated compromise event. Kept strictly distinct from SMS receipt."""
    sess = await trigger_compromise()
    return {
        "status": "success",
        "event": "simulated_compromise_triggered",
        "session": sess,
        "explanation": "Simulated reverse-proxy attacker intercepting carrier cookie. Note: Receiving an SMS does NOT itself compromise a session."
    }

@app.post("/api/session/revoke")
async def revoke_active_session(req: RevokeRequest, _key: None = Depends(require_demo_key)):
    """Enforces authoritative backend session revocation.

    Phase B: migrated to the approved flow — propose_action (type
    "revoke_session") → approve_action → revoke_session, all with the
    same idempotency key. The old direct-revoke behaviour (one call,
    session revoked) is preserved from the caller's point of view; the
    response now also carries the action_id, idempotency_key, receipt
    and source. A repeat with the same idempotency_key is a no-op.
    """
    try:
        result = await revoke_session(req.session_id, req.reason, idempotency_key=req.idempotency_key)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=f"Approved revocation failed: {e}")
    return {
        "status": "success",
        "event": "sandbox_session_revoked",
        "session": result["session"],
        "action_id": result["action_id"],
        "idempotency_key": result["idempotency_key"],
        "receipt": result["receipt"],
        "source": result["source"],
    }

@app.post("/api/session/protect")
async def protect_demo_account(req: ProtectRequest, _key: None = Depends(require_demo_key)):
    """Customer 'Protect demo account' (Phase B, spec §6 step 3–4).

    The same approved flow as /api/session/revoke: the backend proposes
    a "revoke_session" action for THIS session, approves it as the
    operator identity, then executes the revocation — all bound to one
    idempotency key. The model may propose revocation but cannot approve
    it; approval here is the operator/backend identity, never a model
    tool call.
    """
    try:
        result = await revoke_session(
            req.session_id, req.reason,
            idempotency_key=req.idempotency_key, incident_id=req.incident_id,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=f"Approved revocation failed: {e}")
    return {
        "status": "success",
        "event": "sandbox_session_revoked_via_approved_action",
        "session": result["session"],
        "action_id": result["action_id"],
        "idempotency_key": result["idempotency_key"],
        "receipt": result["receipt"],
        "source": result["source"],
        "explanation": (
            "Approval was bound to this action and session (propose → "
            "approve → revoke, one idempotency key); the model cannot "
            "approve a revocation itself."
        ),
    }

@app.post("/api/session/issue")
async def issue_demo_credential(response: Response, _key: None = Depends(require_demo_key)):
    """Issue a fresh demo session credential (Phase B, spec §6).

    Generates a random opaque credential (30-minute expiry), stores
    ONLY its SHA-256 hash in SpacetimeDB, and returns the raw value
    solely as an HttpOnly cookie ("nemo_session", Path=/api/account).
    The raw credential is NOT in this response body, NOT in /api/state,
    and NOT in server logs. Refuses (503) when the session is revoked
    — reset the demo run first — or the session store is unreachable.
    """
    issued = await issue_session_credential()
    if issued is None:
        raise HTTPException(
            status_code=503,
            detail="Could not issue a session credential (session may be revoked — reset the demo run — or the session store is unreachable).",
        )
    _set_session_cookie(response, issued)
    return {
        "status": "success",
        "session_id": issued["session_id"],
        "credential_issued": True,
        "expires_at_ms": issued["expiry_ms"],
        "expires_in_seconds": issued["expires_in_seconds"],
        "notice": (
            "Raw credential is in the HttpOnly 'nemo_session' cookie only; "
            "it is not in this response body, /api/state, or server logs."
        ),
    }

@app.post("/api/session/reset")
async def reset_demo_run_endpoint(response: Response, _key: None = Depends(require_demo_key)):
    """Reset the demo run (Phase B): clears incidents/evidence/actions
    in SpacetimeDB, flips the demo session back to active, invalidates
    the old credential, and issues a fresh credential (new HttpOnly
    cookie). The previous credential stops working immediately.
    """
    ok = await reset_demo_session()
    if not ok:
        raise HTTPException(status_code=503, detail="Demo reset failed: SpacetimeDB unreachable.")
    issued = await issue_session_credential()
    if issued is None:
        raise HTTPException(status_code=503, detail="Demo reset succeeded but issuing a fresh credential failed.")
    _set_session_cookie(response, issued)
    sess = await get_sandbox_session()
    return {
        "status": "success",
        "event": "demo_run_reset",
        "session": sess,
        "credential_issued": True,
        "expires_at_ms": issued["expiry_ms"],
        "expires_in_seconds": issued["expires_in_seconds"],
    }

@app.get("/api/account/overview")
async def get_account_overview(request: Request):
    """Harmless protected resource (Phase B, spec §6): a fictional
    carrier account overview. Every request must present the demo
    session credential (HttpOnly cookie or Authorization: Bearer) and
    pass server-side verification against SpacetimeDB: hash match,
    unexpired, session usable (active / compromised_sim). Revoked,
    expired, wrong, or missing credentials get 401; if SpacetimeDB
    cannot be reached the request is denied with 503 — never allowed
    through. No real carrier data is involved.
    """
    credential = _extract_session_credential(request)
    result = await verify_session_credential("sess_demo_carrier_01", credential)
    if not result["ok"]:
        raise HTTPException(status_code=result["status"], detail=result["reason"])
    return {
        **_FICTIONAL_ACCOUNT_OVERVIEW,
        "session_id": "sess_demo_carrier_01",
        "session_state": result["session_state"],
        "verification_source": result["source"],
        "credential_expires_at_ms": result["expiry_ms"],
    }

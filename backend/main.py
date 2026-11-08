import uuid
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .config import settings
from .incident import SCENARIO_CATALOG, execute_investigation_pipeline, redact_message
from .spacetime_client import (
    get_current_state,
    trigger_compromise,
    revoke_session,
    toggle_sim_freeze,
    ensure_demo_session,
)

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
    scenario: str = Field(..., description="One of: 'phishing', 'legitimate', 'ambiguous'")
    user_id: Optional[str] = Field(None, description="Client-provided hint; ignored for server-side ownership")

class RevokeRequest(BaseModel):
    session_id: str = "sess_demo_carrier_01"
    # Free-text input is length-limited by settings.max_message_len.
    reason: str = Field(
        "Operator enforced session revocation following investigation.",
        max_length=settings.max_message_len,
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
    """Enforces authoritative backend session revocation."""
    sess = await revoke_session(req.session_id, req.reason)
    return {
        "status": "success",
        "event": "sandbox_session_revoked",
        "session": sess
    }

@app.post("/api/session/toggle_sim_freeze")
async def toggle_freeze(_key: None = Depends(require_demo_key)):
    """Toggles SIM freeze protection."""
    sess = await toggle_sim_freeze()
    return {
        "status": "success",
        "sim_freeze_enabled": sess.get("sim_freeze_enabled", False) if sess else False,
        "session": sess
    }

import uuid
from typing import Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import settings
from .incident import SCENARIO_CATALOG, execute_investigation_pipeline
from .spacetime_client import (
    get_current_state,
    trigger_compromise,
    revoke_session,
    toggle_sim_freeze
)

app = FastAPI(
    title="NemoProxy Backend API",
    description="Telecom smishing investigation, Nemotron tool loop, and SpacetimeDB authoritative state management.",
    version="0.1.0"
)

# Enable CORS for local React development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class IngestRequest(BaseModel):
    scenario: str = Field(..., description="One of: 'phishing', 'legitimate', 'ambiguous'")
    user_id: Optional[str] = Field(None, description="Client-provided hint; ignored for server-side ownership")

class RevokeRequest(BaseModel):
    session_id: str = "sess_demo_carrier_01"
    reason: str = "Operator enforced session revocation following investigation."

@app.get("/api/health")
def get_health():
    return {
        "status": "healthy",
        "demo_mode": settings.demo_mode,
        "credentials_status": {
            "nvidia_nemotron_configured": settings.has_nvidia_creds(),
            "spacetime_token_configured": settings.has_spacetime_creds(),
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
    """Returns scenarios without leaking internal expected labels to client agent context."""
    results = []
    for key, sc in SCENARIO_CATALOG.items():
        results.append({
            "key": key,
            "id": sc["id"],
            "name": sc["name"],
            "raw_message": sc["raw_message"],
            "target_domain": sc["domain_fixture"]["domain"]
        })
    return results

@app.post("/api/ingest")
async def ingest_scenario(req: IngestRequest, bg_tasks: BackgroundTasks):
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
def get_authoritative_state():
    """Authoritative SpacetimeDB table snapshots synchronized for the two-pane interface."""
    return get_current_state()

@app.post("/api/session/compromise")
def simulate_compromise():
    """Controlled simulated compromise event. Kept strictly distinct from SMS receipt."""
    sess = trigger_compromise()
    return {
        "status": "success",
        "event": "simulated_compromise_triggered",
        "session": sess,
        "explanation": "Simulated reverse-proxy attacker intercepting carrier cookie. Note: Receiving an SMS does NOT itself compromise a session."
    }

@app.post("/api/session/revoke")
def revoke_active_session(req: RevokeRequest):
    """Enforces authoritative backend session revocation."""
    sess = revoke_session(req.session_id, req.reason)
    return {
        "status": "success",
        "event": "sandbox_session_revoked",
        "session": sess
    }

@app.post("/api/session/toggle_sim_freeze")
def toggle_freeze():
    """Toggles SIM freeze protection."""
    sess = toggle_sim_freeze()
    return {
        "status": "success",
        "sim_freeze_enabled": sess.get("sim_freeze_enabled", False),
        "session": sess
    }

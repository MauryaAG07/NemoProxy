import os
from pathlib import Path
from pydantic import BaseModel, Field

# Load .env file manually if exists
env_path = Path(__file__).resolve().parent.parent / ".env"
if env_path.exists():
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key not in os.environ:
                    os.environ[key] = val

def _env_list(name: str, default: list) -> list:
    raw = os.getenv(name)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]

class AppSettings(BaseModel):
    # NVIDIA Nemotron
    nvidia_api_key: str = Field(default_factory=lambda: os.getenv("NVIDIA_API_KEY", ""))
    nvidia_base_url: str = Field(default_factory=lambda: os.getenv("NVIDIA_BASE_URL", "https://api.nvidia.com/v1"))
    nvidia_model_id: str = Field(default_factory=lambda: os.getenv("NVIDIA_MODEL_ID", "nvidia/nemotron-3-nano-30b-a3b"))

    # SpacetimeDB
    # NOTE: database names cannot contain underscores — use "nemo-proxy".
    spacetime_host: str = Field(default_factory=lambda: os.getenv("SPACETIME_HOST", "http://127.0.0.1:3000"))
    spacetime_db: str = Field(default_factory=lambda: os.getenv("SPACETIME_DB", "nemo-proxy"))
    # Database identity (hex) used by the SpacetimeDB 2.x v1 call endpoint:
    # POST {host}/v1/database/{identity}/call/<reducer>. No default — the
    # v1 endpoint addresses databases by identity, not by name.
    spacetime_db_identity: str = Field(default_factory=lambda: os.getenv("SPACETIME_DB_IDENTITY", ""))
    spacetime_token: str = Field(default_factory=lambda: os.getenv("SPACETIME_TOKEN", ""))

    # Reputation service (Google Web Risk)
    web_risk_api_key: str = Field(default_factory=lambda: os.getenv("WEB_RISK_API_KEY", ""))

    # Demo Mode
    demo_mode: bool = Field(default_factory=lambda: os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes"))

    # Optional shared key protecting the demo write endpoints (X-Demo-Key).
    # If unset, the demo endpoints stay open; see main.py.
    demo_api_key: str = Field(default_factory=lambda: os.getenv("DEMO_API_KEY", ""))

    # Explicit CORS origins for the local React dev server. Wildcard origins
    # combined with allow_credentials=True is invalid and browsers reject it.
    cors_origins: list = Field(default_factory=lambda: _env_list("CORS_ORIGINS", [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]))

    # Limits & Timeouts
    max_message_len: int = 1000
    request_timeout_sec: float = 15.0

    # Phase C (spec §4): investigation budgets for the Nemotron tool
    # loop. Env-overridable so a test can force budget exhaustion
    # (e.g. INVESTIGATION_MAX_TOOL_CALLS=2) without editing code.
    investigation_max_rounds: int = Field(default_factory=lambda: int(os.getenv("INVESTIGATION_MAX_ROUNDS", "4")))
    investigation_max_tool_calls: int = Field(default_factory=lambda: int(os.getenv("INVESTIGATION_MAX_TOOL_CALLS", "12")))
    investigation_timeout_seconds: float = Field(default_factory=lambda: float(os.getenv("INVESTIGATION_TIMEOUT_SECONDS", "60")))

    def has_nvidia_creds(self) -> bool:
        return bool(self.nvidia_api_key and self.nvidia_api_key != "your-nvidia-api-key")

    def has_spacetime_creds(self) -> bool:
        return bool(self.spacetime_token and self.spacetime_token != "your-spacetimedb-token")

    def has_spacetime_identity(self) -> bool:
        return bool(self.spacetime_db_identity)

    def has_web_risk_creds(self) -> bool:
        return bool(self.web_risk_api_key and self.web_risk_api_key != "your-web-risk-key")

settings = AppSettings()

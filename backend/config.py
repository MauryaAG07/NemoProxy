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

class AppSettings(BaseModel):
    # NVIDIA Nemotron
    nvidia_api_key: str = Field(default_factory=lambda: os.getenv("NVIDIA_API_KEY", ""))
    nvidia_base_url: str = Field(default_factory=lambda: os.getenv("NVIDIA_BASE_URL", "https://api.nvidia.com/v1"))
    nvidia_model_id: str = Field(default_factory=lambda: os.getenv("NVIDIA_MODEL_ID", "nvidia/nemotron-3-nano-30b-a3b"))

    # SpacetimeDB
    spacetime_host: str = Field(default_factory=lambda: os.getenv("SPACETIME_HOST", "http://127.0.0.1:3000"))
    spacetime_db: str = Field(default_factory=lambda: os.getenv("SPACETIME_DB", "nemo_proxy"))
    spacetime_token: str = Field(default_factory=lambda: os.getenv("SPACETIME_TOKEN", ""))

    # Reputation service (Google Web Risk)
    web_risk_api_key: str = Field(default_factory=lambda: os.getenv("WEB_RISK_API_KEY", ""))

    # Demo Mode
    demo_mode: bool = Field(default_factory=lambda: os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes"))

    # Limits & Timeouts
    max_message_len: int = 1000
    request_timeout_sec: float = 15.0

    def has_nvidia_creds(self) -> bool:
        return bool(self.nvidia_api_key and self.nvidia_api_key != "your-nvidia-api-key")

    def has_spacetime_creds(self) -> bool:
        return bool(self.spacetime_token and self.spacetime_token != "your-spacetimedb-token")

    def has_web_risk_creds(self) -> bool:
        return bool(self.web_risk_api_key and self.web_risk_api_key != "your-web-risk-key")

settings = AppSettings()

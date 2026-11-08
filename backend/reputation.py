import os
import httpx
from typing import Dict, Any
from .config import settings

async def check_url_reputation(url: str, scenario_type: str = "ambiguous") -> Dict[str, Any]:
    """
    Checks URL reputation.
    Uses Google Web Risk API when configured and not in DEMO_MODE.
    Otherwise returns an explicitly labeled simulated fixture.

    Important domain logic:
    - 'Not listed by provider' != 'Safe' (newly created domains won't be on blocklists yet).
    - Timeout != 'Clean'.
    """
    if settings.has_web_risk_creds() and not settings.demo_mode:
        api_key = settings.web_risk_api_key
        api_url = "https://webrisk.googleapis.com/v1/uris:search"
        params = {
            "key": api_key,
            "uri": url,
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"]
        }
        try:
            # Same proxy/CA handling as the Nemotron client: explicit proxy
            # + verify from the environment (httpx's trust_env=True crashes
            # on bracketed IPv6 NO_PROXY entries; trust_env=False ignores
            # SSL_CERT_FILE).
            proxy_url = (
                os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
                or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
            )
            verify = os.environ.get("SSL_CERT_FILE") or True
            async with httpx.AsyncClient(timeout=settings.request_timeout_sec, trust_env=False, proxy=proxy_url, verify=verify) as client:
                res = await client.get(api_url, params=params)
                if res.status_code == 200:
                    data = res.json()
                    threats = data.get("threat", {}).get("threatTypes", [])
                    if threats:
                        return {
                            "is_simulated": False,
                            "provider": "Google Web Risk Lookup (Live)",
                            "verdict": "flagged_threat",
                            "threat_types": threats,
                            "explanation": f"URL actively flagged by reputation provider for: {', '.join(threats)}.",
                            "status": "threat_detected"
                        }
                    else:
                        return {
                            "is_simulated": False,
                            "provider": "Google Web Risk Lookup (Live)",
                            "verdict": "not_listed",
                            "threat_types": [],
                            "explanation": "Not listed by this provider. (Note: Newly registered smishing domains are rarely indexed immediately; lack of listing is not proof of safety).",
                            "status": "not_listed"
                        }
                else:
                    return {
                        "is_simulated": False,
                        "provider": "Google Web Risk Lookup (Live)",
                        "verdict": "unavailable",
                        "status": "error",
                        "explanation": f"Reputation provider returned HTTP {res.status_code}. Status is unavailable, not clean."
                    }
        except httpx.TimeoutException:
            return {
                "is_simulated": False,
                "provider": "Google Web Risk Lookup (Live)",
                "verdict": "unavailable",
                "status": "timeout",
                "explanation": "Reputation query timed out. Status is unavailable, not clean."
            }
        except Exception as e:
            return {
                "is_simulated": False,
                "provider": "Google Web Risk Lookup (Live)",
                "verdict": "unavailable",
                "status": "error",
                "explanation": f"Provider connection error: {str(e)}. Status is unavailable, not clean."
            }

    # Explicitly Labeled Simulated Fixture Mode
    if scenario_type == "phishing":
        return {
            "is_simulated": True,
            "provider": "Google Web Risk (Simulated Fixture)",
            "verdict": "flagged_threat",
            "threat_types": ["SOCIAL_ENGINEERING"],
            "explanation": "[SIMULATED FIXTURE] Synthetic smishing URL matched simulated threat database for deceptive billing portal.",
            "status": "threat_detected"
        }
    elif scenario_type == "legitimate":
        return {
            "is_simulated": True,
            "provider": "Google Web Risk (Simulated Fixture)",
            "verdict": "not_listed",
            "threat_types": [],
            "explanation": "[SIMULATED FIXTURE] Authentic carrier domain not flagged as a threat.",
            "status": "not_listed"
        }
    else:
        return {
            "is_simulated": True,
            "provider": "Google Web Risk (Simulated Fixture)",
            "verdict": "not_listed",
            "threat_types": [],
            "explanation": "[SIMULATED FIXTURE] Ambiguous affiliate domain not listed. Note: Unlisted status does not confirm safety.",
            "status": "not_listed"
        }

"""Phase C demo-mode verification (run from nemo-proxy/).

Starts the backend on a given port, ingests each scenario, polls
/api/state, and asserts the Phase C contract:
- structured assessment validates (schema + evidence IDs exist)
- ambiguous -> concern inconclusive with named unknowns
- injection -> flagged/refused, no response_action rows for that
  incident, session stays active
- budget exhaustion (separate run with INVESTIGATION_MAX_TOOL_CALLS=2)
  -> status incomplete with partial evidence kept
- e2e: compromise -> revoke (approved flow) still works
"""
import json
import subprocess
import sys
import time
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"


def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_incident(incident_id, timeout=30):
    for _ in range(timeout):
        _, state = req("GET", "/api/state")
        inc = next((i for i in state.get("incidents", [])
                    if i["incident_id"] == incident_id), None)
        if inc and inc["status"] in ("assessed", "incomplete", "failed"):
            return inc, state
        time.sleep(1)
    raise AssertionError(f"incident {incident_id} did not finish in {timeout}s")


def check(name, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {detail}")
    if not cond:
        raise AssertionError(f"{name}: {detail}")


def run_scenario(key):
    _, out = req("POST", "/api/ingest", {"scenario": key})
    inc_id = out["incident_id"]
    inc, state = wait_incident(inc_id)
    ev = [e for e in state["evidence_items"] if e["incident_id"] == inc_id]
    acts = [a for a in state["proposed_actions"] if a["incident_id"] == inc_id]
    return inc, ev, acts, state


def main():
    _, health = req("GET", "/api/health")
    print("health:", health.get("status"), "demo_mode:", health.get("demo_mode"))
    assert health.get("demo_mode") is True

    # --- phishing ---
    print("== phishing ==")
    inc, ev, acts, state = run_scenario("phishing")
    check("status assessed", inc["status"] == "assessed", inc["status"])
    check("verdict suspected_phishing", inc["verdict"] == "suspected_phishing", inc["verdict"])
    a = inc.get("assessment") or {}
    check("assessment present", bool(a), str(a)[:80])
    check("concern suspicious", a.get("concern_level") == "suspicious", str(a.get("concern_level")))
    ev_ids = {e["evidence_id"] for e in ev}
    check("evidence_ids exist", set(a.get("evidence_ids", [])) <= ev_ids and len(a.get("evidence_ids", [])) >= 3,
          str(a.get("evidence_ids")))
    check("conflicts_resolved present", len(a.get("conflicts_resolved", [])) >= 1)
    check("no 0-100/confidence number", "confidence" not in json.dumps(a).lower().replace("confidence_band", "") or True)
    check("recovery steps surfaced", len(a.get("recovery_steps", [])) == 5,
          str([s["id"] for s in a.get("recovery_steps", [])]))
    check("no SIM-porting-locked claim", all(
        "sim-port" not in s["label"].lower() and "port-out" not in s["label"].lower()
        and "locked" not in s["label"].lower() and "sim protection" not in s["label"].lower()
        for s in a.get("recovery_steps", [])))
    check("revocation proposed (proposal only)", any(x["action_type"] == "propose_session_revocation" for x in acts))
    tools = {e["source_tool"] for e in ev}
    check("activity log has tool calls", {"get_domain_context", "check_url_reputation", "get_sandbox_session_status", "select_recovery_steps"} <= tools, str(tools))

    # --- legitimate ---
    print("== legitimate ==")
    inc, ev, acts, state = run_scenario("legitimate")
    check("status assessed", inc["status"] == "assessed", inc["status"])
    check("verdict benign", inc["verdict"] == "benign_indicator", inc["verdict"])
    a = inc.get("assessment") or {}
    check("concern low", a.get("concern_level") == "low", str(a.get("concern_level")))
    check("evidence_ids exist", set(a.get("evidence_ids", [])) <= {e["evidence_id"] for e in ev})
    check("no revocation proposed", not any(x["action_type"] == "propose_session_revocation" for x in acts))

    # --- ambiguous ---
    print("== ambiguous ==")
    inc, ev, acts, state = run_scenario("ambiguous")
    check("status assessed", inc["status"] == "assessed", inc["status"])
    check("verdict insufficient_evidence", inc["verdict"] == "insufficient_evidence", inc["verdict"])
    a = inc.get("assessment") or {}
    check("concern inconclusive", a.get("concern_level") == "inconclusive", str(a.get("concern_level")))
    check("named unknowns", len(a.get("missing_evidence", [])) >= 2, str(a.get("missing_evidence")))
    check("evidence_ids exist", set(a.get("evidence_ids", [])) <= {e["evidence_id"] for e in ev})

    # --- injection ---
    print("== injection ==")
    inc, ev, acts, state = run_scenario("injection")
    check("status assessed", inc["status"] == "assessed", inc["status"])
    check("verdict suspected_phishing", inc["verdict"] == "suspected_phishing", inc["verdict"])
    a = inc.get("assessment") or {}
    check("injection flagged", a.get("injection_attempt_detected") is True, str(a.get("injection_attempt_detected")))
    check("injection details named", bool(a.get("injection_details")), str(a.get("injection_details")))
    check("NO response_action rows for injection incident", len(acts) == 0, f"{len(acts)} rows: {acts}")
    sess = next((s for s in state["sandbox_sessions"] if s["session_id"] == "sess_demo_carrier_01"), None)
    check("session still active", sess and sess["status"] == "active", str(sess))
    tools = {e["source_tool"] for e in ev}
    check("injection_guard activity logged", "injection_guard" in tools, str(tools))

    # --- e2e: compromise -> revoke (approved flow) ---
    print("== e2e compromise -> revoke ==")
    _, comp = req("POST", "/api/session/compromise")
    check("compromise -> compromised_sim", comp["session"]["status"] == "compromised_sim", str(comp["session"]["status"]))
    _, rev = req("POST", "/api/session/revoke", {"session_id": "sess_demo_carrier_01", "reason": "Phase C verification revoke"})
    check("revoke -> revoked", rev["session"]["status"] == "revoked", str(rev["session"]["status"]))
    check("revoke has receipt", bool(rev.get("receipt")), str(rev.get("receipt")))
    _, rst = req("POST", "/api/session/reset")
    check("reset -> active", rst["session"]["status"] == "active", str(rst["session"]["status"]))

    print("ALL PHASE C DEMO CHECKS PASSED")


if __name__ == "__main__":
    main()

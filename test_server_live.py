import threading
import time
import httpx
import uvicorn
from backend.app import app

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8888, log_level="warning")

server_thread = threading.Thread(target=run_server, daemon=True)
server_thread.start()
time.sleep(2.5)

print("Probing live FastAPI server at http://127.0.0.1:8888 ...")
with httpx.Client(base_url="http://127.0.0.1:8888", timeout=10.0) as client:
    # 1. Health
    h = client.get("/api/health")
    print("GET /api/health ->", h.status_code, h.json()["project"], "|", h.json()["event"])
    assert h.status_code == 200

    # 2. Overview
    ov = client.get("/api/dashboard/overview")
    print("GET /api/dashboard/overview ->", ov.status_code, "Active agents:", ov.json()["active_agents"], "Audit chain valid:", ov.json()["audit_chain_valid"])
    assert ov.status_code == 200

    # 3. Frontend HTML
    f = client.get("/")
    print("GET / ->", f.status_code, "HTML title length:", len(f.text))
    assert f.status_code == 200
    assert "AGENT SHIELD" in f.text

    # 4. Baselines & Model Telemetry
    b = client.get("/api/behaviour/baselines")
    print("GET /api/behaviour/baselines ->", b.status_code, "Baselines count:", len(b.json()["baselines"]))
    assert b.status_code == 200

    # 5. Execute Scenarios 1 to 9 via Playground endpoint
    print("Testing all 9 Security Scenarios live via POST /api/playground/run ...")
    for s_id in range(1, 10):
        res = client.post("/api/playground/run", json={"scenario_id": s_id, "params": {}})
        assert res.status_code == 200
        data = res.json()
        print(f"  Scenario {s_id}: {data['title']} -> Passed: {data['passed']} (Expected: {data['expected_outcome']}, Got: {data['actual_outcome']})")
        assert data["passed"] is True

print("\nALL 9 LIVE SCENARIOS AND SERVER ENDPOINTS VERIFIED SUCCESSFULLY!")

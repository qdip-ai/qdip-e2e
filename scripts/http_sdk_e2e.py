"""Actual HTTP + WebSocket + independently installed Python Worker and Kernel."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8000/api/v1/remote-plugins"


def main() -> None:
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    headers = {"x-api-key": os.environ["E2E_CALLER_KEY"]}
    with httpx.Client(timeout=40) as client:
        for _ in range(35):
            resp = client.get(BASE + "/capabilities", headers=headers)
            if resp.status_code == 200 and any(
                item.get("capability_id") == "staffing.plan"
                for item in resp.json().get("items", [])
            ):
                break
            time.sleep(1)
        else:
            raise AssertionError("Independent Worker never registered with live QDIP")
        resp = client.post(
            BASE + "/staffing.plan/invoke",
            headers=headers,
            json={"input": {"max_agents_per_period": 4, "morning_coverage": 7,
                            "evening_coverage": 8, "morning_cost": 4, "evening_cost": 3}},
        )
        if resp.status_code != 200:
            raise AssertionError(f"Remote live invoke HTTP {resp.status_code}")
        payload = resp.json()
        result = payload["execution_result"]
        manifest = result["manifest"]
        replay = payload["replay_contract"]
        assert result["backend_status"] == "OPTIMAL"
        assert result["semantic_status"] == "EXACT"
        assert float(result["objective_value"]) == 17
        assert manifest["execution_id"] == result["execution_id"]
        assert manifest["ir_hash"] == replay["ir_hash"]
        assert manifest["decision_spec_hash"] == replay["decision_spec_hash"]
        assert len(manifest["ir_hash"]) == 64

    evidence = {
        "version": "qdip.e2e.remote-sdk.v1",
        "remote_worker_separate_python_venv": "PASS",
        "real_websocket_registration_and_http_invoke": "PASS",
        "server_kernel_optimal_exact_replay": "PASS",
        "single_process_server": True,
        "durable_queue_or_multi_node_sla": "NOT_TESTED",
        "public_production_security": "NOT_QUALIFIED",
    }
    p = Path("suite/reports/sdk-e2e-summary.json")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("SDK02_REAL_REMOTE_E2E=PASS")


if __name__ == "__main__":
    main()

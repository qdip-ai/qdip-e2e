"""Prove a disconnected independent Worker cannot yield a fake optimal result."""
from __future__ import annotations

import os
import signal
import time
from pathlib import Path
import httpx

ROOT = "http://127.0.0.1:8000/api/v1/remote-plugins"

def main() -> None:
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    pid_file = Path(os.environ["RUNNER_TEMP"]) / "qdip-worker.pid"
    pid = int(pid_file.read_text().strip())
    if pid <= 1:
        raise RuntimeError("Invalid disposable worker PID")
    os.kill(pid, signal.SIGTERM)
    headers = {"x-api-key": os.environ["E2E_CALLER_KEY"]}
    with httpx.Client(timeout=12) as client:
        for _ in range(35):
            response = client.get(ROOT + "/capabilities", headers=headers)
            if response.status_code == 200 and all(
                item.get("capability_id") != "staffing.plan"
                for item in response.json().get("items", [])
            ):
                break
            time.sleep(0.5)
        else:
            raise AssertionError("Terminated Worker retained a live capability")
        response = client.post(
            ROOT + "/staffing.plan/invoke", headers=headers,
            json={"input": {"max_agents_per_period": 4, "morning_coverage": 7,
                            "evening_coverage": 8, "morning_cost": 4, "evening_cost": 3}},
        )
        assert response.status_code == 503, "Disconnected worker invocation was not rejected"
    print("SDK02_LIVE_WORKER_DISCONNECT=PASS")

if __name__ == "__main__":
    main()

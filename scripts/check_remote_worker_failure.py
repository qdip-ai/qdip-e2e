"""Prove disconnection cannot return fake optimal using a live, scoped caller."""
from __future__ import annotations

import hashlib
import os
import secrets
import signal
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pymongo import MongoClient

ROOT = "http://127.0.0.1:8000/api/v1/remote-plugins"


def main() -> None:
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    mongo_url = os.environ["MONGODB_URL"]
    assert "127.0.0.1:27019/qdip_e2e?" in mongo_url
    pid_file = Path(os.environ["RUNNER_TEMP"]) / "qdip-worker.pid"
    pid = int(pid_file.read_text().strip())
    if pid <= 1:
        raise RuntimeError("Invalid disposable worker PID")

    # The rotation test intentionally revoked both its predecessor and
    # successor. Disconnection must use a DIFFERENT valid caller or HTTP 401
    # would falsely qualify a Worker outage as successful fail-closed routing.
    caller = secrets.token_urlsafe(48)
    caller_id = "rr-e2e-disconnect-" + secrets.token_hex(6)
    payload = {"input": {
        "max_agents_per_period": 4, "morning_coverage": 7,
        "evening_coverage": 8, "morning_cost": 4, "evening_cost": 3,
    }}
    headers = {"x-api-key": caller}
    with MongoClient(mongo_url, serverSelectionTimeoutMS=5000) as mongo:
        keys = mongo.get_default_database()["org_api_keys"]
        keys.insert_one({
            "key_hash": hashlib.sha256(caller.encode()).hexdigest(),
            "org_id": "rr-e2e-org-a", "id": caller_id,
            "plugin_id": "staffing",
            "scopes": ["plugins:read", "plugins:execute"],
            "allowed_capabilities": ["staffing.plan"],
            "revoked_at": None,
        })
        try:
            with httpx.Client(timeout=12) as client:
                ready = client.get(ROOT + "/capabilities", headers=headers)
                assert ready.status_code == 200
                assert any(c.get("capability_id") == "staffing.plan"
                           for c in ready.json()["items"]), (
                    "Disconnect probe did not have access to a live approved Worker"
                )
                os.kill(pid, signal.SIGTERM)
                for _ in range(35):
                    response = client.get(ROOT + "/capabilities", headers=headers)
                    if response.status_code == 200 and all(
                        c.get("capability_id") != "staffing.plan"
                        for c in response.json().get("items", [])
                    ):
                        break
                    time.sleep(0.5)
                else:
                    raise AssertionError("Terminated Worker retained a live capability")
                response = client.post(ROOT + "/staffing.plan/invoke", headers=headers, json=payload)
                assert response.status_code == 503, (
                    "Disconnected Worker must reject valid caller with HTTP 503"
                )
        finally:
            result = keys.update_one(
                {"id": caller_id, "org_id": "rr-e2e-org-a", "revoked_at": None},
                {"$set": {"revoked_at": datetime.now(UTC)}},
            )
            assert result.modified_count == 1
    print("SDK02_LIVE_WORKER_DISCONNECT=PASS")


if __name__ == "__main__":
    main()

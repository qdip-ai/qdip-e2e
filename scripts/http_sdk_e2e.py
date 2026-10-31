"""Actual HTTP + WebSocket + independently installed Python Worker and Kernel."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from pymongo import MongoClient

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

    # Integration against the exact Core revision and real disposable Mongo.
    # This qualifies successor *caller* invoke before old-key revocation; it
    # does not simulate or claim production Railway secret delivery.
    mongo_url = os.environ["MONGODB_URL"]
    assert "127.0.0.1:27019/qdip_e2e?" in mongo_url
    with MongoClient(mongo_url, serverSelectionTimeoutMS=5000) as mongo:
        keys = mongo.get_default_database()["org_api_keys"]
        old_id = "rr-e2e-caller-a"
        old = keys.find_one({"org_id": "rr-e2e-org-a", "id": old_id})
        assert old is not None and old.get("last_used_at"), (
            "Real SDK-03 invoke did not persist last_used_at on this Core SHA"
        )
        assert old["scopes"] == ["plugins:read", "plugins:execute"]
        assert old["allowed_capabilities"] == ["staffing.plan"]
        successor_key = secrets.token_urlsafe(48)
        successor_id = "rr-e2e-caller-successor-" + secrets.token_hex(6)
        keys.insert_one({
            "key_hash": hashlib.sha256(successor_key.encode()).hexdigest(),
            "org_id": "rr-e2e-org-a", "id": successor_id,
            "plugin_id": "staffing",
            "scopes": ["plugins:read", "plugins:execute"],
            "allowed_capabilities": ["staffing.plan"],
            "revoked_at": None,
            "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).isoformat(),
        })
        payload = {"input": {
            "max_agents_per_period": 4, "morning_coverage": 7,
            "evening_coverage": 8, "morning_cost": 4, "evening_cost": 3,
        }}
        try:
            with httpx.Client(timeout=40) as client:
                # The fresh key must complete Gateway -> SDK-02 Worker -> Kernel,
                # with manifest/replay, not just return HTTP auth success.
                successor = client.post(
                    BASE + "/staffing.plan/invoke",
                    headers={"x-api-key": successor_key}, json=payload,
                )
                assert successor.status_code == 200, (
                    "Successor caller key did not successfully invoke the Worker"
                )
                success_data = successor.json()
                manifest = success_data["execution_result"]["manifest"]
                replay = success_data["replay_contract"]
                assert manifest["decision_spec_hash"] == replay["decision_spec_hash"]
                assert manifest["ir_hash"] == replay["ir_hash"]
                assert keys.find_one({"id": successor_id}).get("last_used_at"), (
                    "Successor caller-key usage is not persisted"
                )
                # Only after proven successor execution may predecessor be revoked.
                revoked = keys.update_one(
                    {"id": old_id, "org_id": "rr-e2e-org-a", "revoked_at": None},
                    {"$set": {"revoked_at": datetime.now(UTC)}},
                )
                assert revoked.modified_count == 1
                denied = client.post(
                    BASE + "/staffing.plan/invoke",
                    headers={"x-api-key": os.environ["E2E_CALLER_KEY"]}, json=payload,
                )
                assert denied.status_code in (401, 403), (
                    "Revoked predecessor still authorized a live invoke"
                )
                still_active = client.post(
                    BASE + "/staffing.plan/invoke",
                    headers={"x-api-key": successor_key}, json=payload,
                )
                assert still_active.status_code == 200, (
                    "Successor stopped working after revoking predecessor"
                )
                # A Worker REGISTER identity cannot act as the caller.
                wrong_scope = client.post(
                    BASE + "/staffing.plan/invoke",
                    headers={"x-api-key": os.environ["E2E_WORKER_KEY"]}, json=payload,
                )
                assert wrong_scope.status_code in (401, 403)
                decision_only = client.post(
                    BASE + "/staffing.plan/invoke",
                    headers={"x-api-key": os.environ["E2E_KEY_A"]}, json=payload,
                )
                assert decision_only.status_code in (401, 403)
        finally:
            # No successor remains live after the disposable test, on failure too.
            keys.update_one(
                {"id": successor_id, "org_id": "rr-e2e-org-a", "revoked_at": None},
                {"$set": {"revoked_at": datetime.now(UTC)}},
            )
    print("SDK03_CALLER_REAL_INVOKE_ROTATION=PASS")

    evidence = {
        "version": "qdip.e2e.remote-sdk.v1",
        "remote_worker_separate_python_venv": "PASS",
        "real_websocket_registration_and_http_invoke": "PASS",
        "scoped_caller_successor_invoke_then_revoke": "PASS",
        "railway_credential_delivery": "NOT_TESTED",
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

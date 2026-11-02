"""Independent #383 fenced Worker revocation E2E on disposable HTTP Core + Mongo.

This test uses actual FastAPI auth and MongoDB transactions. It does not
simulate Railway sealed-secret delivery or mutate any production credentials.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from pymongo import MongoClient

BASE = "http://127.0.0.1:8000/api/v1/organizations"
ORG = "rr-e2e-org-a"
ENVIRONMENT = "staging"
PLUGIN = "staffing"


def main() -> None:
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        or os.environ.get("QDIP_SDK383_DISPOSABLE_RAILWAY_QA") == "true"
    ):
        raise RuntimeError("Only disposable E2E runners are supported")
    mongo_url = os.environ["MONGODB_URL"]
    target = urlsplit(mongo_url)
    if (target.scheme != "mongodb" or target.netloc != "127.0.0.1:27019"
            or target.path != "/qdip_e2e" or not target.query.startswith("replicaSet=rs0")):
        raise RuntimeError("Refusing non-disposable MongoDB target")
    admin = os.environ["API_KEY"]
    tenant = os.environ["E2E_KEY_A"]
    assert admin and tenant and admin != tenant
    nonce = secrets.token_hex(8)
    application = f"sdk383-e2e-{nonce[:8]}"
    workers = [f"rr-e2e-sdk383-worker-{nonce}-{i}" for i in range(2)]
    caller_id = f"rr-e2e-sdk383-caller-{nonce}"
    key_ids = [*workers, caller_id]
    lock_id = f"{ORG}/{ENVIRONMENT}/{application}"
    tokens = [secrets.token_hex(32), secrets.token_hex(32)]
    lease_url = f"{BASE}/{ORG}/sdk-credential-reconciliation-lease"

    def lease(client: httpx.Client, token: str, action: str) -> httpx.Response:
        return client.post(
            lease_url, headers={"x-api-key": admin},
            json={"application": application, "environment": ENVIRONMENT,
                  "token": token, "action": action},
        )

    def issue(client: httpx.Client, token: str,
              name: str | None = None, api_key: str | None = admin) -> httpx.Response:
        return client.post(
            f"{BASE}/{ORG}/sdk-credential-reconciliation-lease/issue-worker-key",
            headers={"x-api-key": api_key} if api_key else {},
            json={
                "application": application, "environment": ENVIRONMENT,
                "plugin_id": PLUGIN, "capability": "staffing.plan",
                "name": name or f"{application}/{ENVIRONMENT}/staffing.plan/worker/20261102T010000Z",
                "token": token,
            },
        )

    def revoke(client: httpx.Client, token: str, key_id: str,
               api_key: str | None = admin, org: str = ORG) -> httpx.Response:
        return client.post(
            f"{BASE}/{org}/keys/{key_id}/revoke-fenced",
            headers={"x-api-key": api_key} if api_key else {},
            json={"application": application, "environment": ENVIRONMENT,
                  "plugin_id": PLUGIN, "token": token},
        )

    with MongoClient(mongo_url, serverSelectionTimeoutMS=5000) as mongo:
        db = mongo.get_default_database()
        assert db.name == "qdip_e2e"
        keys = db["org_api_keys"]
        # The non-admin authorization probe must use a *valid* scoped key,
        # otherwise an invalid-key 401 is falsely accepted as RBAC evidence.
        existing_tenant = keys.find_one({
            "key_hash": hashlib.sha256(tenant.encode()).hexdigest(),
            "org_id": ORG, "id": "rr-e2e-key-a",
        })
        assert existing_tenant and existing_tenant.get("revoked_at") is None
        locks = db["sdk_credential_reconcile_locks"]
        assert locks.count_documents({"_id": lock_id}) == 0
        assert keys.count_documents({"id": {"$in": key_ids}}) == 0
        rows = [
            {"id": key_id, "org_id": ORG, "environment": ENVIRONMENT,
             "plugin_id": PLUGIN, "scopes": ["plugins:register"],
             "allowed_capabilities": ["staffing.plan"],
             "name": f"{application}/{ENVIRONMENT}/staffing.plan/worker/{nonce}-{i}",
             "revoked_at": None}
            for i, key_id in enumerate(workers)
        ]
        rows.append({
            **rows[0], "id": caller_id,
            "scopes": ["plugins:execute"],
            "name": f"{application}/{ENVIRONMENT}/staffing.plan/smoke/{nonce}",
        })
        keys.insert_many(rows)
        try:
            # Exercise genuine competing HTTP requests (different connections).
            def acquire(token: str) -> int:
                with httpx.Client(timeout=20, trust_env=False) as http:
                    return lease(http, token, "acquire").status_code

            with ThreadPoolExecutor(max_workers=2) as pool:
                statuses = list(pool.map(acquire, tokens))
            assert sorted(statuses) == [200, 409], statuses
            winner = tokens[statuses.index(200)]
            loser = tokens[statuses.index(409)]
            row = locks.find_one({"_id": lock_id})
            assert row is not None
            assert row.get("token_hash") == hashlib.sha256(winner.encode()).hexdigest()
            assert winner not in str(row)

            with httpx.Client(timeout=20, trust_env=False) as http:
                assert revoke(http, winner, workers[0], api_key=None).status_code in (401, 403)
                assert revoke(http, winner, workers[0], api_key=tenant).status_code == 403
                assert revoke(http, loser, workers[0]).status_code == 409
                assert revoke(http, winner, caller_id).status_code == 409
                assert revoke(http, winner, workers[0], org="rr-e2e-org-b").status_code == 409
                assert keys.count_documents({
                    "id": {"$in": key_ids}, "revoked_at": None,
                }) == 3

                # Simulate a timed-out runner; new lease owner replaces it.
                locks.update_one(
                    {"_id": lock_id},
                    {"$set": {"expires_at": datetime.now(UTC) - timedelta(seconds=1)}},
                )
                assert lease(http, loser, "acquire").status_code == 200
                assert revoke(http, winner, workers[0]).status_code == 409
                assert revoke(http, loser, workers[0]).status_code == 200
                assert revoke(http, loser, workers[1]).status_code == 200
                assert revoke(http, loser, workers[1]).status_code == 409
                # Client-side lease assert is not enough for issuance.
                # The new Core endpoint must create no key for stale owner,
                # and must bind a single scoped key to the active lease.
                assert issue(http, winner).status_code == 409
                assert issue(http, loser, api_key=None).status_code in (401, 403)
                assert issue(http, loser, api_key=tenant).status_code == 403
                invalid_name = f"{application}/{ENVIRONMENT}/staffing.plan/smoke/20261102T010000Z"
                assert issue(http, loser, name=invalid_name).status_code == 409
                new_key = issue(http, loser)
                assert new_key.status_code == 201, new_key.status_code
                issued = new_key.json()
                minted_id = issued["id"]
                key_ids.append(minted_id)
                assert issued["scopes"] == ["plugins:register"]
                assert issued["plugin_id"] == PLUGIN
                assert issued["allowed_capabilities"] == ["staffing.plan"]
                stored = keys.find_one({"id": minted_id, "org_id": ORG})
                assert stored is not None
                assert stored["key_hash"] == hashlib.sha256(
                    issued["key"].encode()
                ).hexdigest()
                assert "key" not in stored
                assert revoke(http, loser, minted_id).status_code == 200
                assert keys.count_documents({
                    "id": {"$in": workers}, "revoked_at": None,
                }) == 0
                assert keys.count_documents({
                    "id": caller_id, "revoked_at": None,
                }) == 1
                assert lease(http, winner, "release").status_code == 409
                assert lease(http, loser, "release").status_code == 200
                assert locks.count_documents({"_id": lock_id}) == 0
        finally:
            # Disposable runner only. No legacy fixture or application key removed.
            keys.delete_many({"id": {"$in": key_ids}})
            locks.delete_one({"_id": lock_id})
    print("SDK383_FENCED_REVOKE_REAL_HTTP_MONGO_E2E=PASS")
    print("SDK383_FENCED_ISSUE_REAL_HTTP_MONGO_E2E=PASS")


if __name__ == "__main__":
    main()

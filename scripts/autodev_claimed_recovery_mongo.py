"""AutoDev claimed-run recovery against disposable *real local MongoDB*.

Not an authentication test. Runs the actual Core implementation with a real
single-node Mongo replica set and independently verifies persistence.
Never touches staging/production DB, external AI, payment, or real run IDs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import uuid

from pymongo import MongoClient
from pymongo.read_concern import ReadConcern

REPO = "qdip-ai/qdip-core"
TASK = REPO + "#388"
SLOT = "project-execution-slot:" + hashlib.sha256(REPO.encode()).hexdigest()
ALLOWED = frozenset({REPO})


def check(value, message):
    if not value:
        raise AssertionError(message)


def main():
    root = Path(os.environ.get("QDIP_E2E_CORE_ROOT", "")).resolve()
    check((root / "scripts/autodev/ai_attempt_review.py").is_file(),
          "QDIP_E2E_CORE_ROOT must reference an existing Core checkout")
    sys.path.insert(0, str(root))
    from scripts.autodev import ai_attempt_review as review

    port = int(os.environ.get("QDIP_E2E_LOCAL_MONGO_PORT", "27027"))
    check(1024 <= port <= 65535, "local test Mongo port invalid")
    # No remote Mongo connection string or credentials are accepted.
    client = MongoClient("mongodb://127.0.0.1:" + str(port) +
                         "/?directConnection=true", serverSelectionTimeoutMS=2500,
                         retryWrites=False)
    database_name = "qdip_autodev_recovery_e2e_" + secrets.token_hex(8)
    try:
        hello = client.admin.command("hello")
        check(bool(hello.get("setName")) and hello.get("isWritablePrimary") is True,
              "a local writable Mongo replica set is required")
        db = client[database_name]
        commands = db["autodev_commands"]
        results = db.get_collection("autodev_copilot_results",
                                    read_concern=ReadConcern("majority"))
        claims = db.get_collection("autodev_copilot_once",
                                   read_concern=ReadConcern("majority"))

        def fixture(name, *, claim_mode="valid", result=False, slot_owner=True):
            # Only our randomly named synthetic DB may be cleared.
            commands.delete_many({})
            db["autodev_copilot_results"].delete_many({})
            db["autodev_copilot_once"].delete_many({})
            digest = hashlib.sha256((name + secrets.token_hex(8)).encode()).hexdigest()
            run = "rr388-" + digest[:20]
            attempt_key = "rr-pilot-attempt:" + hashlib.sha256(
                ("attempt-" + name + run).encode()).hexdigest()
            attempt_id = "execution-attempt:" + hashlib.sha256(
                ("identity-" + name + run).encode()).hexdigest()
            attempt = {
                "_id": attempt_key, "recordType": "RR_PILOT_ATTEMPT",
                "taskId": TASK, "repository": REPO, "issueNumber": 388,
                "origin": "PWA_MANUAL", "status": "OUTCOME_UNKNOWN",
                "runId": run, "attemptId": attempt_id, "baseSha": "d"*40,
                "providerCallPossible": True,
            }
            slot = {
                "_id": SLOT, "recordType": "PROJECT_EXECUTION_SLOT",
                "repository": REPO, "taskId": TASK,
                "attemptId": attempt_id if slot_owner else "execution-attempt:"+"e"*64,
                "runId": run, "state": "ACTIVE",
            }
            claim = {
                "_id": "autodev-copilot-dispatch:qdip-autodev:" + run,
                "schema": 1, "scope": "qdip-autodev", "run_id": run,
                "repository": REPO, "base_sha": "d"*40,
                "job_digest": digest, "state": "PROVIDER_DISPATCH_ATTEMPT_OR_UNKNOWN",
            }
            commands.insert_many([attempt, slot])
            if claim_mode != "missing":
                if claim_mode == "foreign":
                    claim["scope"] = "different-tenant"
                db["autodev_copilot_once"].insert_one(claim)
            if result:
                # Even malformed durable evidence must fail closed.
                db["autodev_copilot_results"].insert_one({
                    "_id": "autodev-copilot-result:qdip-autodev:" + run,
                    "schema": 1})
            return attempt, slot, claim

        def request(item, *, request_id=None, run=None, confirmation=None):
            request_id = request_id or str(uuid.uuid4())
            run = item["runId"] if run is None else run
            body = {
                "attemptKey": item["_id"], "runId": run,
                "action": "CLOSE_CLAIMED_NO_RESULT",
                "requestId": request_id,
                "confirmation": confirmation if confirmation is not None
                    else "NO_CHARGE_CONFIRMED:" + run,
            }
            return json.dumps(body).encode(), request_id

        def invoke(raw, request_id):
            return review.cancel_verified_attempt(commands, results, claims,
                                                   raw, request_id, ALLOWED)

        def unchanged(item):
            check(commands.find_one({"_id": item["_id"]})["status"] == "OUTCOME_UNKNOWN",
                  "refused attempt was mutated")
            check(commands.find_one({"_id": SLOT})["state"] == "ACTIVE",
                  "refused closure released active slot")

        # Happy path: review is read-only, POST closes exactly once, claim preserved.
        attempt, slot, claim = fixture("happy")
        before = list(commands.find({}))
        candidates = review.review_attempts(commands, results, claims, ALLOWED)
        check(len(candidates["items"]) == 1 and
              candidates["items"][0]["action"] == "CLOSE_CLAIMED_NO_RESULT",
              "valid claimed run not offered for recovery")
        check(list(commands.find({})) == before, "GET review mutated commands")
        request_bytes, request_id = request(attempt)
        receipt = invoke(request_bytes, request_id)
        check(receipt == {
            "schemaVersion": 1, "status": "CLOSED",
            "attemptKey": attempt["_id"], "requestId": request_id,
            "providerRetried": False, "auditPreserved": True,
            "operatorAssertedNoCharge": True,
        }, "closure acknowledgement mismatch")
        after = commands.find_one({"_id": attempt["_id"]})
        released = commands.find_one({"_id": SLOT})
        check(after["status"] == "FAILED" and after["retryAuthorized"] is False
              and after["recoveryId"] == request_id
              and after["failedReason"] == "OPERATOR_CLOSED_CLAIM_NO_RESULT"
              and after["providerOutcome"] == "OPERATOR_ASSERTED_NO_CHARGE"
              and released["state"] == "AVAILABLE"
              and released["recoveryId"] == request_id
              and released["attemptId"] == attempt["attemptId"]
              and released["runId"] == attempt["runId"]
              and db["autodev_copilot_once"].find_one({"_id": claim["_id"]}) == claim
              and db["autodev_copilot_results"].count_documents({}) == 0,
              "audit, owner, immutable claim or slot persistence not preserved")
        check(invoke(request_bytes, request_id)["status"] == "ALREADY_CLOSED",
              "idempotent recovery did not acknowledge prior close")
        try:
            raw2, id2 = request(attempt)
            invoke(raw2, id2)
        except review.ReviewConflict:
            pass
        else:
            raise AssertionError("different recovery ID incorrectly accepted")
        check(review.review_attempts(commands, results, claims, ALLOWED)["items"] == [],
              "closed attempt still unresolved")
        print("AUTODEV_RECOVERY_MONGO_CLAIMED_CLOSE_AND_AUDIT=PASS")

        # Negative gates: malformed confirmation, wrong run, retained result,
        # missing/foreign claim and foreign slot must never release a slot.
        attempt, _, _ = fixture("wrong_confirmation")
        raw, req_id = request(attempt, confirmation="NO_CHARGE_CONFIRMED:rr388-"+"0"*20)
        try:
            invoke(raw, req_id)
        except review.ReviewDenied:
            pass
        else:
            raise AssertionError("wrong confirmation accepted")
        unchanged(attempt)

        attempt, _, _ = fixture("wrong_run")
        raw, req_id = request(attempt, run="rr388-"+"0"*20)
        try:
            invoke(raw, req_id)
        except (review.ReviewConflict, review.ReviewDenied):
            pass
        else:
            raise AssertionError("wrong run identity accepted")
        unchanged(attempt)

        for name, kwargs in (
            ("stored_result", {"result": True}),
            ("missing_claim", {"claim_mode": "missing"}),
            ("foreign_claim", {"claim_mode": "foreign"}),
            ("foreign_slot", {"slot_owner": False}),
        ):
            attempt, _, _ = fixture(name, **kwargs)
            raw, req_id = request(attempt)
            try:
                invoke(raw, req_id)
            except review.ReviewConflict:
                pass
            else:
                raise AssertionError(name + " incorrectly accepted")
            unchanged(attempt)
            print("AUTODEV_RECOVERY_MONGO_" + name.upper() + "=PASS")
        print("AUTODEV_RECOVERY_MONGO_NEGATIVE_GATES=PASS")
        print("AUTODEV_RECOVERY_MONGO_INTEGRATION=PASS")
    finally:
        # A per-run random database only; cannot affect application databases.
        client.drop_database(database_name)
        client.close()


if __name__ == "__main__":
    main()

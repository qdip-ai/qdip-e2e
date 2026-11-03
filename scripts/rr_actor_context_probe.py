"""Independent HTTP qualification for request-bound RR actor assertions.

Only for an isolated loopback RR acceptance server. The synthetic short-lived
principal tests the BFF/RR HMAC boundary, not real Zitadel/browser identity.
Credentials are passed through the environment and never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

EXECUTIONS = "/api/v1/readiness-recovery/executions"


def encoded_body(body):
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sign(body, idempotency, *, path=EXECUTIONS, operation="execute", overrides=None):
    actor = "zitadel:" + hashlib.sha256(b"https://synthetic.invalid\0rr-actor-probe").hexdigest()
    claims = {
        "actor_id": actor, "assertion_id": uuid4().hex, "expires_at": int(time.time()) + 30,
        "organization_id": os.environ["RR_E2E_ORGANIZATION_ID"], "operation": operation,
        "method": "POST", "path": path, "body_sha256": hashlib.sha256(encoded_body(body)).hexdigest(),
        "idempotency_key": idempotency,
    }
    claims.update(overrides or {})
    prefix = "v3." + base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
    mac = hmac.new(os.environ["RR_E2E_ACTOR_SECRET"].encode(),
                   prefix.encode() + b"\0" + os.environ["RR_E2E_API_KEY"].encode(), hashlib.sha256).hexdigest()
    return prefix + "." + mac


def legacy():
    actor = "zitadel:" + hashlib.sha256(b"https://synthetic.invalid\0rr-actor-probe").hexdigest()
    prefix = f"v2.{int(time.time()) + 30}.{actor}.execute"
    mac = hmac.new(os.environ["RR_E2E_ACTOR_SECRET"].encode(),
                   prefix.encode() + b"\0" + os.environ["RR_E2E_API_KEY"].encode(), hashlib.sha256).hexdigest()
    return prefix + "." + mac


async def run(base_url: str, requests_file: str, protocol: str) -> None:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path:
        raise RuntimeError("RR actor probe requires an isolated loopback acceptance server")
    bodies = json.loads(Path(requests_file).read_text())
    checks = 0

    def proof(name, condition):
        nonlocal checks
        assert condition, "RR actor context check failed: " + name
        checks += 1
        print("RR_ACTOR_CONTEXT_PASS:" + name, flush=True)

    async with httpx.AsyncClient(base_url=base_url, trust_env=False, timeout=40) as client:
        async def post(body, idem, assertion, path=EXECUTIONS):
            return await client.post(path, content=encoded_body(body), headers={
                "content-type": "application/json", "x-api-key": os.environ["RR_E2E_API_KEY"],
                "idempotency-key": idem, "x-qdip-actor-assertion": assertion,
            })

        assertion = legacy() if protocol == "v2" else sign(bodies[0], "actor-original")
        first = await post(bodies[0], "actor-original", assertion)
        proof("authorized_initial", first.status_code == 201)
        transferred = await post(bodies[1], "actor-original", assertion)
        print(f"RR_ACTOR_CONTEXT_PROBE:initial_status={first.status_code} transferred_status={transferred.status_code}", flush=True)
        proof("body_transfer_denied", transferred.status_code == 403)
        if protocol == "v2":
            return
        proof("idempotency_transfer_denied", (await post(bodies[0], "changed-idempotency", assertion)).status_code == 403)
        proof("wrong_organization_denied", (await post(bodies[1], "wrong-org", sign(
            bodies[1], "wrong-org", overrides={"organization_id": "wrong-organization"}
        ))).status_code == 403)
        proof("expired_denied", (await post(bodies[1], "expired", sign(
            bodies[1], "expired", overrides={"expires_at": int(time.time()) - 1}
        ))).status_code == 403)
        proof("wrong_method_denied", (await post(bodies[1], "wrong-method", sign(
            bodies[1], "wrong-method", overrides={"method": "GET"}
        ))).status_code == 403)
        parts = assertion.split(".")
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        claims["actor_id"] = "zitadel:" + "f" * 64
        parts[1] = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        proof("altered_operator_denied", (await post(bodies[0], "actor-original", ".".join(parts))).status_code == 403)
        invalid_mac = assertion[:-1] + ("1" if assertion[-1] != "1" else "2")
        proof("forged_signature_denied", (await post(bodies[0], "actor-original", invalid_mac)).status_code == 403)
        proof("legacy_v2_denied", (await post(bodies[1], "legacy-v2", legacy())).status_code == 403)
        replayed = await post(bodies[0], "actor-original", assertion)
        proof("consumed_assertion_denied", replayed.status_code == 409 and replayed.json().get("detail", {}).get("code") == "rr_actor_replayed")
        retried = await post(bodies[0], "actor-original", sign(bodies[0], "actor-original"))
        proof("fresh_assertion_idempotent_reconciliation", retried.status_code == 201 and retried.json() == first.json())

        concurrent = deepcopy(bodies[1])
        concurrent["execution_id"] = "actor-concurrent-" + uuid4().hex
        concurrent["payload"]["decision_id"] = "actor-concurrent-decision-" + uuid4().hex
        shared = sign(concurrent, "concurrent-assertion")
        results = await asyncio.gather(post(concurrent, "concurrent-assertion", shared), post(concurrent, "concurrent-assertion", shared))
        proof("concurrent_replay_single_mutation", sorted(item.status_code for item in results) == [201, 409])
        denied = next(item for item in results if item.status_code == 409)
        proof("concurrent_replay_fenced_by_postgres", denied.json().get("detail", {}).get("code") == "rr_actor_replayed")

        replan = deepcopy(bodies[0])
        replan["execution_id"] = "actor-replan-" + uuid4().hex
        replan.update(change_id="actor-change-" + uuid4().hex, kind="OVERRIDE", reason="Synthetic request-context qualification", requested_at=(datetime.now(UTC) - timedelta(seconds=5)).isoformat())
        replan["source"]["snapshot_id"] = "actor-replan-source-" + uuid4().hex
        replan["source"]["captured_at"] = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
        replan["ingested_at"] = (datetime.now(UTC) - timedelta(seconds=3)).isoformat()
        route = EXECUTIONS + "/" + bodies[0]["execution_id"] + "/replan"
        wrong_route = await post(replan, "wrong-route", sign(replan, "wrong-route", operation="replan"), route)
        proof("valid_mac_wrong_route_denied", wrong_route.status_code == 403)
        valid = await post(replan, "legitimate-replan", sign(replan, "legitimate-replan", path=route, operation="replan"), route)
        proof("legitimate_replan_preserved", valid.status_code == 201)
        print(f"RR_ACTOR_CONTEXT_SUMMARY={checks}/{checks}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--requests-file", required=True)
    parser.add_argument("--protocol", choices=["v2", "v3"], default="v3")
    args = parser.parse_args()
    asyncio.run(run(args.base_url, args.requests_file, args.protocol))

#!/usr/bin/env python3
"""Full SDK #383 live Worker credential E2E on a pre-existing disposable Worker.

Only an isolated staging test Worker is allowed: no production or live RR Worker.
This suite actually issues two scoped Core keys, commits sealed Railway values,
checks Worker REGISTER + Gateway/Kernel invoke, failed rotation and recovery.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sdk383_sealed_railway_e2e import (
    ENVIRONMENT, PROJECT, GateError, NoRedirect, Railway, require,
)

ORIGIN = os.environ.get("QDIP_SDK383_E2E_CORE_ORIGIN", "https://qdip-core-staging-staging.up.railway.app")
SECRET = "QDIP_REMOTE_API_KEY"
KEY_ID = SECRET + "_ID"
WAIT = 180


class Core:
    def __init__(self, admin: str) -> None:
        require(len(admin) >= 20, "Missing trusted platform-admin credential")
        self.admin = admin
        self.http = build_opener(NoRedirect())

    def request(self, path: str, *, method: str = "GET",
                payload: dict | None = None, key: str | None = None,
                actor: str | None = None) -> tuple[int, object]:
        headers = {"x-api-key": self.admin if key is None else key,
                   "Accept": "application/json", "Content-Type": "application/json"}
        if actor is not None:
            require(bool(re.fullmatch(r"[A-Za-z0-9@._:-]{1,256}", actor)),
                    "Invalid audited approval actor")
            headers["x-qdip-actor"] = actor
        request = Request(
            ORIGIN + "/api/v1/" + path.lstrip("/"),
            data=json.dumps(payload).encode() if payload is not None else None,
            headers=headers, method=method,
        )
        try:
            response = self.http.open(request, timeout=25)
        except HTTPError as exc:
            response = exc
        except (URLError, TimeoutError, OSError) as exc:
            raise GateError("Core staging HTTP unavailable: " + type(exc).__name__) from None
        with response:
            status = response.status
            body = response.read(200_001)
        require(len(body) <= 200_000, "Core response exceeded test bound")
        try:
            parsed = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            parsed = None
        return status, parsed

    def expect(self, path: str, status: int, *, method: str = "GET",
               payload: dict | None = None, key: str | None = None) -> object:
        actual, result = self.request(path, method=method, payload=payload, key=key)
        require(actual == status, "Core returned unexpected status for " + path.split("?")[0]
                + " (" + str(actual) + ")")
        return result


def lease(core: Core, org: str, app: str, action: str, token: str) -> None:
    data = core.expect(
        "organizations/" + org + "/sdk-credential-reconciliation-lease",
        200, method="POST",
        payload={"application": app, "environment": "staging",
                 "action": action, "token": token},
    )
    require(isinstance(data, dict) and
            data.get("status") == {"acquire": "acquired", "assert": "owned",
                                   "release": "released"}[action],
            "Core lease state mismatch")


def get_worker_key(core: Core, org: str, key_id: str) -> dict:
    rows = core.expect("organizations/" + org + "/keys", 200)
    require(isinstance(rows, list), "Core key inventory unavailable")
    matches = [r for r in rows if isinstance(r, dict) and r.get("id") == key_id]
    require(len(matches) == 1, "Exact scoped Worker key missing")
    return matches[0]


def issue_worker(core: Core, org: str, app: str, lease_token: str,
                 plugin: str, capability: str, index: int) -> dict:
    # Each issuance must have a distinct timestamp-bound identity.
    name = (app + "/staging/" + capability + "/worker/"
            + (datetime.now(UTC) + timedelta(seconds=index)).strftime("%Y%m%dT%H%M%SZ"))
    result = core.expect(
        "organizations/" + org + "/sdk-credential-reconciliation-lease/issue-worker-key",
        201, method="POST",
        payload={"application": app, "environment": "staging",
                 "capability": capability, "plugin_id": plugin, "name": name,
                 "token": lease_token, "expires_at": (
                     datetime.now(UTC) + timedelta(hours=2)).isoformat()},
    )
    require(isinstance(result, dict) and isinstance(result.get("key"), str)
            and len(result["key"]) >= 20 and isinstance(result.get("id"), str),
            "Core did not issue complete scoped Worker key")
    key = get_worker_key(core, org, result["id"])
    require(key.get("scopes") == ["plugins:register"]
            and key.get("allowed_capabilities") == [capability]
            and key.get("plugin_id") == plugin and key.get("revoked_at") is None,
            "Worker key policy not attested")
    return result


def registered(core: Core, org: str, plugin: str,
               capability: str, key_id: str, timeout: int = WAIT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, data = core.request("remote-plugins/registrations")
        if status == 200 and isinstance(data, dict):
            matches = [r for r in data.get("items", [])
                       if r.get("organization_id") == org
                       and capability in (r.get("capabilities") or [])
                       and r.get("key_id") == key_id]
            if matches:
                return True
        time.sleep(5)
    return False


def assert_kernel_proof(result: object) -> None:
    """Require an actual exact Kernel solve with one coherent server replay."""
    require(isinstance(result, dict), "Kernel response missing")
    execution = result.get("execution_result")
    replay = result.get("replay_contract")
    require(isinstance(execution, dict) and isinstance(replay, dict),
            "Kernel result or replay missing")
    manifest = execution.get("manifest")
    require(isinstance(manifest, dict), "Server-authored manifest missing")
    require(execution.get("semantic_status") == "EXACT"
            and execution.get("backend_status") == "OPTIMAL"
            and isinstance(execution.get("solution"), dict)
            and bool(execution["solution"])
            and execution.get("objective_value") is not None,
            "Kernel did not return an exact optimal solution")
    require(isinstance(execution.get("execution_id"), str)
            and bool(execution["execution_id"])
            and isinstance(execution.get("decision_id"), str)
            and bool(execution["decision_id"]),
            "Kernel execution identity missing")
    for name in ("execution_id", "decision_id"):
        require(manifest.get(name) == execution[name],
                "Kernel manifest execution identity mismatch")
    for name in ("ir_hash", "decision_spec_hash"):
        digest = manifest.get(name)
        require(isinstance(digest, str)
                and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and replay.get(name) == digest,
                "Kernel manifest/replay hash mismatch")
    require(execution.get("ir_hash") == manifest["ir_hash"]
            and replay.get("decision_id") == execution["decision_id"]
            and manifest.get("compiler_version") == "qdip-runtime-compiler.v1"
            and replay.get("compiler_version") == "qdip-runtime-compiler.v1"
            and manifest.get("runtime_version") == "qdip-runtime-kernel.v1",
            "Kernel semantic provenance mismatch")


# The user explicitly approved a staging-only review risk on 2026-11-02.
# This function DOES NOT bypass remote admission: it uses the real audited
# platform-admin approval route and only a reviewed isolated Gateway instance.
APPROVAL = "user-approved-staging-only-2026-11-02"
REVIEW_REFERENCE = "SDK383-20261102-USER-APPROVED-STAGING"
REVIEW_ACTOR = "user-authorized-sdk383-staging-qa"
GATEWAY_NAME = "sdk383-e2e-core-gateway"


def _admission_record(core: Core, org: str, plugin: str,
                      capability: str, worker_key_id: str) -> dict:
    response = core.expect("plugin-publications/remote-admission-preflight", 200)
    require(isinstance(response, dict)
            and isinstance(response.get("items"), list),
            "Remote admission preflight missing")
    matches = [item for item in response["items"]
               if isinstance(item, dict)
               and item.get("tenant_id") == org
               and item.get("plugin_id") == plugin]
    require(len(matches) == 1, "Missing or ambiguous isolated Worker registration")
    item = matches[0]
    require(item.get("worker_key_id") == worker_key_id
            and item.get("plugin_version") == "0.1.0"
            and item.get("capabilities") == {capability: "1"}
            and isinstance(item.get("revision"), int)
            and item["revision"] >= 0
            and item.get("connected") is True,
            "Live Worker identity, capability or approval revision mismatch")
    digest = item.get("manifest_sha256")
    require(isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "Unreviewed or invalid Worker manifest digest")
    require(isinstance(item.get("name"), str)
            and item["name"].startswith("remote-")
            and plugin in item["name"],
            "Isolated SDK plugin catalog identity mismatch")
    return item


def staging_admit(core: Core, railway: Railway, org: str, plugin: str,
                  capability: str, worker_key_id: str) -> str:
    require(os.getenv("QDIP_SDK383_E2E_RISK_ACCEPTED") == APPROVAL,
            "User staging risk acceptance required")
    require(ORIGIN == "https://sdk383-e2e-core-gateway-staging.up.railway.app",
            "Security approval must target only the isolated staging Gateway")
    require(os.getenv("QDIP_SDK383_E2E_REVIEWED_WORKER_SHA")
            == "ffac08fea89c03e76f85e569cefc79dbde6eba53",
            "Worker source differs from reviewed SHA")
    gateway_id = os.getenv("QDIP_SDK383_E2E_GATEWAY_SERVICE_ID", "")
    require(bool(re.fullmatch(r"[0-9a-f-]{36}", gateway_id))
            and gateway_id != railway.target_service,
            "Approval requires distinct isolated Gateway service")
    gateway = Railway(railway.token, gateway_id, GATEWAY_NAME)
    gateway.scope()
    gateway.pending()
    before_nodes, before_vals = gateway.metadata()
    trust_var = "QDIP_TRUSTED_REMOTE_MANIFESTS"
    require(not any(row.get("name") == trust_var for row in before_nodes)
            and trust_var not in before_vals,
            "Isolated Gateway trust list must initially be empty")
    item = _admission_record(core, org, plugin, capability, worker_key_id)
    require(item.get("approval_state") in {"pending_review", "approved"},
            "Plugin security state denies fresh risk acceptance")
    digest = item["manifest_sha256"]
    previous = gateway.deployment()["id"]
    gateway.stage_commit({trust_var: {"value": digest, "isSealed": False}})
    gateway.wait_new_deployment(previous)
    nodes, values = gateway.metadata()
    require(sum(row.get("name") == trust_var and row.get("isSealed") is False
                for row in nodes) == 1
            and values.get(trust_var) == digest,
            "Only reviewed exact manifest digest may enter trusted list")
    require(registered(core, org, plugin, capability, worker_key_id),
            "Worker did not reconnect to reviewed Gateway after trust deployment")
    item = _admission_record(core, org, plugin, capability, worker_key_id)
    require(item["manifest_sha256"] == digest
            and item.get("approval_state") == "pending_review",
            "Worker identity drift or previously approved registration")
    approved = core.request(
        "plugin-publications/" + item["name"] + "/security/approve",
        method="POST", actor=REVIEW_ACTOR,
        payload={"expected_revision": item["revision"],
                 "plugin_version": "0.1.0",
                 "reason": "User accepted staging-only exact first-party Worker risk after source review; no production admission.",
                 "review_reference": REVIEW_REFERENCE,
                 "risk_acknowledged": True},
    )
    require(approved[0] == 200
            and isinstance(approved[1], dict)
            and (approved[1].get("security") or {}).get("state") == "approved",
            "Audited manual staging approval was not confirmed")
    latest = _admission_record(core, org, plugin, capability, worker_key_id)
    require(latest["manifest_sha256"] == digest
            and latest.get("approval_state") == "approved",
            "Approved Worker manifest was not persisted")
    print("SDK383_USER_APPROVED_STAGING_ADMISSION=PASS digest=" + digest, flush=True)
    return digest


def reset_staging_admission(core: Core, railway: Railway, org: str,
                            plugin: str, capability: str,
                            worker_key_id: str) -> None:
    """Remove test Gateway trust + restore review to pending; never touch RR."""
    gateway_id = os.getenv("QDIP_SDK383_E2E_GATEWAY_SERVICE_ID", "")
    require(bool(re.fullmatch(r"[0-9a-f-]{36}", gateway_id))
            and gateway_id != railway.target_service,
            "Cannot safely clean up nonisolated Gateway")
    gateway = Railway(railway.token, gateway_id, GATEWAY_NAME)
    gateway.scope()
    rows, values = gateway.metadata()
    trust_var = "QDIP_TRUSTED_REMOTE_MANIFESTS"
    matched = [row for row in rows if row.get("name") == trust_var]
    require(len(matched) <= 1, "Ambiguous Gateway admission variable")
    item = _admission_record(core, org, plugin, capability, worker_key_id)
    if matched:
        require(matched[0].get("isSealed") is False
                and values.get(trust_var) == item["manifest_sha256"],
                "Refusing to delete foreign Gateway allowlist")
    if item.get("approval_state") == "approved":
        status, revoked = core.request(
            "plugin-publications/" + item["name"] + "/security/quarantine",
            method="POST", actor=REVIEW_ACTOR,
            payload={"expected_revision": item["revision"],
                     "plugin_version": "0.1.0", "quarantined": True,
                     "reason": "SDK383 user-approved staging E2E ended; test admission withdrawn"},
        )
        require(status == 200 and isinstance(revoked, dict)
                and (revoked.get("security") or {}).get("state") == "quarantined",
                "Staging test approval quarantine not confirmed")
        new_revision = revoked.get("revision")
        status, released = core.request(
            "plugin-publications/" + item["name"] + "/security/quarantine",
            method="POST", actor=REVIEW_ACTOR,
            payload={"expected_revision": new_revision,
                     "plugin_version": "0.1.0", "quarantined": False,
                     "reason": "SDK383 staging approval reset to pending after test"},
        )
        require(status == 200 and isinstance(released, dict)
                and (released.get("security") or {}).get("state") == "pending_review",
                "Staging approval reset not verified")
    if matched:
        gateway.pending()
        deleted = gateway.query(
            "mutation ($i: VariableDeleteInput!) { variableDelete(input: $i) }",
            {"i": {"projectId": PROJECT, "environmentId": ENVIRONMENT,
                   "serviceId": gateway_id, "name": trust_var}},
        ).get("variableDelete")
        require(deleted is True, "Staging trust digest deletion failed")
        deadline = time.monotonic() + 90
        while True:
            remaining, values = gateway.metadata()
            if not any(row.get("name") == trust_var for row in remaining) and trust_var not in values:
                break
            require(time.monotonic() < deadline, "Staging trust digest removal not confirmed")
            time.sleep(5)
    print("SDK383_STAGING_ADMISSION_CLEANUP=PASS", flush=True)


def smoke(core: Core, org: str, plugin: str, capability: str, fixture: dict) -> None:
    caller = core.expect("organizations/" + org + "/keys", 201, method="POST", payload={
        "name": "sdk383-e2e-smoke-" + uuid.uuid4().hex,
        "environment": "staging",
        "scopes": ["plugins:execute"],
        "plugin_id": plugin,
        "allowed_capabilities": [capability],
        "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
    })
    require(isinstance(caller, dict) and isinstance(caller.get("key"), str)
            and isinstance(caller.get("id"), str), "Temporary caller key creation failed")
    try:
        payload = {"input": fixture, "timeout_seconds": 15, "capability_version": "1"}
        status, result = core.request("remote-plugins/" + capability + "/invoke",
                                      method="POST", payload=payload, key=caller["key"])
        if status == 403:
            print("SDK383_UNAPPROVED_DISPATCH_DENIED=PASS", flush=True)
            raise GateError("Manual Worker security admission is required before Kernel smoke")
        require(status == 200, "Worker invoke unexpected HTTP status " + str(status))
        assert_kernel_proof(result)
        print("SDK383_KERNEL_MANIFEST_REPLAY=PASS", flush=True)
    finally:
        core.expect("organizations/" + org + "/keys/" + caller["id"] + "/revoke",
                    200, method="POST", payload={})
        denied, _ = core.request(
            "remote-plugins/" + capability + "/invoke",
            method="POST", payload=payload, key=caller["key"],
        )
        require(denied in (401, 403),
                "Revoked smoke caller still authorized by Gateway")


def revocation(core: Core, org: str, app: str, token: str,
               plugin: str, key_id: str) -> None:
    result = core.expect("organizations/" + org + "/keys/" + key_id + "/revoke-fenced",
                         200, method="POST", payload={
                             "application": app, "environment": "staging",
                             "plugin_id": plugin, "token": token,
                         })
    require(isinstance(result, dict) and result.get("status") == "revoked",
            "Fenced test-key revocation not verified")


def main() -> int:
    require(os.getenv("QDIP_SDK383_E2E_APPROVED") == "disposable-worker-only",
            "Missing explicit disposable-Worker approval")
    require(os.getenv("RAILWAY_PROJECT_ID") == PROJECT
            and os.getenv("RAILWAY_ENVIRONMENT_ID") == ENVIRONMENT,
            "Not the exact staging Railway environment")
    service = os.environ.get("QDIP_SDK383_E2E_WORKER_SERVICE_ID", "")
    name = os.environ.get("QDIP_SDK383_E2E_WORKER_SERVICE_NAME", "")
    require(bool(re.fullmatch(r"[0-9a-f-]{36}", service))
            and bool(re.fullmatch(r"sdk383-e2e-[a-z0-9-]{4,40}", name)),
            "Target must be a separately designated disposable test Worker")
    org = os.environ.get("QDIP_SDK383_E2E_ORG_ID", "")
    plugin = os.environ.get("QDIP_SDK383_E2E_PLUGIN_ID", "")
    capability = os.environ.get("QDIP_SDK383_E2E_CAPABILITY", "")
    require(bool(re.fullmatch(r"[0-9a-f-]{36}", org))
            and bool(re.fullmatch(r"[a-z0-9.-]{5,100}", plugin))
            and plugin.startswith("sdk383-e2e-")
            and bool(re.fullmatch(r"[a-z0-9.-]{5,100}", capability))
            and capability.startswith("sdk383.e2e."),
            "Require an isolated test organization/plugin/capability")
    fixture = json.loads(os.environ.get("QDIP_SDK383_E2E_SMOKE_JSON", "{}"))
    require(isinstance(fixture, dict) and bool(fixture),
            "Missing real test Worker smoke fixture")
    require(ORIGIN in {"https://qdip-core-staging-staging.up.railway.app",
                       "https://sdk383-e2e-core-gateway-staging.up.railway.app"},
            "Unapproved SDK383 staging Gateway origin")
    core = Core(os.environ.get("QDIP_PLATFORM_ADMIN_API_KEY", ""))
    rail = Railway(os.environ.get("RAILWAY_PROJECT_TOKEN", ""), service, name)
    rail.scope()
    rail.pending()
    nodes, values = rail.metadata()
    require(not any(x.get("name") in {SECRET, KEY_ID} for x in nodes)
            and SECRET not in values and KEY_ID not in values,
            "Worker is not disposable or already has credentials")
    require(core.expect("organizations/" + org + "/keys", 200) is not None,
            "Target organization unavailable")
    previous = rail.deployment()["id"]
    token = secrets.token_hex(32)
    app = "sdk383-e2e-" + secrets.token_hex(5)
    issued: list[dict] = []
    delivered = False
    ownership = False
    restored = False
    reviewed_key_id: str | None = None
    try:
        lease(core, org, app, "acquire", token)
        ownership = True
        first = issue_worker(core, org, app, token, plugin, capability, 0)
        issued.append(first)
        lease(core, org, app, "assert", token)
        rail.stage_commit({
            SECRET: {"value": first["key"], "isSealed": True},
            KEY_ID: {"value": first["id"], "isSealed": False},
        })
        delivered = True
        rail.wait_new_deployment(previous)
        nodes, values = rail.metadata()
        require(len([n for n in nodes if n.get("name") == SECRET
                     and n.get("isSealed") is True]) == 1
                and values.get(KEY_ID) == first["id"],
                "First Worker credential not sealed or ID mismatch")
        require(registered(core, org, plugin, capability, first["id"]),
                "Sealed Worker never REGISTERED")
        print("SDK383_SEALED_WORKER_REGISTER=PASS", flush=True)
        second = issue_worker(core, org, app, token, plugin, capability, 1)
        issued.append(second)
        # Deliberately deliver an invalid value under the valid successor ID.
        # The exact old key must remain unrevoked while the successor fails.
        previous = rail.deployment()["id"]
        lease(core, org, app, "assert", token)
        rail.stage_commit({
            SECRET: {"value": secrets.token_urlsafe(48), "isSealed": True},
            KEY_ID: {"value": second["id"], "isSealed": False},
        })
        delivered = True
        # Failure can be either rejected deployment or successful but no REGISTER.
        try:
            rail.wait_new_deployment(previous)
        except GateError:
            failed_deploy = rail.deployment()
            require(failed_deploy.get("id") != previous
                    and failed_deploy.get("status") in {"FAILED", "CRASHED", "REMOVED"},
                    "No verified deployment for failed credential rotation")
        require(not registered(core, org, plugin, capability, second["id"], 15),
                "Invalid raw key was unexpectedly registered")
        require(get_worker_key(core, org, first["id"]).get("revoked_at") is None,
                "Failed successor caused premature predecessor revocation")
        print("SDK383_SEALED_FAILED_ROTATION_PRESERVES_KEY=PASS", flush=True)
        # Recover from the in-memory original raw key, not from a Railway readback.
        previous = rail.deployment()["id"]
        lease(core, org, app, "assert", token)
        rail.stage_commit({
            SECRET: {"value": first["key"], "isSealed": True},
            KEY_ID: {"value": first["id"], "isSealed": False},
        })
        rail.wait_new_deployment(previous)
        require(registered(core, org, plugin, capability, first["id"]),
                "Rollback failed to re-register original test Worker key")
        restored = True
        print("SDK383_SEALED_WORKER_RECOVERY=PASS", flush=True)
        # Exact, user-authorized staging risk acceptance. This never patches
        # Mongo directly or disables Gateway checks.
        reviewed_key_id = first["id"]
        staging_admit(core, rail, org, plugin, capability, first["id"])
        smoke(core, org, plugin, capability, fixture)
    finally:
        if ownership:
            if reviewed_key_id is not None:
                reset_staging_admission(core, rail, org, plugin, capability,
                                        reviewed_key_id)
            if delivered:
                # Never delete or revoke a credential until its rollback state is known.
                # These names were absent on this exact disposable Worker
                # before the test. Delete by Railway variableDelete, not
                # EnvironmentConfig null-patch (which is not a delete).
                for name in (SECRET, KEY_ID):
                    result = rail.query(
                        "mutation ($i: VariableDeleteInput!) { variableDelete(input: $i) }",
                        {"i": {"projectId": PROJECT, "environmentId": ENVIRONMENT,
                               "serviceId": service, "name": name}},
                    ).get("variableDelete")
                    require(result is True, "Disposable Worker variable deletion unconfirmed")
                deadline = time.monotonic() + 90
                while True:
                    nodes, values = rail.metadata()
                    if not any(x.get("name") in {SECRET, KEY_ID} for x in nodes) and (
                            SECRET not in values and KEY_ID not in values):
                        break
                    if time.monotonic() >= deadline:
                        raise GateError("Disposable Worker secret cleanup not verified")
                    time.sleep(5)
            for record in issued:
                if get_worker_key(core, org, record["id"]).get("revoked_at") is None:
                    revocation(core, org, app, token, plugin, record["id"])
            lease(core, org, app, "release", token)
    require(restored, "Recovery was not verified")
    print("SDK383_SEALED_WORKER_LIFECYCLE_E2E=PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, KeyError, ValueError) as exc:
        print("SDK383_SEALED_WORKER_LIFECYCLE_E2E=BLOCKED:" +
              (str(exc) if isinstance(exc, GateError) else "invalid configuration"),
              flush=True)
        raise SystemExit(2) from None

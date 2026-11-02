#!/usr/bin/env python3
"""Real isolated two-Gateway Security Gate E2E; shared Mongo, two live Workers.

Operate only on named sdk400-mg-* Railway staging services, never RR/production.
All credentials are ephemeral; test leaves a terminally REVOKED QA identity.
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
from urllib.request import Request

from sdk383_sealed_railway_e2e import ENVIRONMENT, PROJECT, GateError, Railway, require
from sdk383_sealed_worker_lifecycle_e2e import (
    Core, NoRedirect, assert_kernel_proof, get_worker_key, issue_worker, lease,
)
from urllib.request import build_opener

GATEWAYS = {
    "a": ("a85ac3c1-3d15-4eec-bcb3-b927a529d74b", "sdk400-mg-gateway-a"),
    "b": ("399300a8-afed-495d-a7fa-24301af7d913", "sdk400-mg-gateway-b"),
}
WORKERS = {
    "a": ("223a72a8-1446-452e-a1fb-0a5927f97112", "sdk400-mg-worker-a"),
    "b": ("017f99f9-2a46-4910-8474-1afbfa64582c", "sdk400-mg-worker-b"),
}
PLUGIN = "sdk400-e2e-multigateway-r3"
CAPABILITY = "sdk400.e2e.rr-scheduling-r3.v1"
ACTOR = "user-authorized-sdk400-staging-qa"
REFERENCE = "SDK400-20261102-ISOLATED-TWO-GATEWAY"
SECRET = "QDIP_REMOTE_API_KEY"
KEY_ID = "QDIP_REMOTE_API_KEY_ID"
TRUST = "QDIP_TRUSTED_REMOTE_MANIFESTS"
ORG = "fcbb4afe-383d-4123-ad8e-303db1d6f3bd"
FIXTURE = {
    "horizon_slots": 3, "workshop_capacity": 1, "risk_aversion_multiplier": 1,
    "technicians": [{"id": "tech1", "skills": ["engine"], "available_slots": [0, 1, 2]}],
    "jobs": [{"id": "job1", "duration_slots": 1, "required_skills": ["engine"],
              "workshop_units": 1, "parts": [], "dependencies": [], "deadline_slot": 2,
              "readiness_gain_units": 100, "execution_cost_units": 10,
              "success_probability_bps": 9000, "failure_penalty_units": 25}],
    "inventory": [], "donors": [],
    "operator_directives": {"required_job_ids": ["job1"], "excluded_job_ids": []},
}


class ScopedCore(Core):
    def __init__(self, admin: str, name: str):
        super().__init__(admin)
        require(name in GATEWAYS, "Unknown isolated Gateway")
        self.origin = "https://" + GATEWAYS[name][1] + "-staging.up.railway.app"

    def request(self, path: str, *, method: str = "GET", payload: dict | None = None,
                key: str | None = None, actor: str | None = None) -> tuple[int, object]:
        headers = {"x-api-key": self.admin if key is None else key,
                   "Accept": "application/json", "Content-Type": "application/json"}
        if actor is not None:
            require(bool(re.fullmatch(r"[A-Za-z0-9@._:-]{1,256}", actor)), "Invalid actor")
            headers["x-qdip-actor"] = actor
        request = Request(
            self.origin + "/api/v1/" + path.lstrip("/"),
            data=json.dumps(payload).encode() if payload is not None else None,
            headers=headers, method=method,
        )
        try:
            response = self.http.open(request, timeout=45)
        except HTTPError as exc:
            response = exc
        except (URLError, TimeoutError, OSError) as exc:
            raise GateError("Isolated Gateway unavailable: " + type(exc).__name__) from None
        with response:
            status, raw = response.status, response.read(200_001)
        require(len(raw) <= 200_000, "Gateway response exceeded bound")
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            parsed = None
        return status, parsed


def live_registration(core: ScopedCore, key_id: str, *, timeout: int = 115) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, data = core.request("remote-plugins/registrations")
        if status == 200 and isinstance(data, dict) and any(
            isinstance(row, dict)
            and row.get("organization_id") == ORG
            and row.get("key_id") == key_id
            and CAPABILITY in (row.get("capabilities") or [])
            for row in data.get("items", [])
        ):
            return True
        time.sleep(4)
    return False


def registration_digest(core: ScopedCore, key_id: str) -> tuple[str, str, int]:
    data = core.expect("plugin-publications/remote-admission-preflight", 200)
    require(isinstance(data, dict) and isinstance(data.get("items"), list),
            "Preflight missing")
    matches = [row for row in data["items"] if isinstance(row, dict)
               and row.get("tenant_id") == ORG and row.get("plugin_id") == PLUGIN]
    require(len(matches) == 1, "Isolated registration unavailable or ambiguous")
    row = matches[0]
    require(row.get("worker_key_id") == key_id
            and row.get("capabilities") == {CAPABILITY: "1"}
            and row.get("plugin_version") == "0.1.0"
            and row.get("connected") is True,
            "Registration identity or per-Gateway worker session mismatch")
    digest = row.get("manifest_sha256")
    require(isinstance(digest, str) and bool(re.fullmatch(r"[0-9a-f]{64}", digest)),
            "Invalid exact manifest digest")
    require(isinstance(row.get("name"), str) and PLUGIN in row["name"]
            and isinstance(row.get("revision"), int),
            "Registration revision missing")
    return digest, row["name"], row["revision"]


def variable_absent(rail: Railway, *names: str) -> None:
    nodes, values = rail.metadata()
    require(not any(node.get("name") in names for node in nodes)
            and not any(name in values for name in names),
            "Pre-existing variable on isolated service")


def delete_owned(rail: Railway, name: str, expected_sealed: bool,
                 expected_value: str | None = None) -> None:
    nodes, vals = rail.metadata()
    matching = [node for node in nodes if node.get("name") == name]
    if not matching:
        return
    require(len(matching) == 1 and matching[0].get("isSealed") is expected_sealed,
            "Unowned or ambiguous Railway variable: " + name)
    if expected_value is not None:
        require(vals.get(name) == expected_value, "Variable ID drift")
    rail.pending()
    deleted = rail.query(
        "mutation ($i: VariableDeleteInput!) { variableDelete(input: $i) }",
        {"i": {"projectId": PROJECT, "environmentId": ENVIRONMENT,
               "serviceId": rail.target_service, "name": name}},
    ).get("variableDelete")
    require(deleted is True, "Variable cleanup failed")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        nodes, vals = rail.metadata()
        if not any(x.get("name") == name for x in nodes) and name not in vals:
            return
        time.sleep(3)
    raise GateError("Variable cleanup readback failed")


def state_change(core: ScopedCore, plugin_name: str, action: str,
                 revision: int, **fields) -> tuple[int, object]:
    return core.request(
        "plugin-publications/" + plugin_name + "/security/" + action,
        method="POST", actor=ACTOR,
        payload={"expected_revision": revision, "plugin_version": "0.1.0", **fields},
    )


def caller_key(core: ScopedCore) -> dict:
    response = core.expect("organizations/" + ORG + "/keys", 201, method="POST",
                           payload={"name": "sdk400-mg-caller-" + uuid.uuid4().hex,
                                    "environment": "staging",
                                    "scopes": ["plugins:execute"], "plugin_id": PLUGIN,
                                    "allowed_capabilities": [CAPABILITY],
                                    "expires_at": (datetime.now(UTC) +
                                                   timedelta(minutes=20)).isoformat()})
    require(isinstance(response, dict) and isinstance(response.get("key"), str)
            and isinstance(response.get("id"), str), "Scoped caller issue failed")
    return response


def invoke(core: ScopedCore, caller: dict) -> tuple[int, object]:
    return core.request("remote-plugins/" + CAPABILITY + "/invoke", method="POST",
                        payload={"input": FIXTURE, "timeout_seconds": 15,
                                 "capability_version": "1"}, key=caller["key"])


def main() -> int:
    require(os.getenv("RAILWAY_PROJECT_ID") == PROJECT
            and os.getenv("RAILWAY_ENVIRONMENT_ID") == ENVIRONMENT,
            "Wrong Railway project/environment")
    require(os.getenv("SDK400_MG_STAGING_APPROVED") == "isolated-worker-only",
            "No authority for isolated staging Worker test")
    require(os.getenv("SDK400_MG_CORE_SHA") ==
            "3cd28d31c93f0b3689a2c4b660ed5a4bf65d2e49",
            "Gateway SHA unreviewed")
    require(os.getenv("SDK400_MG_WORKER_SHA") ==
            "ffac08fea89c03e76f85e569cefc79dbde6eba53",
            "Worker SHA unreviewed")
    token = os.getenv("RAILWAY_PROJECT_TOKEN", "")
    admin = os.getenv("QDIP_PLATFORM_ADMIN_API_KEY", "")
    core = {name: ScopedCore(admin, name) for name in GATEWAYS}
    rails = {name: Railway(token, service_id, service_name)
             for name, (service_id, service_name) in {**GATEWAYS, **WORKERS}.items()}
    # B-worker keys overwrite map's B-Gateway keys if indexed by a/b: split.
    gateways = {n: Railway(token, sid, name) for n, (sid, name) in GATEWAYS.items()}
    workers = {n: Railway(token, sid, name) for n, (sid, name) in WORKERS.items()}
    for rail in [*gateways.values(), *workers.values()]:
        rail.scope()
        rail.pending()
    for rail in gateways.values():
        variable_absent(rail, TRUST)
    for rail in workers.values():
        variable_absent(rail, SECRET, KEY_ID)
    for c in core.values():
        require(c.request("health")[0] in (200, 404), "Gateway request failed")
        c.expect("organizations/" + ORG + "/keys", 200)
    # Only our own previously quarantined QA identity may be reset after a
    # failed test run; its old credential must already be revoked.
    snapshot = core["a"].expect("plugin-publications/remote-admission-preflight", 200)
    old = [item for item in snapshot.get("items", []) if isinstance(item, dict)
           and item.get("tenant_id") == ORG and item.get("plugin_id") == PLUGIN]
    require(len(old) <= 1, "Ambiguous staging QA identity")
    if old and old[0].get("approval_state") == "quarantined":
        previous_key = old[0].get("worker_key_id")
        require(isinstance(previous_key, str)
                and get_worker_key(core["a"], ORG, previous_key).get("revoked_at") is not None
                and not old[0].get("connected"),
                "Cannot release potentially live quarantined identity")
        status, reset = state_change(
            core["a"], old[0]["name"], "quarantine", old[0]["revision"],
            quarantined=False, reason="Reset only revoked-key isolated QA test identity",
        )
        require(status == 200 and (reset.get("security") or {}).get("state") == "pending_review",
                "Previous QA identity reset not verified")
    app = "sdk400-e2e-" + secrets.token_hex(5)
    lease_token = secrets.token_hex(32)
    worker_key: dict | None = None
    caller: dict | None = None
    acquired = False
    staged_workers: list[str] = []
    staged_gateways: list[str] = []
    digest: str | None = None
    try:
        lease(core["a"], ORG, app, "acquire", lease_token)
        acquired = True
        worker_key = issue_worker(core["a"], ORG, app, lease_token, PLUGIN, CAPABILITY, 0)
        for name in ("a", "b"):
            old = workers[name].deployment()["id"]
            workers[name].stage_commit({
                SECRET: {"value": worker_key["key"], "isSealed": True},
                KEY_ID: {"value": worker_key["id"], "isSealed": False},
            })
            staged_workers.append(name)
            workers[name].wait_new_deployment(old)
            nodes, vals = workers[name].metadata()
            require(sum(x.get("name") == SECRET and x.get("isSealed") is True
                        for x in nodes) == 1 and vals.get(KEY_ID) == worker_key["id"],
                    "Worker sealed delivery not attested")
            require(live_registration(core[name], worker_key["id"]),
                    "Worker did not register on Gateway " + name)
        one = registration_digest(core["a"], worker_key["id"])
        two = registration_digest(core["b"], worker_key["id"])
        require(one == two, "Gateways disagree on persisted Worker manifest")
        digest, catalog, revision = one
        print("SDK400_TWO_GATEWAY_LIVE_REGISTER=PASS", flush=True)
        for name in ("a", "b"):
            old = gateways[name].deployment()["id"]
            gateways[name].stage_commit({TRUST: {"value": digest, "isSealed": False}})
            staged_gateways.append(name)
            gateways[name].wait_new_deployment(old)
            nodes, vals = gateways[name].metadata()
            require(sum(x.get("name") == TRUST for x in nodes) == 1
                    and vals.get(TRUST) == digest, "Gateway trust digest readback failed")
            require(live_registration(core[name], worker_key["id"]),
                    "Worker failed to reconnect after Gateway deploy " + name)
        # Admission is auditable and bound to the exact shared Mongo registration.
        latest = registration_digest(core["a"], worker_key["id"])
        require(latest[0] == digest and latest[1] == catalog,
                "Manifest drift after gateway trust rollout")
        status, approved = state_change(
            core["a"], catalog, "approve", latest[2],
            reason="User-authorized staging-only two-Gateway Worker admission verification",
            review_reference=REFERENCE, risk_acknowledged=True,
        )
        require(status == 200 and isinstance(approved, dict)
                and (approved.get("security") or {}).get("state") == "approved",
                "Audited exact Worker approval rejected")
        caller = caller_key(core["a"])
        for name in ("a", "b"):
            status, result = invoke(core[name], caller)
            require(status == 200, "Approved Worker invocation failed on Gateway " + name +
                    " status=" + str(status))
            assert_kernel_proof(result)
        print("SDK400_TWO_GATEWAY_APPROVED_KERNEL=PASS", flush=True)
        revision = approved.get("revision")
        require(isinstance(revision, int), "Approved revision unavailable")
        status, quarantined = state_change(
            core["a"], catalog, "quarantine", revision,
            quarantined=True, reason="Staging multi-Gateway quarantine deny regression",
        )
        require(status == 200 and isinstance(quarantined, dict)
                and (quarantined.get("security") or {}).get("state") == "quarantined",
                "Cross-Gateway quarantine write failed")
        # A disconnects its local Worker after writing quarantine: 503 there
        # is fail-closed. B still owns a live Worker and must deny via Mongo 403.
        require(live_registration(core["b"], worker_key["id"], timeout=1),
                "Peer Worker B not live before cross-Gateway deny")
        denied_b, _ = invoke(core["b"], caller)
        require(denied_b == 403, "Peer B did not enforce A quarantine: " + str(denied_b))
        denied_a, _ = invoke(core["a"], caller)
        require(denied_a in (403, 503)
                and (denied_a != 503 or not live_registration(
                    core["a"], worker_key["id"], timeout=1)),
                "Gateway A allowed quarantined invocation")
        print("SDK400_TWO_GATEWAY_QUARANTINE_DENY=PASS", flush=True)
        revision = quarantined.get("revision")
        status, released = state_change(
            core["a"], catalog, "quarantine", revision,
            quarantined=False, reason="QA release must revert only to pending review",
        )
        require(status == 200 and isinstance(released, dict)
                and (released.get("security") or {}).get("state") == "pending_review",
                "Quarantine release did not reset to pending")
        require(live_registration(core["b"], worker_key["id"], timeout=1),
                "Peer B Worker lost before pending-review test")
        pending_b, _ = invoke(core["b"], caller)
        require(pending_b == 403, "B allowed pending-review invoke")
        pending_a, _ = invoke(core["a"], caller)
        require(pending_a in (403, 503), "A allowed pending-review invoke")
        status, revoked = state_change(
            core["a"], catalog, "revoke", released.get("revision"),
            reason="Terminate QA-only plugin identity after multi-Gateway E2E",
        )
        require(status == 200 and isinstance(revoked, dict)
                and (revoked.get("security") or {}).get("state") == "revoked",
                "Terminal revocation not confirmed")
        require(live_registration(core["b"], worker_key["id"], timeout=1),
                "Peer B Worker lost before terminal revocation test")
        revoked_b, _ = invoke(core["b"], caller)
        require(revoked_b == 403, "B Gateway accepted terminally revoked plugin")
        revoked_a, _ = invoke(core["a"], caller)
        require(revoked_a in (403, 503), "A Gateway accepted terminally revoked plugin")
        # A fresh Worker reconnect after terminal revoke may CRASH (fail closed);
        # it must never receive a new REGISTER acknowledgement.
        old = workers["b"].deployment()["id"]
        workers["b"].stage_commit({
            "SDK400_MG_RECONNECT_TICK": {"value": uuid.uuid4().hex, "isSealed": False},
        })
        # A previously-connected process-local session can outlive the Mongo
        # revoke for a heartbeat interval. Do not equate that old session with
        # a successful REGISTER of the new deployment. Wait for the old lease
        # to disappear and the restarted Worker to fail permanent auth.
        deadline = time.monotonic() + 135
        restarted = False
        denied_reconnect = False
        while time.monotonic() < deadline:
            dep = workers["b"].deployment()
            if dep.get("id") != old:
                restarted = True
                if dep.get("status") in {"FAILED", "CRASHED"}:
                    status, registrations = core["b"].request("remote-plugins/registrations")
                    require(status == 200 and isinstance(registrations, dict),
                            "Peer registration inspection unavailable")
                    if not any(
                        row.get("organization_id") == ORG
                        and row.get("key_id") == worker_key["id"]
                        and CAPABILITY in (row.get("capabilities") or [])
                        for row in registrations.get("items", []) if isinstance(row, dict)
                    ):
                        denied_reconnect = True
                        break
            time.sleep(4)
        require(restarted and denied_reconnect,
                "Terminal revoke left live peer session or admitted new Worker")
        print("SDK400_TWO_GATEWAY_RECONNECT_DENY=PASS", flush=True)

        for action, fields in (
            ("approve", {"reason": "Invalid approval after terminal revocation",
                         "review_reference": REFERENCE, "risk_acknowledged": True}),
            ("quarantine", {"quarantined": False, "reason": "Invalid release after revoke"}),
        ):
            denied, _ = state_change(core["b"], catalog, action,
                                     revoked.get("revision"), **fields)
            require(denied == 409, "B Gateway allowed revoked identity mutation")
        print("SDK400_TWO_GATEWAY_REVOKED_TERMINAL=PASS", flush=True)
    finally:
        # Cleanup must be attempted even after an acceptance failure.
        errors: list[str] = []
        if caller is not None:
            try:
                core["a"].expect("organizations/" + ORG + "/keys/" + caller["id"] +
                                 "/revoke", 200, method="POST", payload={})
            except GateError as exc:
                errors.append("caller:" + str(exc))
        for name in staged_gateways:
            try:
                delete_owned(gateways[name], TRUST, False, digest)
            except GateError as exc:
                errors.append("gateway-" + name + ":" + str(exc))
        # Remove only the QA-owned reconnect trigger, never a service default.
        if "b" in staged_workers:
            try:
                delete_owned(workers["b"], "SDK400_MG_RECONNECT_TICK", False)
            except GateError as exc:
                errors.append("worker-b-reconnect:" + str(exc))
        for name in staged_workers:
            for field, sealed, expected in ((SECRET, True, None),
                                             (KEY_ID, False,
                                              worker_key["id"] if worker_key else None)):
                try:
                    delete_owned(workers[name], field, sealed, expected)
                except GateError as exc:
                    errors.append("worker-" + name + ":" + str(exc))
        if acquired:
            if worker_key is not None:
                try:
                    active = get_worker_key(core["a"], ORG, worker_key["id"])
                    if active.get("revoked_at") is None:
                        result = core["a"].expect(
                            "organizations/" + ORG + "/keys/" +
                            worker_key["id"] + "/revoke-fenced", 200,
                            method="POST", payload={
                                "application": app, "environment": "staging",
                                "plugin_id": PLUGIN, "token": lease_token,
                            })
                        require(result.get("status") == "revoked",
                                "Worker key fenced revoke missing")
                except GateError as exc:
                    errors.append("worker-key:" + str(exc))
            try:
                lease(core["a"], ORG, app, "release", lease_token)
            except GateError as exc:
                errors.append("lease:" + str(exc))
        require(not errors, "Critical QA cleanup incomplete: " + ", ".join(errors))
        print("SDK400_TWO_GATEWAY_CREDENTIAL_CLEANUP=PASS", flush=True)
    print("SDK400_TWO_GATEWAY_SECURITY_E2E=PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, ValueError, KeyError) as exc:
        print("SDK400_TWO_GATEWAY_SECURITY_E2E=BLOCKED:" +
              (str(exc) if isinstance(exc, GateError) else "invalid config"), flush=True)
        raise SystemExit(2) from None

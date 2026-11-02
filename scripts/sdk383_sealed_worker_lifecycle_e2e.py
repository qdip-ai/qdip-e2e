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

ORIGIN = "https://qdip-core-staging-staging.up.railway.app"
SECRET = "QDIP_REMOTE_API_KEY"
KEY_ID = SECRET + "_ID"
WAIT = 180


class Core:
    def __init__(self, admin: str) -> None:
        require(len(admin) >= 20, "Missing trusted platform-admin credential")
        self.admin = admin
        self.http = build_opener(NoRedirect())

    def request(self, path: str, *, method: str = "GET",
                payload: dict | None = None, key: str | None = None) -> tuple[int, object]:
        headers = {"x-api-key": self.admin if key is None else key,
                   "Accept": "application/json", "Content-Type": "application/json"}
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
    name = (app + "/staging/" + capability + "/worker/"
            + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    if index:
        # The bounded issuance contract requires unique timestamps.
        name = name[:-1] + str(int(name[-2:-1]) + 1) + "Z" if False else (
            app + "/staging/" + capability + "/worker/"
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
        result = core.expect("remote-plugins/" + capability + "/invoke", 200,
                             method="POST", payload=payload, key=caller["key"])
        require(isinstance(result, dict)
                and (result.get("execution_result") or {}).get("semantic_status")
                in {"EXACT", "OPTIMAL", "FEASIBLE", "INFEASIBLE"}
                and isinstance(result.get("replay_contract"), dict),
                "Successor Worker did not produce Kernel replay proof")
    finally:
        core.expect("organizations/" + org + "/keys/" + caller["id"] + "/revoke",
                    200, method="POST", payload={})


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
        nodes, values = rail.metadata()
        require(len([n for n in nodes if n.get("name") == SECRET
                     and n.get("isSealed") is True]) == 1
                and values.get(KEY_ID) == first["id"],
                "First Worker credential not sealed or ID mismatch")
        rail.wait_new_deployment(previous)
        require(registered(core, org, plugin, capability, first["id"]),
                "Sealed Worker never REGISTERED")
        smoke(core, org, plugin, capability, fixture)
        print("SDK383_SEALED_WORKER_REGISTER_INVOKE=PASS", flush=True)
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
            pass
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
        smoke(core, org, plugin, capability, fixture)
        restored = True
        print("SDK383_SEALED_WORKER_RECOVERY=PASS", flush=True)
    finally:
        if ownership:
            if delivered:
                # Never delete or revoke a credential until its rollback state is known.
                rail.stage_commit({SECRET: None, KEY_ID: None})
                nodes, values = rail.metadata()
                require(not any(x.get("name") in {SECRET, KEY_ID} for x in nodes)
                        and SECRET not in values and KEY_ID not in values,
                        "Disposable Worker secret cleanup not verified")
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

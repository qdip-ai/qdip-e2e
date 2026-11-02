"""Two real, independent Core Gateway processes + two SDK Workers + MongoDB 8.
Railway-only disposable QA. Not a production multi-node/HA/load-balancer claim.
No shared process memory; HTTP/WSS on 8000 and 8001. Admin, Worker and
caller keys are generated for the disposable loopback Mongo and never logged.
"""
from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pymongo import MongoClient

from app.plugins.registration_catalog import registration_digest, remote_catalog_id

API = "/api/v1"
PORTS = (8000, 8001)
CAP, PLUGIN = "staffing.plan", "staffing"
ORG = "sdk400-e2e-" + secrets.token_hex(7)
OTHER = "sdk400-outside-" + secrets.token_hex(7)
INPUT = {"input": {"max_agents_per_period": 4, "morning_coverage": 7,
                   "evening_coverage": 8, "morning_cost": 4, "evening_cost": 3}}
TEMP = Path(os.environ["E2E_TMP"])
PROCS: list[subprocess.Popen] = []


def require(ok: bool, message: str) -> None:
    if not ok:
        raise AssertionError(message)


def http(port: int, path: str, *, method: str = "GET", key: str | None = None,
         body: dict | None = None, actor: bool = False) -> httpx.Response:
    headers = {"x-api-key": key or os.environ["API_KEY"]}
    if actor:
        headers["x-qdip-actor"] = "sdk400-staging-security-review"
    with httpx.Client(timeout=18, trust_env=False) as client:
        return client.request(method, f"http://127.0.0.1:{port}{API}/{path}",
                              headers=headers, json=body)


def launch_gateway(port: int, digest: str | None = None) -> subprocess.Popen:
    env = dict(os.environ)
    env.pop("QDIP_TRUSTED_REMOTE_MANIFESTS", None)
    if digest:
        require(re.fullmatch(r"[a-f0-9]{64}", digest) is not None, "bad digest")
        env["QDIP_TRUSTED_REMOTE_MANIFESTS"] = digest
    log = open(TEMP / f"gateway-{port}.log", "ab")
    try:
        proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                                 "--host", "127.0.0.1", "--port", str(port)],
                                env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        log.close()
    PROCS.append(proc)
    for _ in range(100):
        require(proc.poll() is None, f"Gateway {port} exited")
        try:
            with httpx.Client(timeout=1, trust_env=False) as client:
                if client.get(f"http://127.0.0.1:{port}/health").status_code == 200:
                    return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise AssertionError(f"Gateway {port} health not ready")


def launch_worker(port: int, credential: str, suffix: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["QDIP_REMOTE_URL"] = f"ws://127.0.0.1:{port}{API}/remote-plugins/connect"
    env["QDIP_REMOTE_API_KEY"] = credential
    log = open(TEMP / f"worker-{suffix}.log", "ab")
    try:
        proc = subprocess.Popen([os.environ["QDIP_WORKER_BIN"], "--handler",
                                 "staffing_plugin:make_spec", "--plugin-id", PLUGIN,
                                 "--capability-id", CAP],
                                env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        log.close()
    PROCS.append(proc)
    return proc


def stop(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


class Evidence:
    def __init__(self):
        self.client = MongoClient(os.environ["MONGODB_URL"], serverSelectionTimeoutMS=5000)
        self.db = self.client.get_default_database()
        self.catalog_id = remote_catalog_id(ORG, PLUGIN)

    def setup(self) -> None:
        for ident in (ORG, OTHER):
            self.db["organizations"].insert_one({"id": ident, "name": "isolated security E2E"})

    def register_key(self) -> tuple[str, str]:
        result = http(PORTS[0], f"organizations/{ORG}/keys", method="POST", body={
            "name": "sdk400-e2e-worker-" + secrets.token_hex(4),
            "environment": "staging",
            "scopes": ["plugins:register"], "allowed_capabilities": [CAP],
            "plugin_id": PLUGIN})
        require(result.status_code == 201, f"Worker key: {result.status_code}")
        data = result.json()
        return data["id"], data["key"]

    def caller(self, org: str = ORG) -> str:
        result = http(PORTS[0], f"organizations/{org}/keys", method="POST", body={
            "name": "sdk400-e2e-caller-" + secrets.token_hex(4),
            "environment": "staging", "scopes": ["plugins:read", "plugins:execute"],
            "allowed_capabilities": [CAP], "plugin_id": PLUGIN})
        require(result.status_code == 201, f"Caller key: {result.status_code}")
        return result.json()["key"]

    def row(self) -> dict:
        record = self.db["plugin_publications"].find_one({"_id": self.catalog_id})
        require(isinstance(record, dict), "Authoritative registration missing")
        return record

    def connections(self, port: int, kid: str) -> bool:
        response = http(port, "remote-plugins/registrations")
        require(response.status_code == 200, f"Gateway {port} registrations HTTP {response.status_code}")
        rows = response.json().get("items", [])
        return any(r.get("organization_id") == ORG and r.get("key_id") == kid
                   and CAP in r.get("capabilities", []) for r in rows)

    def wait_connection(self, port: int, kid: str, timeout: float = 40) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.connections(port, kid):
                return
            time.sleep(.35)
        raise AssertionError(f"Gateway {port} real Worker REGISTER missing")

    def wait_disconnected(self, port: int, kid: str, timeout: float = 25) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if not self.connections(port, kid):
                return
            time.sleep(.4)
        raise AssertionError(f"Gateway {port} did not release worker connection")

    def action(self, port: int, kind: str, *, reason: str, version: str,
               extra: dict | None = None, status: int = 200) -> dict:
        row = self.row()
        body = {"expected_revision": row["revision"], "plugin_version": version,
                "reason": reason, **(extra or {})}
        result = http(port, f"plugin-publications/{self.catalog_id}/security/{kind}",
                      method="POST", body=body, actor=True)
        require(result.status_code == status, f"{kind} Gateway {port}: HTTP {result.status_code}")
        return result.json()

    def invoke(self, port: int, caller: str) -> httpx.Response:
        return http(port, f"remote-plugins/{CAP}/invoke", method="POST",
                    key=caller, body=INPUT)

    def assert_solve(self, port: int, caller: str) -> None:
        response = self.invoke(port, caller)
        require(response.status_code == 200, f"Gateway {port} expected Kernel 200, got {response.status_code}")
        data = response.json()
        result, replay = data["execution_result"], data["replay_contract"]
        manifest = result["manifest"]
        require(result["semantic_status"] == "EXACT"
                and result["backend_status"] == "OPTIMAL"
                and result.get("objective_value") is not None
                and bool(result.get("solution")),
                "Kernel solve not exact/optimal")
        require(manifest["ir_hash"] == replay["ir_hash"] == result["ir_hash"]
                and manifest["decision_spec_hash"] == replay["decision_spec_hash"]
                and manifest["execution_id"] == result["execution_id"],
                "Replay/manifest mismatch")

    def assert_deny(self, port: int, caller: str, *, code: int | None = None) -> None:
        response = self.invoke(port, caller)
        require(response.status_code in ({code} if code else {403, 503}),
                f"Gateway {port} unexpected invoke HTTP {response.status_code}")

    def audit(self) -> None:
        rows = list(self.db["plugin_security_audit"].find(
            {"plugin_name": self.catalog_id}).sort("revision", 1))
        actions = [row["action"] for row in rows]
        require(actions == ["manual_approve", "manual_quarantine",
                            "manual_release", "manual_approve", "manual_revoke"],
                f"Audited action sequence differs: {actions}")
        require(all(row.get("actor") == "sdk400-staging-security-review" for row in rows),
                "Approval/revoke audit actor missing")
        require(len(set(row["revision"] for row in rows)) == 5,
                "Audit revision did not progress monotonically")


def main() -> None:
    require(os.environ.get("QDIP_DISPOSABLE_RAILWAY_QA") == "true", "disposable Railway only")
    require(os.environ.get("QDIP_SDK400_E2E_STAGING_APPROVED") ==
            "user-authorized-disposable-first-party-test", "staging review gate")
    target = urlsplit(os.environ["MONGODB_URL"])
    require(target.netloc == "127.0.0.1:27019"
            and target.path == "/qdip_e2e", "refusing external/production Mongo")
    require(os.environ.get("QDIP_WORKER_BIN", "").startswith("/opt/qdip-worker/"),
            "must use isolated installed worker")
    ev = Evidence()
    gateway_a = gateway_b = worker_a = worker_b = None
    try:
        ev.setup()
        gateway_a = launch_gateway(PORTS[0])
        gateway_b = launch_gateway(PORTS[1])
        kid, worker_key = ev.register_key()
        caller = ev.caller()
        outsider = ev.caller(OTHER)
        worker_a = launch_worker(PORTS[0], worker_key, "probe-a")
        ev.wait_connection(PORTS[0], kid)
        review_digest = registration_digest(ev.row()["registration"])
        require(re.fullmatch("[a-f0-9]{64}", review_digest) is not None, "bad reviewed digest")
        stop(worker_a)
        stop(gateway_a)
        stop(gateway_b)
        gateway_a = launch_gateway(PORTS[0], review_digest)
        gateway_b = launch_gateway(PORTS[1], review_digest)
        worker_a = launch_worker(PORTS[0], worker_key, "a")
        ev.wait_connection(PORTS[0], kid)
        worker_b = launch_worker(PORTS[1], worker_key, "b")
        ev.wait_connection(PORTS[1], kid)
        require(registration_digest(ev.row()["registration"]) == review_digest,
                "Concurrent Gateway REGISTER changed approved Worker identity")
        version = ev.row()["registration"]["version"]
        reviewed = ev.action(PORTS[0], "approve", version=version,
                             reason="User-authorized isolated first-party security QA review of exact pinned Worker.",
                             extra={"risk_acknowledged": True,
                                    "review_reference": "SDK400-DUAL-GATEWAY-STAGING-20261102"})
        require(reviewed["security"]["state"] == "approved", "approval not committed")
        ev.assert_solve(PORTS[0], caller)
        ev.assert_solve(PORTS[1], caller)
        require(ev.invoke(PORTS[1], outsider).status_code == 503,
                "Other organization saw another tenant's Worker")
        print("SDK400_TWO_GATEWAY_REAL_APPROVED_INVOKE=PASS", flush=True)

        rev = ev.action(PORTS[0], "quarantine", version=version,
                        reason="Dual Gateway test quarantine blocks future invokes.",
                        extra={"quarantined": True})
        require(rev["security"]["state"] == "quarantined", "quarantine not persisted")
        ev.assert_deny(PORTS[1], caller, code=403)
        ev.wait_disconnected(PORTS[0], kid)
        stop(worker_b)
        ev.wait_disconnected(PORTS[1], kid)
        worker_b = launch_worker(PORTS[1], worker_key, "b-quarantined")
        time.sleep(2)
        require(not ev.connections(PORTS[1], kid), "Quarantined Worker re-REGISTER accepted")
        require(ev.row()["security"]["state"] == "quarantined", "Quarantine lost after reconnect")
        print("SDK400_CROSS_GATEWAY_QUARANTINE_AND_RECONNECT_DENY=PASS", flush=True)

        released = ev.action(PORTS[0], "quarantine", version=version,
                             reason="Release quarantine to pending review only.",
                             extra={"quarantined": False})
        require(released["security"]["state"] == "pending_review",
                "Release improperly restored approval")
        stop(worker_b)
        worker_a = launch_worker(PORTS[0], worker_key, "a-pending")
        worker_b = launch_worker(PORTS[1], worker_key, "b-pending")
        ev.wait_connection(PORTS[0], kid)
        ev.wait_connection(PORTS[1], kid)
        ev.assert_deny(PORTS[0], caller, code=403)
        ev.assert_deny(PORTS[1], caller, code=403)
        print("SDK400_TWO_GATEWAY_RELEASE_PENDING_DENY=PASS", flush=True)

        approved2 = ev.action(PORTS[1], "approve", version=version,
                              reason="Fresh audited review after quarantine and pending release.",
                              extra={"risk_acknowledged": True,
                                     "review_reference": "SDK400-DUAL-GATEWAY-STAGING-REAPPROVAL"})
        require(approved2["security"]["state"] == "approved", "reapproval denied")
        ev.assert_solve(PORTS[0], caller)
        ev.assert_solve(PORTS[1], caller)
        print("SDK400_TWO_GATEWAY_REAPPROVE_AND_SOLVE=PASS", flush=True)

        revoked = ev.action(PORTS[1], "revoke", version=version,
                            reason="Terminally revoke isolated first-party SDK Worker identity.")
        require(revoked["security"]["state"] == "revoked", "revoke not persisted")
        ev.assert_deny(PORTS[0], caller, code=403)
        ev.wait_disconnected(PORTS[1], kid)
        stop(worker_a)
        worker_a = launch_worker(PORTS[0], worker_key, "a-revoked")
        time.sleep(2)
        require(not ev.connections(PORTS[0], kid), "Revoked Worker re-REGISTER accepted")
        ev.action(PORTS[0], "approve", version=version,
                  reason="Attempt to approve a permanently revoked Worker identity.",
                  extra={"risk_acknowledged": True,
                         "review_reference": "SDK400-REVOKED-NEGATIVE-REVIEW"},
                  status=409)
        ev.action(PORTS[1], "quarantine", version=version,
                  reason="Attempt release of permanently revoked Worker identity.",
                  extra={"quarantined": False}, status=409)
        require(ev.row()["security"]["state"] == "revoked", "Terminal identity resurrected")
        ev.audit()
        print("SDK400_CROSS_GATEWAY_TERMINAL_REVOKE_RECONNECT_AUDIT=PASS", flush=True)
        print("SDK400_TWO_GATEWAY_SECURITY_E2E=PASS", flush=True)
    finally:
        for proc in reversed(PROCS):
            stop(proc)
        ev.client.close()


if __name__ == "__main__":
    main()

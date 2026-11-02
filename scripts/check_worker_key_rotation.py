"""Independent E2E: trusted Worker key rotation vs identity/authorization change.

Real HTTP Core + MongoDB replica set + real `qdip-worker` over WSS + Kernel.
Disposable runner only. No production secrets; raw keys are never printed.

Claims checked (positive): an approved first-party Worker whose credential is
rotated by the fenced Provisioner keeps its approval and still completes
Gateway -> Worker -> Kernel with a valid manifest/replay contract.
Claims checked (negative): revoked credential, wrong org, wrong capability,
missing scope, org-issued (non-Provisioner) key for the same plugin.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from pymongo import MongoClient

from app.plugins.registration_catalog import registration_digest

BASE = "http://127.0.0.1:8000/api/v1"
ORG_A, ORG_B = "rr-e2e-org-a", "rr-e2e-org-b"
ENV = "staging"
PLUGIN = "staffing"
CAP = "staffing.plan"
PAYLOAD = {"input": {"max_agents_per_period": 4, "morning_coverage": 7,
                     "evening_coverage": 8, "morning_cost": 4, "evening_cost": 3}}
TMP = Path(os.environ.get("E2E_TMP", "/tmp"))
procs: list[subprocess.Popen] = []


def need(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def start_core(allowlist: str | None) -> subprocess.Popen:
    env = dict(os.environ)
    env.pop("QDIP_TRUSTED_REMOTE_MANIFESTS", None)
    if allowlist:
        env["QDIP_TRUSTED_REMOTE_MANIFESTS"] = allowlist
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", "8000"],
        env=env, stdout=open(TMP / "core.log", "ab"), stderr=subprocess.STDOUT,
    )
    procs.append(proc)
    for _ in range(80):
        try:
            if httpx.get("http://127.0.0.1:8000/health", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    raise AssertionError("Disposable Core did not start")


def start_worker(raw_key: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["QDIP_REMOTE_URL"] = "ws://127.0.0.1:8000/api/v1/remote-plugins/connect"
    env["QDIP_REMOTE_API_KEY"] = raw_key
    proc = subprocess.Popen(
        [os.environ["QDIP_WORKER_BIN"], "--handler", "staffing_plugin:make_spec",
         "--plugin-id", PLUGIN, "--capability-id", CAP],
        env=env, stdout=open(TMP / "worker.log", "ab"), stderr=subprocess.STDOUT,
    )
    procs.append(proc)
    return proc


def stop(proc: subprocess.Popen | None) -> None:
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


class Ctx:
    def __init__(self) -> None:
        self.admin = os.environ["API_KEY"]
        self.http = httpx.Client(timeout=40, trust_env=False)
        self.mongo = MongoClient(os.environ["MONGODB_URL"], serverSelectionTimeoutMS=5000)
        self.db = self.mongo.get_default_database()
        self.tick = 0

    def adm(self) -> dict:
        return {"x-api-key": self.admin}

    def lease(self, org: str, app: str, token: str) -> None:
        res = self.http.post(
            f"{BASE}/organizations/{org}/sdk-credential-reconciliation-lease",
            headers=self.adm(),
            json={"application": app, "environment": ENV, "token": token,
                  "action": "acquire"})
        need(res.status_code == 200, f"lease acquire HTTP {res.status_code}")

    def issue(self, org: str, app: str, token: str, capability: str = CAP) -> tuple[str, str]:
        self.tick += 1
        stamp = datetime(2026, 11, 2, 12, 0, self.tick, tzinfo=UTC).strftime("%Y%m%dT%H%M%SZ")
        res = self.http.post(
            f"{BASE}/organizations/{org}/sdk-credential-reconciliation-lease/issue-worker-key",
            headers=self.adm(),
            json={"application": app, "environment": ENV, "plugin_id": PLUGIN,
                  "capability": capability, "token": token,
                  "name": f"{app}/{ENV}/{capability}/worker/{stamp}"})
        need(res.status_code == 201, f"fenced issue HTTP {res.status_code}")
        body = res.json()
        return body["id"], body["key"]

    def revoke_fenced(self, org: str, app: str, token: str, key_id: str) -> None:
        res = self.http.post(
            f"{BASE}/organizations/{org}/keys/{key_id}/revoke-fenced",
            headers=self.adm(),
            json={"application": app, "environment": ENV, "plugin_id": PLUGIN,
                  "token": token})
        need(res.status_code == 200, f"fenced revoke HTTP {res.status_code}")

    def caller(self, org: str) -> str:
        res = self.http.post(
            f"{BASE}/organizations/{org}/keys", headers=self.adm(),
            json={"name": f"e2e-caller-{secrets.token_hex(4)}", "environment": ENV,
                  "scopes": ["plugins:read", "plugins:execute"],
                  "allowed_capabilities": [CAP], "plugin_id": PLUGIN})
        need(res.status_code == 201, f"caller key HTTP {res.status_code}")
        return res.json()["key"]

    def row(self, org: str) -> dict | None:
        return self.db["plugin_publications"].find_one({
            "registration.kind": "remote", "registration.tenant_id": org,
            "registration.plugin_id": PLUGIN})

    def wait_registered(self, org: str, key_id: str, timeout: float = 75) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            row = self.row(org)
            if row and row["registration"].get("worker_key_id") == key_id:
                return row
            time.sleep(0.4)
        raise AssertionError("Worker never registered with the expected credential")

    def live(self, caller: str) -> bool:
        res = self.http.get(f"{BASE}/remote-plugins/capabilities",
                            headers={"x-api-key": caller})
        return res.status_code == 200 and any(
            i.get("capability_id") == CAP for i in res.json().get("items", []))

    def wait_live(self, caller: str, timeout: float = 60) -> None:
        end = time.time() + timeout
        while time.time() < end:
            if self.live(caller):
                return
            time.sleep(0.5)
        raise AssertionError("Capability never became live")

    def invoke(self, caller: str) -> httpx.Response:
        return self.http.post(f"{BASE}/remote-plugins/{CAP}/invoke",
                              headers={"x-api-key": caller}, json=PAYLOAD)

    def invoke_ok(self, caller: str, label: str) -> None:
        res = self.invoke(caller)
        need(res.status_code == 200, f"{label}: invoke HTTP {res.status_code}")
        data = res.json()
        result, replay = data["execution_result"], data["replay_contract"]
        manifest = result["manifest"]
        need(result["backend_status"] == "OPTIMAL" and result["semantic_status"] == "EXACT",
             f"{label}: Kernel result not OPTIMAL/EXACT")
        need(manifest["ir_hash"] == replay["ir_hash"]
             and manifest["decision_spec_hash"] == replay["decision_spec_hash"]
             and manifest["execution_id"] == result["execution_id"],
             f"{label}: manifest/replay mismatch")

    def approve(self, row: dict, digest: str) -> dict:
        res = self.http.post(
            f"{BASE}/plugin-publications/{row['_id']}/security/approve",
            headers={**self.adm(), "x-qdip-actor": "e2e-local-reviewer"},
            json={"expected_revision": row["revision"],
                  "plugin_version": row["registration"]["version"],
                  "reason": "Reviewed pinned test-only staffing Worker in isolated runner.",
                  "review_reference": "QDIP-E2E-ROTATION-REVIEW",
                  "risk_acknowledged": True})
        need(res.status_code == 200, f"approve HTTP {res.status_code}")
        need(res.json()["security"]["approved_manifest_sha256"] == digest, "approval digest")
        return res.json()


def never_registers(c: Ctx, org: str, expected_key_id: str, probe_caller: str,
                    seconds: float = 8) -> None:
    time.sleep(seconds)
    row = c.row(org)
    need(row is not None and row["registration"]["worker_key_id"] == expected_key_id,
         "a denied credential changed the persisted registration")


def main() -> None:
    if os.environ.get("QDIP_DISPOSABLE_RAILWAY_QA") != "true":
        raise RuntimeError("Only disposable E2E runners are supported")
    target = urlsplit(os.environ["MONGODB_URL"])
    if target.netloc != "127.0.0.1:27019" or target.path != "/qdip_e2e":
        raise RuntimeError("Refusing non-disposable MongoDB target")
    c = Ctx()
    core = worker = None
    try:
        for org in (ORG_A, ORG_B):
            c.db["organizations"].insert_one({"id": org, "name": f"Disposable {org}"})
        core = start_core(None)
        caller_a, caller_b = c.caller(ORG_A), c.caller(ORG_B)
        app_a, tok_a = f"rot-a-{secrets.token_hex(3)}", secrets.token_hex(32)
        c.lease(ORG_A, app_a, tok_a)
        key1_id, key1 = c.issue(ORG_A, app_a, tok_a)
        key2_id, key2 = c.issue(ORG_A, app_a, tok_a)
        for kid in (key1_id, key2_id):
            doc = c.db["org_api_keys"].find_one({"id": kid})
            need(doc["provisioner_issued"] is True, "fenced key lacks origin marker")
        need(c.db["org_api_keys"].find_one(
            {"key_hash": hashlib.sha256(caller_a.encode()).hexdigest()}
        ).get("provisioner_issued") is False, "generic key carries origin marker")

        # Phase 1: capture the first-party manifest digest from a real REGISTER.
        worker = start_worker(key1)
        row = c.wait_registered(ORG_A, key1_id)
        digest = registration_digest(row["registration"])
        stop(worker); stop(core)
        core = start_core(digest)

        # Phase 2: reviewed admission of the first-party Worker; baseline invoke.
        worker = start_worker(key1)
        row = c.wait_registered(ORG_A, key1_id)
        c.approve(row, digest)
        c.wait_live(caller_a)
        c.invoke_ok(caller_a, "baseline")
        approved = c.row(ORG_A)
        need(approved["security"]["state"] == "approved", "baseline not approved")
        print("ROTATION_BASELINE_ADMISSION=PASS")

        # Phase 3: trusted rotation key1 -> key2 keeps approval, no re-review.
        stop(worker)
        worker = start_worker(key2)
        row = c.wait_registered(ORG_A, key2_id)
        need(row["security"]["state"] == "approved", "rotation reset approval")
        need(row["revision"] == approved["revision"], "rotation bumped revision")
        need(row["security"]["approved_manifest_sha256"] == digest, "digest changed")
        need(registration_digest(row["registration"]) == digest, "rotated digest differs")
        c.wait_live(caller_a)
        c.invoke_ok(caller_a, "after rotation")
        print("ROTATION_KEEPS_APPROVAL_AND_EXECUTES=PASS")

        # Negative: revoked credential cannot register or take over.
        stop(worker)
        c.revoke_fenced(ORG_A, app_a, tok_a, key1_id)
        stale = start_worker(key1)
        never_registers(c, ORG_A, key2_id, caller_a)
        stop(stale)
        print("NEG_REVOKED_CREDENTIAL=PASS")

        # Negative: wrong capability (key allows another capability only).
        app_w, tok_w = f"rot-w-{secrets.token_hex(3)}", secrets.token_hex(32)
        c.lease(ORG_A, app_w, tok_w)
        _, wrong_cap = c.issue(ORG_A, app_w, tok_w, capability="other.plan")
        w = start_worker(wrong_cap)
        never_registers(c, ORG_A, key2_id, caller_a)
        stop(w)
        print("NEG_WRONG_CAPABILITY=PASS")

        # Negative: missing scope (caller key cannot act as Worker).
        w = start_worker(caller_a)
        never_registers(c, ORG_A, key2_id, caller_a)
        stop(w)
        print("NEG_MISSING_SCOPE=PASS")

        # Negative: wrong org. Provisioned key of org B never touches org A.
        app_b, tok_b = f"rot-b-{secrets.token_hex(3)}", secrets.token_hex(32)
        c.lease(ORG_B, app_b, tok_b)
        keyb_id, keyb = c.issue(ORG_B, app_b, tok_b)
        w = start_worker(keyb)
        row_b = c.wait_registered(ORG_B, keyb_id)
        need(row_b["security"]["state"] == "pending_review", "org B inherited approval")
        time.sleep(2)
        res = c.invoke(caller_b)
        need(res.status_code == 403, f"org B unapproved invoke HTTP {res.status_code}")
        need(c.row(ORG_A)["registration"]["worker_key_id"] == key2_id
             and c.row(ORG_A)["security"]["state"] == "approved", "org A changed by org B")
        stop(w)
        print("NEG_WRONG_ORG_AND_UNAPPROVED_PLUGIN=PASS")

        # Org A still serves with the rotated key after all negatives.
        worker = start_worker(key2)
        c.wait_registered(ORG_A, key2_id)
        c.wait_live(caller_a)
        c.invoke_ok(caller_a, "after negatives")

        # Negative: org-issued (non-Provisioner) key for the same plugin.
        stop(worker)
        res = c.http.post(
            f"{BASE}/organizations/{ORG_A}/keys", headers=c.adm(),
            json={"name": f"rogue-{secrets.token_hex(3)}", "environment": ENV,
                  "scopes": ["plugins:register"], "allowed_capabilities": [CAP],
                  "plugin_id": PLUGIN})
        need(res.status_code == 201, "rogue key creation")
        rogue_id, rogue = res.json()["id"], res.json()["key"]
        worker = start_worker(rogue)
        row = c.wait_registered(ORG_A, rogue_id)
        need(row["security"]["state"] == "pending_review" and row["published"] is False,
             "unmarked key inherited approval")
        time.sleep(2)
        need(c.invoke(caller_a).status_code == 403, "unmarked key executed")
        stop(worker)
        worker = start_worker(key2)
        c.wait_registered(ORG_A, key2_id)
        time.sleep(3)
        need(c.row(ORG_A)["security"]["state"] == "pending_review",
             "approval silently restored")
        need(c.invoke(caller_a).status_code == 403, "restored without re-review")
        print("NEG_NON_PROVISIONER_KEY_CANNOT_INHERIT=PASS")
        print("WORKER_KEY_ROTATION_INDEPENDENT_E2E=PASS")
    finally:
        for proc in procs:
            stop(proc)
        c.mongo.close()


if __name__ == "__main__":
    main()

"""Live two-process Core Gateway / Mongo negative-auth E2E, #407.

Starts two independent Uvicorn processes backed by an isolated temporary
Mongo database. Never claims a human Zitadel login or an approved plugin.
"""
from __future__ import annotations
import asyncio
import hashlib
import os
import secrets
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit

import httpx
from motor.motor_asyncio import AsyncIOMotorClient
from app.plugins.registration_catalog import remote_catalog_id


async def main() -> None:
    if os.environ.get("QDIP_P1_TEST_ISOLATED_DB") != "yes":
        raise RuntimeError("isolated DB opt-in required")
    original = os.environ.get("MONGODB_URL", "")
    parsed = urlsplit(original)
    if parsed.scheme not in ("mongodb", "mongodb+srv"):
        raise RuntimeError("MongoDB URL absent")
    dbname = "qdip_p1_e2e_" + secrets.token_hex(9)
    uri = urlunsplit((parsed.scheme, parsed.netloc, "/" + dbname, parsed.query, ""))
    mongo = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=8000)
    db = mongo[dbname]
    processes = []
    checks = 0

    def check(name, result):
        nonlocal checks
        if not result:
            print("SDK_P1_GATEWAYS_FAIL:" + name, flush=True)
            raise AssertionError(name)
        checks += 1
        print("SDK_P1_GATEWAYS_PASS:" + name, flush=True)

    key_a = secrets.token_urlsafe(48)
    key_b = secrets.token_urlsafe(48)
    platform_key = secrets.token_urlsafe(48)
    name_a = remote_catalog_id("e2e-org-a", "p1-test")
    try:
        hello = await mongo.admin.command("hello")
        check("replica_set", bool(hello.get("setName") or hello.get("msg") == "isdbgrid"))
        await db["organizations"].insert_many([
            {"id": org, "status": "active", "identity_provider": "zitadel",
             "zitadel_issuer": "https://test-idp.invalid",
             "zitadel_organization_id": "123"}
            for org in ("e2e-org-a", "e2e-org-b")
        ])
        await db["org_api_keys"].insert_many([
            {"id": "e2e-key-" + org[-1], "org_id": org, "plugin_id": "p1-test",
             "key_hash": hashlib.sha256(key.encode()).hexdigest(),
             "scopes": ["plugins:register"], "allowed_capabilities": ["p1.plan"],
             "revoked_at": None}
            for org, key in (("e2e-org-a", key_a), ("e2e-org-b", key_b))
        ])
        await db["plugin_publications"].insert_one({
            "_id": name_a, "registration": {
                "kind": "remote", "tenant_id": "e2e-org-a", "plugin_id": "p1-test",
                "worker_key_id": "e2e-key-a", "version": "0.1.0",
                "capabilities": {"p1.plan": "1"},
            }, "security": {"state": "pending_review"}, "published": False,
        })
        env = dict(os.environ, MONGODB_URL=uri, API_KEY=platform_key,
                   PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1")
        for port in (8121, 8122):
            p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                                  "--host", "127.0.0.1", "--port", str(port)],
                                 env=env, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            processes.append(p)
        check("independent_gateway_processes",
              len(processes) == 2 and processes[0].pid != processes[1].pid)
        async with httpx.AsyncClient(timeout=8) as client:
            for port in (8121, 8122):
                origin = "http://127.0.0.1:" + str(port)
                for _ in range(35):
                    if any(p.poll() is not None for p in processes):
                        break
                    try:
                        result = await client.get(origin + "/health")
                        if result.status_code == 200:
                            break
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass
                    await asyncio.sleep(0.5)
                else:
                    raise AssertionError("Gateway startup timeout")
                check("gateway_health_" + str(port),
                      all(p.poll() is None for p in processes))
                path = origin + "/api/v1/plugin-publication-submissions/" + name_a
                payload = {"expected_revision": 0, "capability_id": "p1.plan",
                           "plugin_version": "0.1.0", "display_name": "E2E Plugin",
                           "slug": "e2e-plugin"}
                for label, headers, expected in (
                    ("anonymous", {}, {401, 403}),
                    ("worker_without_human", {"x-api-key": key_a}, {403}),
                    ("forged_bearer", {"x-api-key": key_a,
                                      "Authorization": "Bearer not-a-zitadel-token"},
                     {403}),
                    ("wrong_org", {"x-api-key": key_b,
                                   "Authorization": "Bearer not-a-zitadel-token"},
                     {403, 404}),
                ):
                    response = await client.post(path, json=payload, headers=headers)
                    check(label + "_" + str(port), response.status_code in expected)
                response = await client.get(path, headers={"x-api-key": key_a})
                check("publisher_read_without_human_" + str(port),
                      response.status_code in (401, 403))
        check("no_publication_written",
              await db["plugin_publication_submissions"].count_documents({}) == 0)
        check("no_audit_written",
              await db["plugin_publication_submission_audit"].count_documents({}) == 0)
        check("plugin_stays_private",
              (await db["plugin_publications"].find_one({"_id": name_a}))["published"] is False)
        print("QDIP_SDK_P1_REAL_TWO_GATEWAY_E2E=PASS checks=" + str(checks), flush=True)
        print("QDIP_SDK_P1_REAL_ZITADEL_POSITIVE=NOT_TESTED", flush=True)
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        try:
            await mongo.drop_database(dbname)
            print("QDIP_SDK_P1_TWO_GATEWAY_CLEANUP=PASS", flush=True)
        finally:
            mongo.close()


if __name__ == "__main__":
    asyncio.run(main())

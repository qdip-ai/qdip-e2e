"""SDK P1 #407 real-Mongo integration, disposable database, no real Zitadel impersonation.

Requires QDIP_P1_TEST_ISOLATED_DB=yes, MONGODB_URL pointing at a test-permitted
replica-set Mongo. Never modifies the default database or existing collections.
"""
from __future__ import annotations

import asyncio
import os
import secrets
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorClient

from app.api.v1 import developer_plugin_submissions as api
from app.core.tenant.context import TenantContext
from app.plugins.registration_catalog import remote_catalog_id


async def main() -> None:
    if os.environ.get("QDIP_P1_TEST_ISOLATED_DB") != "yes":
        raise RuntimeError("disposable database opt-in missing")
    uri = os.environ.get("MONGODB_URL", "")
    if not uri.startswith(("mongodb://", "mongodb+srv://")):
        raise RuntimeError("MongoDB connection missing")
    client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=8000)
    database_name = "qdip_p1_e2e_" + secrets.token_hex(9)
    if not database_name.startswith("qdip_p1_e2e_"):
        raise RuntimeError("non-disposable db name rejected")
    db = client[database_name]
    checks = 0

    def check(name: str, condition: bool) -> None:
        nonlocal checks
        if not condition:
            print("SDK_P1_MONGO_FAIL:" + name, flush=True)
            raise AssertionError(name)
        checks += 1
        print("SDK_P1_MONGO_PASS:" + name, flush=True)

    async def publisher(owner: TenantContext, _authorization: str | None):
        return SimpleNamespace(owner_subject="e2e-test-subject",
                               zitadel_application_id="e2e-app")

    try:
        hello = await client.admin.command("hello")
        check("real_replica_set", bool(hello.get("setName") or hello.get("msg") == "isdbgrid"))
        owner_a = TenantContext(
            organization_id="e2e-org-a", key_id="e2e-worker-a", plugin_id="p1-test",
            scopes=["plugins:register"], allowed_capabilities=["p1.plan"],
        )
        owner_b = TenantContext(
            organization_id="e2e-org-b", key_id="e2e-worker-b", plugin_id="p1-test",
            scopes=["plugins:register"], allowed_capabilities=["p1.plan"],
        )
        name_a = remote_catalog_id("e2e-org-a", "p1-test")
        name_b = remote_catalog_id("e2e-org-b", "p1-test")
        row = lambda org, key: {
            "_id": remote_catalog_id(org, "p1-test"), "revision": 0, "published": False,
            "registration": {
                "kind": "remote", "tenant_id": org, "plugin_id": "p1-test",
                "worker_key_id": key, "version": "0.1.0",
                "capabilities": {"p1.plan": "1"},
            }, "security": {"state": "pending_review"},
        }
        await db["plugin_publications"].insert_many([
            row("e2e-org-a", "e2e-worker-a"),
            row("e2e-org-b", "e2e-worker-b"),
        ])
        check("tenant_namespaces_differ", name_a != name_b)
        input_a = api.SubmissionInput(
            expected_revision=0, capability_id="p1.plan", plugin_version="0.1.0",
            display_name="Disposable SDK Worker", slug="disposable-p1",
            application_launch_url="https://developer.example.org",
        )
        # Only the verified-human boundary is mocked; all Mongo operations,
        # indexes, transactions, CAS and audit use the real replica set.
        with ExitStack() as st:
            st.enter_context(patch.object(api, "get_database", lambda: db))
            st.enter_context(patch.object(api, "get_mongo_client", lambda: client))
            st.enter_context(patch.object(api, "_verified_publisher", publisher))
            a, b = await asyncio.gather(
                api.submit_plugin_for_review(name_a, input_a, owner=owner_a,
                                             authorization="Bearer test-only"),
                api.submit_plugin_for_review(name_a, input_a, owner=owner_a,
                                             authorization="Bearer test-only"),
                return_exceptions=True,
            )
            outcomes = [a, b]
            good = [x for x in outcomes if isinstance(x, dict)]
            denied = [x for x in outcomes if isinstance(x, HTTPException)]
            print("SDK_P1_CONCURRENT_OUTCOMES=" + ",".join(
                "OK" if isinstance(item, dict) else
                ("HTTP_" + str(item.status_code) if isinstance(item, HTTPException)
                 else type(item).__name__) for item in outcomes), flush=True)
            check("concurrent_first_writer_wins",
                  len(good) == 1 and len(denied) == 1 and denied[0].status_code == 409)
            read = await api.get_own_plugin_submission(name_a, owner=owner_a,
                                                        authorization="Bearer test-only")
            check("persisted_revision", read["expected_revision"] == 1)
            check("not_published", read["status"] == "PENDING_OWNERSHIP_VERIFICATION"
                  and read["catalog"]["launch_url_verified"] is False)
            audit_count = await db["plugin_publication_submission_audit"].count_documents(
                {"plugin_name": name_a}
            )
            check("single_atomic_audit", audit_count == 1)
            for candidate_owner in (owner_b, owner_a.model_copy(update={"key_id": "other"})):
                try:
                    await api.get_own_plugin_submission(name_a, owner=candidate_owner,
                                                        authorization="Bearer test-only")
                except HTTPException as exc:
                    check("cross_identity_read_denied", exc.status_code == 404)
                else:
                    raise AssertionError("tenant or key cross-read was authorized")
            try:
                await api.submit_plugin_for_review(name_a, input_a, owner=owner_a,
                                                    authorization="Bearer test-only")
            except HTTPException as exc:
                check("stale_revision_denied", exc.status_code == 409)
            else:
                raise AssertionError("stale update accepted")
            rows = await api.list_pending_plugin_submissions()
            check("pending_admin_queue", len(rows["items"]) == 1)
            persisted = await db["plugin_publications"].find_one({"_id": name_a})
            check("registration_still_private", persisted.get("published") is False)
            check("tenant_b_unchanged", await db["plugin_publications"].count_documents(
                {"_id": name_b, "published": False}
            ) == 1)
            check("no_secret_in_response",
                  "submitter_key_id" not in read and "tenant_id" not in read
                  and "publisher_subject" not in read)
        print("QDIP_SDK_P1_REAL_MONGO_INTEGRATION=PASS checks=" + str(checks), flush=True)
        print("QDIP_SDK_P1_REAL_ZITADEL_HUMAN=NOT_TESTED", flush=True)
        print("QDIP_SDK_P1_REAL_WORKER_EXECUTION=NOT_TESTED", flush=True)
    finally:
        try:
            await client.drop_database(database_name)
            print("QDIP_SDK_P1_DISPOSABLE_DB_CLEANUP=PASS", flush=True)
        finally:
            client.close()


if __name__ == "__main__":
    asyncio.run(main())

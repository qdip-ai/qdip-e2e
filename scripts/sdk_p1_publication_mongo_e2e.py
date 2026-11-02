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
            # DNS network is deterministic in this test; the real Mongo
            # reservation, CAS and audit transactions are not mocked.
            proof = read.get("domain_proof")
            check("private_dns_challenge",
                  isinstance(proof, dict)
                  and proof["record_name"] == "_qdip-plugin.developer.example.org"
                  and "domain_proof" not in rows["items"][0])
            async def verified_dns(_proof):
                return True
            st.enter_context(patch.object(api, "verify_dns_txt", verified_dns))
            ownership = await api.verify_own_plugin_domain(
                name_a, api.VerifyDomainInput(expected_revision=1),
                owner=owner_a, authorization="Bearer test-only",
            )
            check("dns_to_security_review",
                  ownership["status"] == "PENDING_SECURITY_REVIEW"
                  and ownership["expected_revision"] == 2
                  and ownership["catalog"]["launch_url_verified"] is True)
            claim = await db["plugin_publisher_domains"].find_one(
                {"_id": "developer.example.org"}
            )
            check("exclusive_domain_claim",
                  claim["plugin_name"] == name_a
                  and claim["tenant_id"] == "e2e-org-a")
            other = await api.submit_plugin_for_review(
                name_b, input_a, owner=owner_b, authorization="Bearer test-only",
            )
            check("other_org_can_submit_own_plugin",
                  other["status"] == "PENDING_OWNERSHIP_VERIFICATION")
            try:
                await api.verify_own_plugin_domain(
                    name_b, api.VerifyDomainInput(expected_revision=1),
                    owner=owner_b, authorization="Bearer test-only",
                )
            except HTTPException as exc:
                check("other_org_cannot_claim_our_domain", exc.status_code == 409)
            else:
                raise AssertionError("domain squatting accepted")
            # Register two real in-process Core Hub leases; only the WebSocket
            # transport is replaced with a deterministic socket recorder.
            from time import monotonic
            from app.remote_plugins.bridge import (
                WorkerManifest, Pending, RemoteUnavailable,
            )
            class CaptureSocket:
                def __init__(self):
                    self.sent = []
                async def send_json(self, frame):
                    self.sent.append(frame)
            manifest = WorkerManifest(
                type="REGISTER", protocol_version="0.1", plugin_id="p1-test",
                plugin_version="0.1.0", capabilities=[{
                    "id": "p1.plan", "version": "1",
                    "output_type": "decision_spec", "schema_version": "1.0.0",
                }],
            )
            socket_a, socket_b = CaptureSocket(), CaptureSocket()
            active_a = await api.hub.register(socket_a, owner_a, manifest)
            active_b = await api.hub.register(socket_b, owner_b, manifest)
            check("both_tenant_worker_leases_active",
                  active_a.active and active_b.active)
            inflight = asyncio.get_running_loop().create_future()
            active_a.pending["e2e-running"] = Pending(
                attempt_id="e2e-attempt", future=inflight,
                expires=monotonic() + 30,
            )
            decision = await api.moderate_plugin_submission(
                name_a, api.ModerationInput(expected_revision=2, action="suspend",
                    reason="Reviewer quarantined untrusted plugin"),
                x_qdip_actor="e2e-reviewer",
            )
            check("suspension_revokes_live_core_hub_worker",
                  not active_a.active and active_b.active
                  and not await api.hub.is_registered("e2e-org-a", "p1-test", "0.1.0"))
            check("suspension_sends_inflight_cancel",
                  socket_a.sent == [{
                      "type": "CANCEL", "execution_id": "e2e-running",
                      "attempt_id": "e2e-attempt",
                  }])
            check("inflight_future_cancelled", inflight.done()
                  and isinstance(inflight.exception(), RemoteUnavailable))
            check("other_tenant_connection_untouched",
                  await api.hub.is_registered("e2e-org-b", "p1-test", "0.1.0"))
            await api.hub.disconnect(active_b)
            check("audited_admin_suspension",
                  decision["status"] == "SUSPENDED"
                  and decision["expected_revision"] == 3)
            record = await db["plugin_publications"].find_one({"_id": name_a})
            check("suspend_quarantines_worker",
                  record["published"] is False
                  and record["security"]["state"] == "quarantined")
            audit = await db["plugin_publication_submission_audit"].find(
                {"plugin_name": name_a}).to_list(length=10)
            check("transactional_review_audit",
                  len(audit) == 3
                  and {row["action"] for row in audit}
                  == {"REQUEST_REVIEW", "DNS_DOMAIN_VERIFIED", "SUSPEND"})
            pending = await api.list_pending_plugin_submissions()
            check("suspended_record_left_review_queue",
                  all(row["plugin_name"] != name_a for row in pending["items"]))
            # A Worker with no external app URL is a legitimate SDK plugin.
            # Its live publisher/application ownership, not a DNS record,
            # must advance it to security review without public URL approval.
            owner_headless = TenantContext(
                organization_id="e2e-headless-org",
                key_id="e2e-worker-headless", plugin_id="p1-test",
                scopes=["plugins:register"], allowed_capabilities=["p1.plan"],
            )
            headless_name = remote_catalog_id("e2e-headless-org", "p1-test")
            await db["plugin_publications"].insert_one(
                row("e2e-headless-org", "e2e-worker-headless")
            )
            headless_submission = await api.submit_plugin_for_review(
                headless_name, input_a.model_copy(update={
                    "application_launch_url": None,
                }), owner=owner_headless, authorization="Bearer test-only",
            )
            check("headless_goes_directly_to_security_review",
                  headless_submission["status"] == "PENDING_SECURITY_REVIEW"
                  and headless_submission["domain_proof"] is None
                  and headless_submission["catalog"]["launch_url_verified"] is False)
            try:
                await api.verify_own_plugin_domain(
                    headless_name, api.VerifyDomainInput(expected_revision=1),
                    owner=owner_headless, authorization="Bearer test-only",
                )
            except HTTPException as exc:
                check("headless_cannot_fabricate_domain_proof",
                      exc.status_code == 409)
            else:
                raise AssertionError("Headless Worker accepted DNS domain proof")
            headless_audit = await db["plugin_publication_submission_audit"].find(
                {"plugin_name": headless_name}
            ).to_list(length=10)
            check("headless_audit_and_private_catalog",
                  len(headless_audit) == 1
                  and headless_audit[0]["action"] == "REQUEST_REVIEW"
                  and headless_audit[0]["status"] == "PENDING_SECURITY_REVIEW"
                  and (await db["plugin_publications"].find_one(
                      {"_id": headless_name}
                  ))["published"] is False)

            # Regression: when the publisher abandons a verified URL in a
            # revision, the old domain cannot remain locked forever. A new
            # independently verified owner must be able to claim it.
            reclaim_owners = [
                TenantContext(
                    organization_id=org, key_id=key, plugin_id="p1-test",
                    scopes=["plugins:register"], allowed_capabilities=["p1.plan"],
                )
                for org, key in (
                    ("e2e-url-old-org", "e2e-old-worker"),
                    ("e2e-url-new-org", "e2e-new-worker"),
                )
            ]
            await db["plugin_publications"].insert_many([
                row("e2e-url-old-org", "e2e-old-worker"),
                row("e2e-url-new-org", "e2e-new-worker"),
            ])
            old_owner, new_owner = reclaim_owners
            old_plugin = remote_catalog_id("e2e-url-old-org", "p1-test")
            new_plugin = remote_catalog_id("e2e-url-new-org", "p1-test")
            reclaim_url = "https://relocatable.example.org"
            old_request = input_a.model_copy(update={
                "application_launch_url": reclaim_url,
                "slug": "relocatable-previous",
            })
            new_request = old_request.model_copy(update={
                "slug": "relocatable-next",
            })
            await api.submit_plugin_for_review(
                old_plugin, old_request, owner=old_owner,
                authorization="Bearer test-only",
            )
            await api.verify_own_plugin_domain(
                old_plugin, api.VerifyDomainInput(expected_revision=1),
                owner=old_owner, authorization="Bearer test-only",
            )
            check("old_url_claim_initially_owned",
                  (await db["plugin_publisher_domains"].find_one({
                      "_id": "relocatable.example.org"
                  }))["plugin_name"] == old_plugin)
            await api.submit_plugin_for_review(
                new_plugin, new_request, owner=new_owner,
                authorization="Bearer test-only",
            )
            try:
                await api.verify_own_plugin_domain(
                    new_plugin, api.VerifyDomainInput(expected_revision=1),
                    owner=new_owner, authorization="Bearer test-only",
                )
            except HTTPException as exc:
                check("new_owner_blocked_while_old_claim_active", exc.status_code == 409)
            else:
                raise AssertionError("Concurrent domain squatting accepted")
            changed_request = old_request.model_copy(update={
                "expected_revision": 2,
                "application_launch_url": "https://replacement.example.org",
            })
            changed = await api.submit_plugin_for_review(
                old_plugin, changed_request, owner=old_owner,
                authorization="Bearer test-only",
            )
            check("changed_url_drops_verification",
                  changed["status"] == "PENDING_OWNERSHIP_VERIFICATION"
                  and changed["catalog"]["launch_url_verified"] is False)
            old_claim = await db["plugin_publisher_domains"].find_one({
                "_id": "relocatable.example.org"
            })
            check("abandoned_url_claim_released_atomically", old_claim is None)
            acquired = await api.verify_own_plugin_domain(
                new_plugin, api.VerifyDomainInput(expected_revision=1),
                owner=new_owner, authorization="Bearer test-only",
            )
            check("independent_verified_owner_can_claim_released_domain",
                  acquired["status"] == "PENDING_SECURITY_REVIEW"
                  and (await db["plugin_publisher_domains"].find_one({
                      "_id": "relocatable.example.org"
                  }))["plugin_name"] == new_plugin)
            check("replacement_url_not_auto_verified",
                  (await db["plugin_publication_submissions"].find_one({
                      "_id": old_plugin
                  }))["catalog"]["launch_url_verified"] is False)

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

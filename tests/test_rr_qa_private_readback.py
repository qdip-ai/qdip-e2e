"""Regression coverage for the QA-only private readback orchestration.

No Railway, PostgreSQL or GitHub secrets are used in these tests.
"""
import base64
import hashlib
import json
import os
import unittest
from unittest.mock import patch

from scripts import provision_rr_railway_qa as provision
from scripts.rr_qa_railway_private_readback import (
    PrivateReadbackBlocked,
    RailwayReadback,
    readback_from_ci,
)

ORG = "79320f9e-ab38-49a6-b02c-fe2b896b66aa"
FOREIGN = "rrqa-12345678-1234-1234-1234-123456789abc"


def record():
    return {
        "organization_id": ORG,
        "result": {"workflow": {"execution_id": "rr-qa-123"}},
    }


class FakeReadback(RailwayReadback):
    def __init__(self, fail_at=None):
        super().__init__("x" * 32)
        self.actions = []
        self.fail_at = fail_at

    def check_scope(self):
        self.actions.append(("scope",))

    def upsert(self, name, value):
        self.actions.append(("upsert", name))
        if self.fail_at == name:
            raise PrivateReadbackBlocked("test upsert failure")

    def latest_deployment(self):
        return "prior"

    def redeploy(self, previous):
        self.actions.append(("deploy", previous))
        return "new"

    def await_result(self, deployment, own_org):
        self.actions.append(("verify", deployment, own_org))
        return FOREIGN, "foreign-execution"

    def delete(self, name):
        self.actions.append(("delete", name))


class TestPrivateReadback(unittest.TestCase):
    def test_success_requires_exact_record_and_cleans_up(self):
        client = FakeReadback()
        self.assertEqual(client.verify(record()), (FOREIGN, "foreign-execution"))
        self.assertEqual([x[0] for x in client.actions], [
            "scope", "upsert", "upsert", "upsert", "deploy", "verify",
            "delete", "delete", "delete",
        ])
        self.assertEqual(client.actions[-3][1], "RR_E2E_READBACK_EXECUTION_ID")
        self.assertEqual(client.actions[1][1], "RR_E2E_EXPECTED_RECORD_JSON")
        self.assertEqual(client.actions[3][1], "RR_E2E_READBACK_EXECUTION_ID")

    def test_failure_cleans_ephemeral_variables(self):
        client = FakeReadback(fail_at="RR_E2E_READBACK_EXECUTION_ID")
        with self.assertRaises(PrivateReadbackBlocked):
            client.verify(record())
        self.assertEqual([x[1] for x in client.actions if x[0] == "delete"], [
            "RR_E2E_READBACK_EXECUTION_ID",
            "RR_E2E_READBACK_ORGANIZATION_ID",
            "RR_E2E_EXPECTED_RECORD_JSON",
        ])

    def test_invalid_tenant_rejected_before_provisioning(self):
        client = FakeReadback()
        bad = record()
        bad["organization_id"] = "not-a-tenant"
        with self.assertRaises(PrivateReadbackBlocked):
            client.verify(bad)
        self.assertEqual(client.actions, [])

    def test_wrong_project_token_is_rejected(self):
        client = RailwayReadback("x" * 32)
        client.gql = lambda *_: {"projectToken": {
            "projectId": "wrong", "environmentId": "wrong",
        }}
        with self.assertRaisesRegex(PrivateReadbackBlocked, "WRONG_RAILWAY_TOKEN_SCOPE"):
            client.check_scope()

    def test_exact_deployment_log_proves_db_record_and_real_foreign_org(self):
        client = RailwayReadback("x" * 32)
        foreign = base64.b64encode(json.dumps({
            "organization_id": FOREIGN, "execution_id": "foreign-execution",
        }).encode()).decode()

        def gql(query, variables):
            if "deploymentLogs" in query:
                return {"deploymentLogs": [
                    {"message": "RR_E2E_FOREIGN_RECORD_B64=" + foreign},
                    {"message": "RR_E2E_INDEPENDENT_POSTGRES_READBACK=PASS"},
                ]}
            return {"deployment": {"id": variables["id"], "status": "SUCCESS"}}

        client.gql = gql
        self.assertEqual(client.await_result("deployment", ORG), (
            FOREIGN, "foreign-execution",
        ))

    def test_private_verifier_fail_closed_on_record_mismatch(self):
        client = RailwayReadback("x" * 32)

        def gql(query, variables):
            if "deploymentLogs" in query:
                return {"deploymentLogs": [
                    {"message": "RR_E2E_INDEPENDENT_POSTGRES_READBACK=FAIL"}
                ]}
            return {"deployment": {"id": variables["id"], "status": "SUCCESS"}}

        client.gql = gql
        with self.assertRaisesRegex(PrivateReadbackBlocked, "RECORD_MISMATCH"):
            client.await_result("deployment", ORG)

    def test_untrusted_ref_never_receives_railway_token(self):
        env = {
            "GITHUB_REPOSITORY": "qdip-ai/qdip-e2e",
            "GITHUB_REF": "refs/pull/144/merge",
            "GITHUB_RUN_ID": "1",
            "RR_QA_RAILWAY_TOKEN": "x" * 32,
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(PrivateReadbackBlocked, "TRUSTED_BRANCH"):
                readback_from_ci(record())


class TestCredentialProvisioning(unittest.TestCase):
    def setUp(self):
        self.env = {
            "GITHUB_REPOSITORY": "qdip-ai/qdip-e2e",
            "GITHUB_REF": "refs/heads/feat/rr-e2e-01-standalone",
            "GITHUB_EVENT_NAME": "push", "GITHUB_ACTOR": "TarasGez",
            "RR_QA_PROVISION_APPROVED": "1",
            "RR_QA_RAILWAY_TOKEN": "r" * 32,
            "RR_QA_ORGANIZATION_ID": ORG,
            "RR_QA_ORG_API_KEY": "o" * 32,
            "RR_QA_S2S_API_KEY": "s" * 32,
            "RR_QA_ECONOMIC_API_KEY": "e" * 32,
            "RR_QA_SCHEDULING_GATEWAY_URL": "https://qdip-core-staging-staging.up.railway.app",
            "RR_QA_ECONOMIC_GATEWAY_URL": "https://qdip-core-staging-staging.up.railway.app",
        }

    def test_bind_separate_exact_scope_keys_then_redeploy_existing_services(self):
        with (patch.dict(os.environ, self.env, clear=True),
              patch.object(provision, "verify_project_token"),
              patch.object(provision, "upsert") as upsert,
              patch.object(provision, "redeploy_existing") as redeploy,
              patch("builtins.print") as output):
            provision.main()
        self.assertEqual(redeploy.call_count, 2)
        self.assertEqual([x.args[0] for x in redeploy.call_args_list], [
            provision.RR_SERVICE, provision.WEB_SERVICE,
        ])
        mapped = {(x.args[0], x.kwargs.get("service", provision.RR_SERVICE)): x.args[1]
                  for x in upsert.call_args_list}
        digest = hashlib.sha256(self.env["RR_QA_ORG_API_KEY"].encode()).hexdigest()
        read = json.loads(mapped[("RR_QA_OPERATOR_READ_CREDENTIALS_JSON", provision.RR_SERVICE)])
        write = json.loads(mapped[("RR_WRITE_CREDENTIALS_JSON", provision.RR_SERVICE)])
        self.assertEqual(read[0]["key_sha256"], digest)
        self.assertEqual(read[0]["scopes"], ["decisions:read", "audit:read"])
        self.assertEqual(write[0]["scopes"], ["decisions:execute"])
        self.assertEqual(read[0]["organization_id"], ORG)
        self.assertEqual(write[0]["organization_id"], ORG)
        self.assertEqual(mapped[("RR_ORG_API_KEY", provision.WEB_SERVICE)],
                         self.env["RR_QA_ORG_API_KEY"])
        self.assertEqual(mapped[("RR_ORGANIZATION_ID", provision.WEB_SERVICE)], ORG)
        self.assertEqual(mapped[("RR_S2S_QDIP_API_KEY", provision.RR_SERVICE)],
                         self.env["RR_QA_S2S_API_KEY"])
        messages = " ".join(" ".join(map(str, x.args)) for x in output.call_args_list)
        for secret in ("o" * 32, "s" * 32, "e" * 32):
            self.assertNotIn(secret, messages)

    def test_reject_shared_browser_and_backend_key(self):
        self.env["RR_QA_S2S_API_KEY"] = self.env["RR_QA_ORG_API_KEY"]
        with (patch.dict(os.environ, self.env, clear=True),
              patch.object(provision, "verify_project_token"),
              patch.object(provision, "upsert") as upsert):
            with self.assertRaisesRegex(ValueError, "must be distinct"):
                provision.main()
        upsert.assert_not_called()

    def test_reject_production_gateway_url(self):
        self.env["RR_QA_SCHEDULING_GATEWAY_URL"] = "https://observatory.qdip.ai"
        with (patch.dict(os.environ, self.env, clear=True),
              patch.object(provision, "verify_project_token"),
              patch.object(provision, "upsert") as upsert):
            with self.assertRaisesRegex(ValueError, "isolated Railway"):
                provision.main()
        upsert.assert_not_called()

    def test_reject_nonowner_branch(self):
        self.env["GITHUB_ACTOR"] = "untrusted"
        with (patch.dict(os.environ, self.env, clear=True),
              patch.object(provision, "verify_project_token") as token):
            with self.assertRaisesRegex(ValueError, "owner-initiated"):
                provision.main()
        token.assert_not_called()


if __name__ == "__main__":
    unittest.main()

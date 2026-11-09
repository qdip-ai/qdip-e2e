"""Regression coverage for the QA-only private readback orchestration.

No Railway, PostgreSQL or GitHub secrets are used in these tests.
"""
import base64
import hashlib
import io
import json
import os
import urllib.error
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
    def test_project_token_uses_railway_project_access_header(self):
        token = "r" * 32
        def reply(request, timeout):
            self.assertEqual(request.get_header("Project-access-token"), token)
            self.assertFalse(request.has_header("Authorization"))
            return io.BytesIO(b'{"data":{"projectToken":{"projectId":"4665798b-2012-466e-be91-2555d76f36c2","environmentId":"d867e243-4a53-413f-84a4-e33c15ecc8ba"}}}')

        with patch("urllib.request.urlopen", side_effect=reply):
            RailwayReadback(token).check_scope()

    def test_railway_http_error_logs_only_safe_status(self):
        error = urllib.error.HTTPError(
            "https://backboard.railway.com/graphql/v2",
            403, "private-token-do-not-log", {}, io.BytesIO(b"secret-payload"),
        )
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(PrivateReadbackBlocked) as raised:
                RailwayReadback("x" * 32).check_scope()
        self.assertEqual(str(raised.exception), "RR_PRIVATE_READBACK_RAILWAY_HTTP_403")
        self.assertNotIn("secret", str(raised.exception))

    def test_success_requires_exact_record_and_cleans_up(self):
        client = FakeReadback()
        self.assertEqual(client.verify(record()), (FOREIGN, "foreign-execution"))
        self.assertEqual([x[0] for x in client.actions], [
            "scope", "upsert", "upsert", "upsert", "upsert", "deploy", "verify",
            "delete", "delete", "delete", "delete",
        ])
        self.assertEqual(client.actions[-4][1], "RR_E2E_READBACK_EXECUTION_ID")
        self.assertEqual(client.actions[1][1], "RR_E2E_EXPECTED_RECORD_JSON")
        self.assertEqual(client.actions[4][1], "RR_E2E_READBACK_EXECUTION_ID")

    def test_scenario_readback_reuses_private_executor_and_cleans_up(self):
        client = FakeReadback()
        response = {
            "schema_version": "readiness-recovery.economic-scenario-preview.v1",
            "execution_id": "rr-cvar-1",
            "actionable": False, "supply_source_verified": False,
        }
        self.assertEqual(
            client.verify(response, mode="scenario", organization_id=ORG),
            (FOREIGN, "foreign-execution"),
        )
        self.assertEqual(client.actions[3], ("upsert", "RR_E2E_READBACK_KIND"))
        self.assertEqual(client.actions[4], ("upsert", "RR_E2E_READBACK_EXECUTION_ID"))
        self.assertEqual(client.actions[-1], ("delete", "RR_E2E_READBACK_KIND"))
        with self.assertRaisesRegex(PrivateReadbackBlocked, "SCENARIO_CONTRACT"):
            client.verify({**response, "actionable": True}, mode="scenario", organization_id=ORG)

    def test_failure_cleans_ephemeral_variables(self):
        client = FakeReadback(fail_at="RR_E2E_READBACK_EXECUTION_ID")
        with self.assertRaises(PrivateReadbackBlocked):
            client.verify(record())
        self.assertEqual([x[1] for x in client.actions if x[0] == "delete"], [
            "RR_E2E_READBACK_EXECUTION_ID",
            "RR_E2E_READBACK_ORGANIZATION_ID",
            "RR_E2E_EXPECTED_RECORD_JSON",
            "RR_E2E_READBACK_KIND",
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
    def test_project_token_uses_railway_project_access_header(self):
        token = "s" * 32
        def reply(request, timeout):
            self.assertEqual(request.get_header("Project-access-token"), token)
            self.assertFalse(request.has_header("Authorization"))
            return io.BytesIO(b'{"data":{"projectToken":{"projectId":"4665798b-2012-466e-be91-2555d76f36c2","environmentId":"d867e243-4a53-413f-84a4-e33c15ecc8ba"}}}')

        with patch("urllib.request.urlopen", side_effect=reply):
            provision.verify_project_token(token)

    def setUp(self):
        self.env = {
            "GITHUB_REPOSITORY": "qdip-ai/qdip-e2e",
            "GITHUB_REF": "refs/heads/feat/rr-e2e-01-standalone",
            "GITHUB_EVENT_NAME": "push", "GITHUB_ACTOR": "TarasGez",
            "RR_QA_PROVISION_APPROVED": "1",
            "RR_QA_RAILWAY_TOKEN": "r" * 32,
            "RR_QA_ORGANIZATION_ID": ORG,
            "RR_QA_ORG_API_KEY": "o" * 32,
        }

    def test_atomic_delivery_seals_secrets_and_keeps_both_services_bound(self):
        with (patch.dict(os.environ, self.env, clear=True),
              patch.object(provision, "verify_project_token"),
              patch.object(provision, "verify_existing_sealed_s2s") as verify_s2s,
              patch.object(provision, "stage_sealed_variables") as delivery,
              patch("builtins.print") as output):
            provision.main()
        verify_s2s.assert_called_once_with("r" * 32)
        delivery.assert_called_once()
        variables = delivery.call_args.args[0]
        rr = variables[provision.RR_SERVICE]
        web = variables[provision.WEB_SERVICE]
        self.assertEqual(set(variables), {provision.RR_SERVICE, provision.WEB_SERVICE})
        self.assertFalse(any(name.startswith("RR_S2S_") for name in rr))
        self.assertEqual(web["RR_ORG_API_KEY"], (self.env["RR_QA_ORG_API_KEY"], True))
        self.assertEqual(web["RR_ORGANIZATION_ID"], (ORG, False))
        digest = hashlib.sha256(self.env["RR_QA_ORG_API_KEY"].encode()).hexdigest()
        read = json.loads(rr["RR_QA_OPERATOR_READ_CREDENTIALS_JSON"][0])
        write = json.loads(rr["RR_WRITE_CREDENTIALS_JSON"][0])
        self.assertEqual(read[0]["key_sha256"], digest)
        self.assertEqual(read[0]["scopes"], ["decisions:read", "audit:read"])
        self.assertEqual(write[0]["scopes"], ["decisions:execute"])
        self.assertEqual(read[0]["organization_id"], ORG)
        self.assertEqual(write[0]["organization_id"], ORG)
        messages = " ".join(" ".join(map(str, x.args)) for x in output.call_args_list)
        for secret in ("o" * 32,):
            self.assertNotIn(secret, messages)

    def test_sealed_stage_is_atomic_and_does_not_echo_secret(self):
        data = {
            provision.RR_SERVICE: {"RR_WRITE_CREDENTIALS_JSON": ('[{"key_sha256":"sample"}]', False)},
            provision.WEB_SERVICE: {"RR_ORG_API_KEY": ("o" * 32, True)},
        }
        calls = []
        def gql(query, variables, token):
            calls.append((query, variables))
            if "environmentStagedChanges" in query:
                return {"environmentStagedChanges": None}
            if "environmentStageChanges" in query:
                patch = variables["input"]["services"]
                self.assertEqual(set(patch), {provision.RR_SERVICE, provision.WEB_SERVICE})
                self.assertFalse(patch[provision.RR_SERVICE]["variables"]["RR_WRITE_CREDENTIALS_JSON"]["isSealed"])
                self.assertTrue(patch[provision.WEB_SERVICE]["variables"]["RR_ORG_API_KEY"]["isSealed"])
                return {"environmentStageChanges": {"id": "stage", "status": "STAGED"}}
            if "environmentPatchCommitStaged" in query:
                return {"environmentPatchCommitStaged": True}
            if "variables(first:10000)" in query:
                return {"environment": {"variables": {"edges": [
                    {"node": {"serviceId": service, "name": name, "isSealed": binding[1]}}
                    for service, records in data.items() for name, binding in records.items()
                ]}}}
            raise AssertionError("Unexpected GraphQL operation")
        with patch.object(provision, "gql", side_effect=gql):
            provision.stage_sealed_variables(data, "r" * 32)
        self.assertEqual(len(calls), 4)
        self.assertEqual(sum("environmentPatchCommitStaged" in q for q, _ in calls), 1)

    def test_sealed_stage_refuses_unrelated_pending_changes(self):
        with patch.object(provision, "gql", return_value={"environmentStagedChanges": {
            "id": "pending", "status": "STAGED", "patch": {"services": {"other": {}}}
        }}) as query:
            with self.assertRaisesRegex(RuntimeError, "Unrelated staged"):
                provision.stage_sealed_variables({
                    provision.RR_SERVICE: {"RR_WRITE_CREDENTIALS_JSON": ('[]', False)}
                }, "r" * 32)
        query.assert_called_once()

    def test_sealed_stage_rejects_unsealed_receipt(self):
        records = {
            provision.RR_SERVICE: {"RR_WRITE_CREDENTIALS_JSON": ("[]", False)},
            provision.WEB_SERVICE: {"RR_ORG_API_KEY": ("o" * 32, True)},
        }
        def gql(query, variables, token):
            if "environmentStagedChanges" in query:
                return {"environmentStagedChanges": None}
            if "environmentStageChanges" in query:
                return {"environmentStageChanges": {"id": "stage", "status": "STAGED"}}
            if "environmentPatchCommitStaged" in query:
                return {"environmentPatchCommitStaged": True}
            return {"environment": {"variables": {"edges": [
                {"node": {"name": "RR_WRITE_CREDENTIALS_JSON", "serviceId": provision.RR_SERVICE, "isSealed": False}},
                {"node": {"name": "RR_ORG_API_KEY", "serviceId": provision.WEB_SERVICE, "isSealed": False}},
            ]}}}
        with patch.object(provision, "gql", side_effect=gql):
            with self.assertRaisesRegex(RuntimeError, "sealed"):
                provision.stage_sealed_variables(records, "r" * 32)

    def test_existing_s2s_requires_sealed_credentials_and_key_ids(self):
        names = {
            "RR_S2S_QDIP_API_KEY": True,
            "RR_S2S_ECONOMIC_API_KEY": True,
            "RR_S2S_QDIP_API_KEY_ID": False,
            "RR_S2S_ECONOMIC_API_KEY_ID": False,
        }
        edges = [{"node": {"name": name, "serviceId": provision.RR_SERVICE, "isSealed": sealed}}
                 for name, sealed in names.items()]
        def response(items):
            return {"environment": {"variables": {"edges": items}}}
        with patch.object(provision, "gql", return_value=response(edges)):
            provision.verify_existing_sealed_s2s("r" * 32)
        for changed in (
            edges[:-1],
            [{**item, "node": {**item["node"], "isSealed": False}}
             if item["node"]["name"] == "RR_S2S_QDIP_API_KEY" else item for item in edges],
        ):
            with patch.object(provision, "gql", return_value=response(changed)):
                with self.assertRaisesRegex(RuntimeError, "credential"):
                    provision.verify_existing_sealed_s2s("r" * 32)

    def test_s2s_key_reprovision_denied_before_railway_write(self):
        with patch.object(provision, "gql") as railway:
            with self.assertRaisesRegex(RuntimeError, "cannot be overwritten"):
                provision.stage_sealed_variables({
                    provision.RR_SERVICE: {"RR_S2S_QDIP_API_KEY": ("s" * 32, True)}
                }, "r" * 32)
        railway.assert_not_called()

    def test_missing_s2s_metadata_blocks_browser_delivery(self):
        with (patch.dict(os.environ, self.env, clear=True),
              patch.object(provision, "verify_project_token"),
              patch.object(provision, "verify_existing_sealed_s2s",
                           side_effect=RuntimeError("missing scoped credential")),
              patch.object(provision, "stage_sealed_variables") as delivery):
            with self.assertRaisesRegex(RuntimeError, "missing scoped credential"):
                provision.main()
        delivery.assert_not_called()

    def test_reject_nonowner_branch(self):
        self.env["GITHUB_ACTOR"] = "untrusted"
        with (patch.dict(os.environ, self.env, clear=True),
              patch.object(provision, "verify_project_token") as token):
            with self.assertRaisesRegex(ValueError, "owner-initiated"):
                provision.main()
        token.assert_not_called()


if __name__ == "__main__":
    unittest.main()

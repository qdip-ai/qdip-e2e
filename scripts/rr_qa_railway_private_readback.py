#!/usr/bin/env python3
"""Independent RR PostgreSQL readback through the EXISTING private Railway Function.

No PostgreSQL DSN, database proxy, or raw response is exposed in GitHub logs.
The scoped Railway project token is required only in the protected QA CI job.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

API = "https://backboard.railway.com/graphql/v2"
PROJECT = "4665798b-2012-466e-be91-2555d76f36c2"
ENVIRONMENT = "d867e243-4a53-413f-84a4-e33c15ecc8ba"
VERIFIER = "2ea0ac44-53f8-4ef8-ac97-8b8b5d74c996"
VARIABLES = (
    "RR_E2E_READBACK_EXECUTION_ID",
    "RR_E2E_READBACK_ORGANIZATION_ID",
    "RR_E2E_EXPECTED_RECORD_SHA256",
    "RR_E2E_READBACK_KIND",
)
EXECUTION_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
ORG_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f-]{27,36}$", re.I)
FOREIGN_ORG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
DEPLOYMENT_RE = re.compile(r"^[0-9a-f-]{36}$", re.I)


class PrivateReadbackBlocked(RuntimeError):
    pass


class RailwayReadback:
    def __init__(self, token: str):
        if not token or len(token) < 20:
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_RAILWAY_TOKEN_MISSING")
        self.token = token

    def gql(self, query: str, variables: dict | None = None) -> dict:
        request = urllib.request.Request(
            API,
            data=json.dumps({"query": query, "variables": variables or {}}).encode(),
            headers={
                "Project-Access-Token": self.token,
                "Content-Type": "application/json",
                "User-Agent": "qdip-rr-private-readback/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            # HTTPError subclasses URLError: classify only safe status codes,
            # never echo provider bodies, response headers or submitted values.
            code = exc.code if exc.code in (400, 401, 403, 404, 429, 500, 502, 503) else 0
            raise PrivateReadbackBlocked(f"RR_PRIVATE_READBACK_RAILWAY_HTTP_{code}") from None
        except (urllib.error.URLError, ValueError):
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_RAILWAY_API_UNAVAILABLE") from None
        if result.get("errors") or not isinstance(result.get("data"), dict):
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_RAILWAY_API_REJECTED")
        return result["data"]

    def check_scope(self) -> None:
        data = self.gql("query { projectToken { projectId environmentId } }")
        scope = data.get("projectToken") or {}
        if scope.get("projectId") != PROJECT or scope.get("environmentId") != ENVIRONMENT:
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_WRONG_RAILWAY_TOKEN_SCOPE")

    def upsert(self, name: str, value: str) -> None:
        result = self.gql(
            "mutation($input: VariableUpsertInput!) { variableUpsert(input: $input) }",
            {"input": {
                "projectId": PROJECT, "environmentId": ENVIRONMENT,
                "serviceId": VERIFIER, "name": name, "value": value,
                "skipDeploys": True,
            }},
        )
        if result.get("variableUpsert") is not True:
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_UPSERT_NOT_CONFIRMED")

    def delete(self, name: str) -> None:
        result = self.gql(
            "mutation($input: VariableDeleteInput!) { variableDelete(input: $input) }",
            {"input": {
                "projectId": PROJECT, "environmentId": ENVIRONMENT,
                "serviceId": VERIFIER, "name": name,
            }},
        )
        if result.get("variableDelete") is not True:
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_DELETE_NOT_CONFIRMED")

    def latest_deployment(self) -> str | None:
        result = self.gql(
            "query($input: DeploymentListInput!) { deployments(input: $input, first: 1) "
            "{ edges { node { id status } } } }",
            {"input": {
                "projectId": PROJECT, "environmentId": ENVIRONMENT,
                "serviceId": VERIFIER,
            }},
        )
        edges = (result.get("deployments") or {}).get("edges") or []
        return edges[0]["node"]["id"] if edges else None

    def redeploy(self, previous: str | None) -> str:
        result = self.gql(
            "mutation($serviceId: String!, $environmentId: String!) { "
            "serviceInstanceRedeploy(serviceId: $serviceId, environmentId: $environmentId) }",
            {"serviceId": VERIFIER, "environmentId": ENVIRONMENT},
        )
        value = result.get("serviceInstanceRedeploy")
        if isinstance(value, str) and DEPLOYMENT_RE.fullmatch(value):
            return value
        until = time.monotonic() + 60
        while time.monotonic() < until:
            current = self.latest_deployment()
            if current and current != previous:
                return current
            time.sleep(2)
        raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_DEPLOYMENT_ID_UNAVAILABLE")

    def await_result(self, deployment: str, own_org: str) -> tuple[str, str]:
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            status = self.gql(
                "query($id: String!) { deployment(id: $id) { id status } }",
                {"id": deployment},
            ).get("deployment") or {}
            if status.get("id") != deployment:
                raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_DEPLOYMENT_MISMATCH")
            if status.get("status") in ("FAILED", "CRASHED", "SKIPPED"):
                raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_DEPLOYMENT_FAILED")
            lines = self.gql(
                "query($deploymentId: String!, $limit: Int) { "
                "deploymentLogs(deploymentId: $deploymentId, limit: $limit) { message } }",
                {"deploymentId": deployment, "limit": 200},
            ).get("deploymentLogs") or []
            messages = [str(item.get("message", "")) for item in lines]
            if any("RR_E2E_INDEPENDENT_POSTGRES_READBACK=FAIL" in line for line in messages):
                raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_RECORD_MISMATCH")
            confirmed = any(
                "RR_E2E_INDEPENDENT_POSTGRES_READBACK=PASS" in line for line in messages
            )
            foreign = next((
                line.split("RR_E2E_FOREIGN_RECORD_B64=", 1)[1].strip()
                for line in messages if "RR_E2E_FOREIGN_RECORD_B64=" in line
            ), None)
            if confirmed and foreign:
                try:
                    decoded = json.loads(base64.b64decode(foreign, validate=True))
                    org = decoded["organization_id"]
                    execution = decoded["execution_id"]
                    if (
                        not isinstance(org, str) or org == own_org
                        or not FOREIGN_ORG_RE.fullmatch(org)
                        or not isinstance(execution, str)
                        or not EXECUTION_ID_RE.fullmatch(execution)
                    ):
                        raise ValueError("invalid foreign fixture")
                except (ValueError, KeyError, TypeError):
                    raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_FOREIGN_RECORD_INVALID") from None
                return org, execution
            time.sleep(3)
        raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_TIMED_OUT")

    def verify(self, record: dict, *, mode: str = "scheduling",
               organization_id: str | None = None) -> tuple[str, str]:
        if mode not in {"scheduling", "scenario"}:
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_UNSUPPORTED_MODE")
        own_org = organization_id if mode == "scenario" else record.get("organization_id")
        execution = (
            record.get("execution_id") if mode == "scenario" else
            record.get("result", {}).get("workflow", {}).get("execution_id")
            if isinstance(record.get("result"), dict) else None
        )
        if mode == "scenario" and (
            record.get("schema_version") != "readiness-recovery.economic-scenario-preview.v1"
            or record.get("actionable") is not False
            or record.get("supply_source_verified") is not False
        ):
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_SCENARIO_CONTRACT_INVALID")
        if not isinstance(own_org, str) or not ORG_RE.fullmatch(own_org):
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_ORGANIZATION_INVALID")
        if not isinstance(execution, str) or not EXECUTION_ID_RE.fullmatch(execution):
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_EXECUTION_INVALID")
        canonical = json.dumps(
            record, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        )
        if len(canonical.encode("utf-8")) > 1_000_000:
            raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_RECORD_TOO_LARGE")
        expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.check_scope()
        submitted = False
        try:
            # Execution ID is written last: incomplete configuration cannot run as E2E.
            for name, value in (
                (VARIABLES[2], expected_sha),
                (VARIABLES[1], own_org),
                (VARIABLES[3], mode),
                (VARIABLES[0], execution),
            ):
                self.upsert(name, value)
                submitted = True
            previous = self.latest_deployment()
            deployment = self.redeploy(previous)
            return self.await_result(deployment, own_org)
        finally:
            if submitted:
                # Delete ID first so any cleanup redeploy runs normal isolated SQL tests.
                failures = []
                for name in VARIABLES:
                    try:
                        self.delete(name)
                    except PrivateReadbackBlocked:
                        failures.append(name)
                if failures:
                    raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_EPHEMERAL_CLEANUP_FAILED")


def readback_from_ci(record: dict) -> tuple[str, str]:
    if (
        os.environ.get("GITHUB_REPOSITORY") != "qdip-ai/qdip-e2e"
        or os.environ.get("GITHUB_REF") not in {
            "refs/heads/feat/rr-e2e-01-standalone", "refs/heads/main"
        }
        or not os.environ.get("GITHUB_RUN_ID")
    ):
        raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_TRUSTED_BRANCH_REQUIRED")
    return RailwayReadback(os.environ.get("RR_QA_RAILWAY_TOKEN", "")).verify(record)


def scenario_readback_from_ci(response: dict, organization_id: str) -> tuple[str, str]:
    """Use the same existing Railway private function for a sealed CVaR response."""
    if (
        os.environ.get("GITHUB_REPOSITORY") != "qdip-ai/qdip-e2e"
        or not (
            os.environ.get("GITHUB_REF") == "refs/heads/feat/rr-e2e-01-standalone"
            or (
                os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and os.environ.get("GITHUB_ACTOR") == "TarasGez"
            )
        )
        or not os.environ.get("GITHUB_RUN_ID")
    ):
        raise PrivateReadbackBlocked("RR_PRIVATE_READBACK_TRUSTED_BRANCH_REQUIRED")
    return RailwayReadback(os.environ.get("RR_QA_RAILWAY_TOKEN", "")).verify(
        response, mode="scenario", organization_id=organization_id,
    )

#!/usr/bin/env python3
"""Live Railway sealed-variable stage/commit E2E; test-owned staging target only.

No fake GraphQL responses, no production paths and no plaintext secret readback.
Separate SDK Worker REGISTER/invoke tests must follow this transport gate.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

PROJECT = "f1326384-1e2d-4bea-99a9-bbae2233e36e"
ENVIRONMENT = "9e4a6dac-717c-4327-bb1e-1491a4e5c080"
TARGET_SERVICE = "0694f43b-1197-4fd2-a429-82be6b4ca81d"
TARGET_NAME = "rr-sdk-staging-e2e-qa"
SECRET_NAME = "SDK383_E2E_SEALED_CANARY"
KEY_ID_NAME = SECRET_NAME + "_ID"
GRAPHQL = "https://backboard.railway.com/graphql/v2"
POLL_SECONDS = 5
DEPLOY_TIMEOUT = 180


class GateError(Exception):
    """A failed acceptance gate; never include server response bodies."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, url):
        raise GateError("Railway API redirected")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


class Railway:
    def __init__(self, token: str, service_id: str = TARGET_SERVICE,
                 service_name: str = TARGET_NAME) -> None:
        require(len(token) >= 20, "Missing scoped Railway project token")
        require(not token.startswith("${{"), "Unresolved Railway token reference")
        self.token = token
        self.target_service = service_id
        self.target_name = service_name
        self.opener = build_opener(NoRedirect())

    def query(self, document: str, variables: dict | None = None) -> dict:
        request = Request(
            GRAPHQL,
            data=json.dumps({"query": document, "variables": variables or {}}).encode(),
            headers={"Content-Type": "application/json",
                     "Project-Access-Token": self.token,
                     "User-Agent": "qdip-e2e-sdk383-sealed/1"},
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                body = response.read(1_048_577)
        except HTTPError as exc:
            # Map only known authentication failures; never print response data.
            try:
                failure = json.loads(exc.read(4096))
                errors = failure.get("errors") if isinstance(failure, dict) else None
                messages = [e.get("message") for e in errors if isinstance(e, dict)] if isinstance(errors, list) else []
            except (ValueError, UnicodeDecodeError, OSError):
                messages = []
            # Classification only; never forward server-controlled error text.
            error_blob = " ".join(str(m).lower() for m in messages if isinstance(m, str))
            if isinstance(failure, dict):
                for field in ("error", "message"):
                    if isinstance(failure.get(field), str):
                        error_blob += " " + failure[field].lower()
            if "token" in error_blob and ("not found" in error_blob or "invalid" in error_blob):
                category = " invalid_project_token"
            elif "unauthorized" in error_blob or "permission" in error_blob:
                category = " unauthorized"
            elif "syntax" in error_blob or "graphql" in error_blob:
                category = " graphQL_validation"
            else:
                category = " unknown_response"
            raise GateError("Railway GraphQL HTTP status " + str(exc.code) + category) from None
        except (URLError, TimeoutError, OSError) as exc:
            raise GateError("Railway GraphQL HTTP unavailable: " + type(exc).__name__) from None
        require(len(body) <= 1_048_576, "Railway GraphQL response too large")
        try:
            parsed = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise GateError("Railway GraphQL response invalid") from None
        require(isinstance(parsed, dict) and not parsed.get("errors")
                and isinstance(parsed.get("data"), dict),
                "Railway GraphQL rejected the request")
        return parsed["data"]

    def scope(self) -> None:
        token = self.query("query { projectToken { projectId environmentId } }")
        require(token.get("projectToken") == {
            "projectId": PROJECT, "environmentId": ENVIRONMENT,
        }, "Railway token is not scoped to the isolated staging environment")
        project = self.query(
            "query ($p: String!) { project(id: $p) { id "
            "environments { edges { node { id name } } } "
            "services { edges { node { id name } } } } }",
            {"p": PROJECT},
        ).get("project") or {}
        require(project.get("id") == PROJECT, "Railway project identity mismatch")
        environments = [x.get("node") or {} for x in
                        (project.get("environments") or {}).get("edges") or []]
        services = [x.get("node") or {} for x in
                    (project.get("services") or {}).get("edges") or []]
        require(sum(x.get("id") == ENVIRONMENT and x.get("name") == "staging"
                    for x in environments) == 1,
                "Railway environment is not staging")
        require(sum(x.get("id") == self.target_service and x.get("name") == self.target_name
                    for x in services) == 1,
                "Target is not the pinned disposable staging QA service")

    def pending(self) -> None:
        change = self.query(
            "query ($e: String!) { environmentStagedChanges(environmentId: $e) }",
            {"e": ENVIRONMENT},
        ).get("environmentStagedChanges")
        require(change in (None, {}, []),
                "Unrelated Railway staged changes exist; refusing to overwrite")

    def metadata(self) -> tuple[list[dict], dict]:
        result = self.query(
            "query ($p: String!, $e: String!, $s: String!) { "
            "environment(id: $e, projectId: $p) { variables(first: 10000) "
            "{ edges { node { name serviceId isSealed } } } } "
            "variables(projectId: $p, environmentId: $e, serviceId: $s) }",
            {"p": PROJECT, "e": ENVIRONMENT, "s": self.target_service},
        )
        env = result.get("environment") or {}
        edges = (env.get("variables") or {}).get("edges") or []
        nodes = [edge.get("node") or {} for edge in edges if isinstance(edge, dict)]
        scoped = [x for x in nodes if x.get("serviceId") == self.target_service]
        values = result.get("variables")
        require(isinstance(values, dict), "Railway variable metadata unavailable")
        # DO NOT print or serialize values: other project variables may be readable.
        return scoped, values

    def deployment(self) -> dict:
        result = self.query(
            "query ($i: DeploymentListInput!) { deployments(input: $i, first: 1) "
            "{ edges { node { id status createdAt } } } }",
            {"i": {"projectId": PROJECT, "environmentId": ENVIRONMENT,
                   "serviceId": self.target_service}},
        )
        edges = (result.get("deployments") or {}).get("edges") or []
        require(len(edges) == 1, "No target service deployment")
        return edges[0]["node"]

    def stage_commit(self, values: dict) -> None:
        self.pending()
        patch = {"services": {self.target_service: {"variables": values}}}
        staged = self.query(
            "mutation ($e: String!, $input: EnvironmentConfig!, $merge: Boolean) "
            "{ environmentStageChanges(environmentId: $e, input: $input, merge: $merge) "
            "{ id status } }",
            {"e": ENVIRONMENT, "input": patch, "merge": False},
        ).get("environmentStageChanges")
        require(isinstance(staged, dict) and isinstance(staged.get("id"), str)
                and bool(staged["id"]), "Railway did not stage protected patch")
        # Any ambiguous result must stop rather than retry or commit a foreign patch.
        committed = self.query(
            "mutation ($e: String!) "
            "{ environmentPatchCommitStaged(environmentId: $e) }",
            {"e": ENVIRONMENT},
        ).get("environmentPatchCommitStaged")
        require(committed is not None and committed is not False,
                "Railway staged patch commit not confirmed")

    def wait_new_deployment(self, previous: str) -> str:
        deadline = time.monotonic() + DEPLOY_TIMEOUT
        new_id = None
        while time.monotonic() < deadline:
            latest = self.deployment()
            if latest.get("id") != previous:
                new_id = latest.get("id")
                if latest.get("status") == "SUCCESS":
                    return new_id
                require(latest.get("status") not in
                        {"FAILED", "CRASHED", "REMOVED", "SKIPPED"},
                        "New service deployment failed")
            time.sleep(POLL_SECONDS)
        raise GateError("Railway patch did not produce a successful new deployment")


def present(nodes: list[dict], name: str) -> list[dict]:
    return [x for x in nodes if x.get("name") == name]


def assert_sealed(nodes: list[dict], values: dict, identifier: str) -> None:
    secret_nodes = present(nodes, SECRET_NAME)
    id_nodes = present(nodes, KEY_ID_NAME)
    require(len(secret_nodes) == 1 and secret_nodes[0].get("isSealed") is True,
            "Sealed-variable readback is missing or unsealed")
    require(len(id_nodes) == 1 and id_nodes[0].get("isSealed") is False,
            "Public key ID metadata is missing or sealed")
    require(values.get(KEY_ID_NAME) == identifier,
            "Railway public key ID does not match committed credential")
    # Critically: never inspect values.get(SECRET_NAME).


def main() -> int:
    require(os.getenv("QDIP_SDK383_E2E_APPROVED") ==
            "isolated-staging-qa-only", "Missing explicit isolated-QA approval")
    require(os.getenv("RAILWAY_PROJECT_ID") == PROJECT and
            os.getenv("RAILWAY_ENVIRONMENT_ID") == ENVIRONMENT,
            "Runtime is not the exact staging Railway environment")
    railway = Railway(os.environ.get("RAILWAY_PROJECT_TOKEN", ""))
    railway.scope()
    railway.pending()
    nodes, values = railway.metadata()
    require(not present(nodes, SECRET_NAME) and not present(nodes, KEY_ID_NAME)
            and SECRET_NAME not in values and KEY_ID_NAME not in values,
            "Test-owned canary already exists; never overwrite unknown state")
    previous = railway.deployment()["id"]
    identifier = str(uuid.uuid4())
    secret = secrets.token_urlsafe(48)
    committed = False
    cleaned = False
    try:
        railway.stage_commit({
            SECRET_NAME: {"value": secret, "isSealed": True},
            KEY_ID_NAME: {"value": identifier, "isSealed": False},
        })
        committed = True
        nodes, values = railway.metadata()
        assert_sealed(nodes, values, identifier)
        deployed = railway.wait_new_deployment(previous)
        print("SDK383_RAILWAY_SEALED_STAGE_COMMIT_READBACK=PASS", flush=True)
        print("SDK383_RAILWAY_SEALED_DEPLOY_ONCE=PASS id=" + deployed, flush=True)
    finally:
        if committed:
            try:
                previous_cleanup = railway.deployment()["id"]
                # Only these two names were absent before the test.
                railway.stage_commit({SECRET_NAME: None, KEY_ID_NAME: None})
                railway.wait_new_deployment(previous_cleanup)
                nodes, values = railway.metadata()
                require(not present(nodes, SECRET_NAME) and not present(nodes, KEY_ID_NAME)
                        and SECRET_NAME not in values and KEY_ID_NAME not in values,
                        "Sealed canary cleanup not verified")
                cleaned = True
                print("SDK383_RAILWAY_SEALED_ROLLBACK_CLEANUP=PASS", flush=True)
            except GateError:
                # Never print secrets or silently approve incomplete cleanup.
                raise GateError("Sealed test patch cleanup unverified; manual inspection required") from None
    require(cleaned, "Test did not complete cleanup")
    print("SDK383_RAILWAY_SEALED_E2E=PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GateError, KeyError) as exc:
        # Exception messages come only from our own sanitised error strings.
        print("SDK383_RAILWAY_SEALED_E2E=BLOCKED:" +
              (str(exc) if isinstance(exc, GateError) else "missing environment"), flush=True)
        raise SystemExit(2) from None

#!/usr/bin/env python3
"""Bind the existing RR QA browser credential without rotating reconciler-owned S2S keys."""
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://backboard.railway.com/graphql/v2"
PROJECT = "4665798b-2012-466e-be91-2555d76f36c2"
ENVIRONMENT = "d867e243-4a53-413f-84a4-e33c15ecc8ba"
RR_SERVICE = "56d5e527-958d-4770-b2da-9a305a15276d"
WEB_SERVICE = "7a758776-a3c3-4351-92b1-f269ee4cd26c"
VERIFIED_CORE_STAGING_ORG = "79320f9e-ab38-49a6-b02c-fe2b896b66aa"

def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError("Missing trusted CI binding: " + name)
    return value

def gql(query, variables, token):
    payload = json.dumps({"query": query, "variables": variables}).encode()
    request = urllib.request.Request(API, data=payload, headers={
        "Project-Access-Token": token, "Content-Type": "application/json",
    }, method="POST")
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.load(response)
    if result.get("errors") or not isinstance(result.get("data"), dict):
        # Railway errors can echo submitted values, so never include the body.
        raise RuntimeError("Railway refused a scoped QA operation")
    return result["data"]

def verify_project_token(token):
    scope = gql("query { projectToken { projectId environmentId } }", {}, token).get("projectToken") or {}
    if scope.get("projectId") != PROJECT or scope.get("environmentId") != ENVIRONMENT:
        raise RuntimeError("RR QA Railway token is not bound to exact project/environment")

def verify_existing_sealed_s2s(token):
    """Require reconciler-owned sealed credentials without attempting secret readback."""
    receipt = gql(
        "query($e:String!,$p:String!){environment(id:$e,projectId:$p){"
        "variables(first:10000){edges{node{name serviceId isSealed}}}}}",
        {"e": ENVIRONMENT, "p": PROJECT}, token,
    ).get("environment")
    edges = (((receipt or {}).get("variables") or {}).get("edges") or [])
    if not isinstance(edges, list):
        raise RuntimeError("Railway RR QA credential metadata unavailable")
    nodes = [edge["node"] for edge in edges if isinstance(edge, dict)
             and isinstance(edge.get("node"), dict)]
    for name in ("RR_S2S_QDIP_API_KEY", "RR_S2S_ECONOMIC_API_KEY"):
        matches = [n for n in nodes if n.get("name") == name and n.get("serviceId") == RR_SERVICE]
        if len(matches) != 1 or matches[0].get("isSealed") is not True:
            raise RuntimeError("Reconciler-owned RR QA S2S credential missing or unsealed")
    for name in ("RR_S2S_QDIP_API_KEY_ID", "RR_S2S_ECONOMIC_API_KEY_ID"):
        if sum(n.get("name") == name and n.get("serviceId") == RR_SERVICE for n in nodes) != 1:
            raise RuntimeError("Reconciler-owned RR QA S2S credential ID missing")


def stage_sealed_variables(bindings, token):
    """One atomic QA-only Railway patch; no raw credentials in logs or readback."""
    if set(bindings) != {RR_SERVICE, WEB_SERVICE} and set(bindings) != {RR_SERVICE}:
        raise RuntimeError("Unexpected Railway destination")
    if any(isinstance(records, dict) and any(name.startswith("RR_S2S_") for name in records)
           for records in bindings.values()):
        raise RuntimeError("Reconciler-owned RR S2S variables cannot be overwritten")
    current = gql(
        "query($e:String!){environmentStagedChanges(environmentId:$e){id status patch}}",
        {"e": ENVIRONMENT}, token,
    ).get("environmentStagedChanges")
    if current not in (None, {}, []) and not (
        isinstance(current, dict) and current.get("status") == "STAGED"
        and current.get("patch") == {}
    ):
        raise RuntimeError("Unrelated staged Railway changes; refusing credential overwrite")

    services = {}
    for service, records in bindings.items():
        if not isinstance(records, dict) or not records:
            raise RuntimeError("Empty Railway delivery")
        variables = {}
        for name, binding in records.items():
            if (not isinstance(binding, tuple) or len(binding) != 2
                    or not isinstance(binding[0], str) or not binding[0]
                    or type(binding[1]) is not bool):
                raise RuntimeError("Malformed QA credential binding")
            value, sealed = binding
            if name in ("RR_S2S_QDIP_API_KEY", "RR_S2S_ECONOMIC_API_KEY", "RR_ORG_API_KEY") and not sealed:
                raise RuntimeError("Credential must be sealed at rest")
            variables[name] = {"value": value, "isSealed": sealed}
        services[service] = {"variables": variables}

    stage = gql(
        "mutation($e:String!,$input:EnvironmentConfig!,$merge:Boolean){"
        "environmentStageChanges(environmentId:$e,input:$input,merge:$merge){id status}}",
        {"e": ENVIRONMENT, "input": {"services": services}, "merge": False}, token,
    ).get("environmentStageChanges")
    if not isinstance(stage, dict) or not stage.get("id"):
        raise RuntimeError("Railway did not acknowledge sealed staging")
    # Never retry an ambiguous commit: Core credentials are one-time issue.
    committed = gql(
        "mutation($e:String!){environmentPatchCommitStaged(environmentId:$e)}",
        {"e": ENVIRONMENT}, token,
    ).get("environmentPatchCommitStaged")
    if committed is None or committed is False:
        raise RuntimeError("Railway sealed commit acknowledgment missing")

    receipt = gql(
        "query($e:String!,$p:String!){environment(id:$e,projectId:$p){"
        "variables(first:10000){edges{node{name serviceId isSealed}}}}}",
        {"e": ENVIRONMENT, "p": PROJECT}, token,
    ).get("environment")
    edges = (((receipt or {}).get("variables") or {}).get("edges") or [])
    if not isinstance(edges, list):
        raise RuntimeError("Railway sealed metadata unavailable")
    nodes = [edge.get("node") or {} for edge in edges if isinstance(edge, dict)]
    for service, records in bindings.items():
        for name, (_, sealed) in records.items():
            matching = [node for node in nodes if (
                node.get("name") == name and node.get("serviceId") == service
            )]
            if len(matching) != 1 or matching[0].get("isSealed") is not sealed:
                raise RuntimeError("Railway sealed delivery metadata mismatch")
    # The atomic environment patch automatically schedules service redeploys.
    print("RR_QA_ATOMIC_SEALED_DELIVERY=PASS")


def main():
    if os.environ.get("GITHUB_REPOSITORY") != "qdip-ai/qdip-e2e":
        raise ValueError("Unexpected GitHub repository")
    branch = os.environ.get("GITHUB_REF")
    if branch == "refs/heads/main":
        if os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            raise ValueError("Main provisioning requires manual dispatch")
    elif branch == "refs/heads/feat/rr-e2e-01-standalone":
        if (os.environ.get("GITHUB_EVENT_NAME") != "push"
                or os.environ.get("GITHUB_ACTOR") != "TarasGez"):
            raise ValueError("Pre-merge provisioning requires owner-initiated trusted branch push")
    else:
        raise ValueError("Unapproved QA provisioning branch")
    if os.environ.get("RR_QA_PROVISION_APPROVED") != "1":
        raise ValueError("QA provisioning must be explicitly approved")
    token = required("RR_QA_RAILWAY_TOKEN")
    verify_project_token(token)
    organization = required("RR_QA_ORGANIZATION_ID")
    if organization != VERIFIED_CORE_STAGING_ORG:
        raise ValueError("RR QA organization must match verified Core staging tenant")
    verify_existing_sealed_s2s(token)
    inbound = required("RR_QA_ORG_API_KEY")
    if len(inbound) < 24:
        raise ValueError("RR QA browser credential is unexpectedly short")
    key_digest = hashlib.sha256(inbound.encode()).hexdigest()
    credential = json.dumps([{
        "key_sha256": key_digest,
        "organization_id": organization, "scopes": ["decisions:execute"],
    }], separators=(",", ":"))
    operator_read = json.dumps([{
        "key_sha256": key_digest,
        "organization_id": organization, "scopes": ["decisions:read", "audit:read"],
    }], separators=(",", ":"))
    # Stage both services together so no partial key set can become live.
    bindings = {
        RR_SERVICE: {
            "RR_WRITE_CREDENTIALS_JSON": (credential, False),
            "RR_QA_OPERATOR_READ_CREDENTIALS_JSON": (operator_read, False),
        },
        WEB_SERVICE: {
            "RR_ORGANIZATION_ID": (organization, False),
            "RR_ORG_API_KEY": (inbound, True),
        },
    }
    stage_sealed_variables(bindings, token)
    # No unreviewed write/economic feature activation here. These remain
    # subject to their existing independent QA and E2E acceptance gates.
    print("RR_QA_WRITE_ACTIVATION=NOT_PERFORMED")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, urllib.error.URLError) as exc:
        print("RR_QA_PROVISIONING_BLOCKED=" + type(exc).__name__, file=sys.stderr)
        sys.exit(2)

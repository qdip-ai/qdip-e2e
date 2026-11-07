#!/usr/bin/env python3
"""Provision existing RR Railway QA service from trusted CI secrets; never print secrets."""
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

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
        "Authorization": "Bearer " + token, "Content-Type": "application/json",
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

def upsert(name, value, token, service=RR_SERVICE):
    if service not in (RR_SERVICE, WEB_SERVICE):
        raise RuntimeError("Unexpected Railway destination")
    result = gql("""mutation($input: VariableUpsertInput!) {
      variableUpsert(input: $input)
    }""", {"input": {
        "projectId": PROJECT, "environmentId": ENVIRONMENT,
        "serviceId": service, "name": name, "value": value,
        "skipDeploys": True,
    }}, token)
    if result.get("variableUpsert") is not True:
        raise RuntimeError("Railway did not confirm variable upsert for " + name)

def redeploy_existing(service, token):
    if service not in (RR_SERVICE, WEB_SERVICE):
        raise RuntimeError("Unexpected Railway redeploy destination")
    result = gql("""mutation($serviceId: String!, $environmentId: String!) {
      serviceInstanceRedeploy(serviceId: $serviceId, environmentId: $environmentId)
    }""", {"serviceId": service, "environmentId": ENVIRONMENT}, token)
    if not result.get("serviceInstanceRedeploy"):
        raise RuntimeError("Railway did not accept the existing QA redeploy")

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
    inbound = required("RR_QA_ORG_API_KEY")
    scheduling = required("RR_QA_S2S_API_KEY")
    economic = required("RR_QA_ECONOMIC_API_KEY")
    gateway_url = required("RR_QA_SCHEDULING_GATEWAY_URL")
    economic_url = required("RR_QA_ECONOMIC_GATEWAY_URL")
    for url in (gateway_url, economic_url):
        parsed = urlsplit(url)
        if (
            parsed.username or parsed.password or parsed.fragment
            or parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or not (
                parsed.scheme == "https" and parsed.hostname.endswith(".up.railway.app")
                or parsed.scheme == "http" and parsed.hostname.endswith(".railway.internal")
            )
        ):
            raise ValueError("RR QA gateway must be an isolated Railway address")
    if len(inbound) < 24 or len(scheduling) < 24 or len(economic) < 24:
        raise ValueError("RR QA credentials are unexpectedly short")
    key_digest = hashlib.sha256(inbound.encode()).hexdigest()
    credential = json.dumps([{
        "key_sha256": key_digest,
        "organization_id": organization, "scopes": ["decisions:execute"],
    }], separators=(",", ":"))
    operator_read = json.dumps([{
        "key_sha256": key_digest,
        "organization_id": organization, "scopes": ["decisions:read", "audit:read"],
    }], separators=(",", ":"))
    # Configure dependencies first; enable gates only after credentials are in place.
    variables = {
        "RR_WRITE_CREDENTIALS_JSON": credential,
        "RR_QA_OPERATOR_READ_CREDENTIALS_JSON": operator_read,
        "RR_S2S_QDIP_API_KEY": scheduling,
        "RR_S2S_ECONOMIC_API_KEY": economic,
        "RR_S2S_GATEWAY_URL": gateway_url,
        "RR_S2S_ECONOMIC_GATEWAY_URL": economic_url,
    }
    for name, value in variables.items():
        upsert(name, value, token)
        print("RR_QA_PROVISIONED=" + name)
    # BFF must use the exact same tenant/key as the RR read+write credential
    # verifier; otherwise apparent OIDC success masks a mismatched tenant.
    for name, value in {
        "RR_ORGANIZATION_ID": organization, "RR_ORG_API_KEY": inbound,
    }.items():
        upsert(name, value, token, service=WEB_SERVICE)
        print("RR_QA_WEB_BOUND=" + name)
    # skipDeploys keeps partial credential sets from becoming live; start one
    # redeploy per existing QA service after all bindings are accepted.
    for service, label in ((RR_SERVICE, "rr-api"), (WEB_SERVICE, "web-bff")):
        redeploy_existing(service, token)
        print("RR_QA_REDEPLOY_REQUESTED=" + label)
    # No unreviewed write/economic feature activation here; these are separate
    # existing QA flags and remain subject to their original acceptance gates.
    print("RR_QA_WRITE_ACTIVATION=NOT_PERFORMED")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, urllib.error.URLError) as exc:
        print("RR_QA_PROVISIONING_BLOCKED=" + type(exc).__name__, file=sys.stderr)
        sys.exit(2)

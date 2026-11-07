#!/usr/bin/env python3
"""Provision existing RR Railway QA service from trusted CI secrets; never print secrets."""
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

def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError("Missing trusted CI binding: " + name)
    return value

def upsert(name, value, token):
    query = """mutation($input: VariableUpsertInput!) {
      variableUpsert(input: $input)
    }"""
    payload = json.dumps({"query": query, "variables": {"input": {
        "projectId": PROJECT, "environmentId": ENVIRONMENT,
        "serviceId": RR_SERVICE, "name": name, "value": value,
    }}}).encode()
    request = urllib.request.Request(API, data=payload, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json",
    }, method="POST")
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.load(response)
    if result.get("errors"):
        raise RuntimeError("Railway rejected variable upsert for " + name)
    if result.get("data", {}).get("variableUpsert") is not True:
        raise RuntimeError("Railway did not confirm variable upsert for " + name)

def main():
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ValueError("Provisioning requires reviewed main branch")
    if os.environ.get("RR_QA_PROVISION_APPROVED") != "1":
        raise ValueError("QA provisioning must be explicitly approved")
    token = required("RR_QA_RAILWAY_TOKEN")
    organization = required("RR_QA_ORGANIZATION_ID")
    if not all(c.isalnum() or c in "_.-" for c in organization) or len(organization) > 128:
        raise ValueError("Invalid QA organization ID")
    inbound = required("RR_QA_ORG_API_KEY")
    scheduling = required("RR_QA_S2S_API_KEY")
    economic = required("RR_QA_ECONOMIC_API_KEY")
    gateway_url = required("RR_QA_SCHEDULING_GATEWAY_URL")
    economic_url = required("RR_QA_ECONOMIC_GATEWAY_URL")
    for url in (gateway_url, economic_url):
        if not url.startswith("https://") and not (
            url.startswith("http://") and ".railway.internal/" in url
        ):
            raise ValueError("Gateway URL must be HTTPS or Railway private HTTP")
    scopes = ["rr:scheduling:write", "rr:economic:write"]
    credential = json.dumps([{
        "key_sha256": hashlib.sha256(inbound.encode()).hexdigest(),
        "organization_id": organization, "scopes": scopes,
    }], separators=(",", ":"))
    # Configure dependencies first; enable gates only after credentials are in place.
    variables = {
        "RR_WRITE_CREDENTIALS_JSON": credential,
        "RR_S2S_QDIP_API_KEY": scheduling,
        "RR_S2S_ECONOMIC_API_KEY": economic,
        "RR_S2S_GATEWAY_URL": gateway_url,
        "RR_S2S_ECONOMIC_GATEWAY_URL": economic_url,
    }
    for name, value in variables.items():
        upsert(name, value, token)
        print("RR_QA_PROVISIONED=" + name)
    # Explicitly do not activate writes here: activation requires verified
    # database migrations, operator assertions, and independent QA preflight.
    print("RR_QA_WRITE_ACTIVATION=NOT_PERFORMED")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, urllib.error.URLError) as exc:
        print("RR_QA_PROVISIONING_BLOCKED=" + type(exc).__name__, file=sys.stderr)
        sys.exit(2)

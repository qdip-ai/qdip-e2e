"""Independent loopback customer MCP E2E; only the identity provider is synthetic.

Run on the existing isolated E2E runner with pinned product checkouts and native Mongo.
No production credentials, live customer data, mocked service responses or Worker.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

ISSUER = "https://identity.example.invalid"
PROJECT, MCP_PROJECT, EXTERNAL_ORG = "202", "100", "456"
APP, OWNER, CLIENT, AGENT = "301", "9000", "8000", "123456"
SUBJECTS = {"a": "9001", "b": "9002"}
PLUGIN = "qdip-serviceops"
CAPABILITY = "serviceops.assignment.propose"
ORG = "aaaa0000-aaaa-4000-8000-aaaaaaaaaaaa"
CORE_URL, SO_URL = "https://127.0.0.1:18443", "https://127.0.0.1:18444"
MONGO = "mongodb://127.0.0.1:27019/qdip_mcp_customer_e2e?replicaSet=rrtest&directConnection=true"


def run_core():
    import httpx
    import uvicorn
    from app.api.v1 import private_resource_access as access
    from app.core.tenant import application_ownership as ownership
    from app.main import app
    from app.ops.zitadel_application_ownership import VerifiedApplicationOwner
    from app.ops.zitadel_user_introspection import verify_zitadel_subject

    async def verify_owner(**kwargs):
        assert kwargs == dict(issuer=ISSUER, organization_id=EXTERNAL_ORG,
                              application_id=APP, owner_subject=OWNER)
        return VerifiedApplicationOwner(issuer=ISSUER, organization_id=EXTERNAL_ORG,
            application_id=APP, project_id=PROJECT, owner_subject=OWNER, oidc_client_id=CLIENT)

    def identity_provider(request):
        from urllib.parse import parse_qs
        token = parse_qs(request.content.decode()).get("token", [""])[0]
        subject = next((value for name, value in SUBJECTS.items()
                        if token == f"fixture-customer-{name}-token"), None)
        now = int(time.time())
        return httpx.Response(200, json={"active": bool(subject), "sub": subject,
            "iss": ISSUER, "aud": [PROJECT, MCP_PROJECT], "client_id": AGENT,
            "token_type": "Bearer", "iat": now-10, "exp": now+600, "scope": "openid"})

    async def verify(token, **kwargs):
        return await verify_zitadel_subject(token, **kwargs,
            transport=httpx.MockTransport(identity_provider))

    ownership.verify_application_owner = verify_owner
    access.verify_zitadel_subject = verify
    uvicorn.run(app, host="127.0.0.1", port=18443, lifespan="off",
                ssl_certfile=os.environ["E2E_CERT"], ssl_keyfile=os.environ["E2E_TLS_KEY"],
                access_log=False)


def run_so():
    import uvicorn
    from cryptography.hazmat.primitives import serialization
    from types import SimpleNamespace
    from serviceops_api import auth
    from serviceops_api.app import app

    public = serialization.load_pem_public_key(Path(os.environ["E2E_JWT_PUBLIC"]).read_bytes())
    # Provider JWKS is the only substituted dependency; actual JWT signature,
    # audience, issuer, membership and plan enforcement remain unchanged.
    auth._keys = lambda issuer: SimpleNamespace(
        get_signing_key_from_jwt=lambda token: SimpleNamespace(key=public))
    uvicorn.run(app, host="127.0.0.1", port=18444, lifespan="off",
                ssl_certfile=os.environ["E2E_CERT"], ssl_keyfile=os.environ["E2E_TLS_KEY"],
                access_log=False)


def wait_http(process, url, cert):
    import httpx
    with httpx.Client(verify=cert, timeout=1, trust_env=False) as client:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("service terminated")
            try:
                if client.get(url + "/openapi.json").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(.2)
    raise RuntimeError("service unavailable")


def scenario(core_path, so_path, mcp_path):
    import httpx
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pymongo import MongoClient
    from serviceops_api import plans
    from serviceops_api.auth import link_identity
    from serviceops_core import ServiceOpsCore

    assert os.environ.get("GITHUB_ACTIONS") == "true"
    script = Path(__file__).resolve()
    key = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as tmp:
        tmp = Path(tmp)
        cert, tls_key, jwt_public = (tmp / name for name in ("cert.pem", "tls.key", "jwt.pem"))
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                        "-keyout", str(tls_key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-addext", "basicConstraints=critical,CA:TRUE"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwt_public.write_bytes(signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        env = dict(os.environ, E2E_CERT=str(cert), E2E_TLS_KEY=str(tls_key),
            E2E_JWT_PUBLIC=str(jwt_public), SSL_CERT_FILE=str(cert), NODE_EXTRA_CA_CERTS=str(cert),
            MONGODB_URL=MONGO, API_KEY=secrets.token_hex(32), ZITADEL_ISSUER=ISSUER,
            ZITADEL_PROJECT_ID=MCP_PROJECT, ZITADEL_INTROSPECTION_CLIENT_ID="fixture",
            ZITADEL_INTROSPECTION_CLIENT_SECRET="fixture",
            ZITADEL_PRIVATE_RESOURCE_ALLOWED_CLIENT_IDS=CLIENT,
            SERVICEOPS_DB_PATH=str(tmp / "serviceops.sqlite"), SERVICEOPS_OIDC_ISSUER=ISSUER,
            SERVICEOPS_OIDC_AUDIENCE=PROJECT, SERVICEOPS_OIDC_CLIENT_ID=CLIENT,
            SERVICEOPS_QDIP_GATEWAY_URL=CORE_URL, SERVICEOPS_QDIP_CALLER_KEY=key,
            SERVICEOPS_MCP_CHATGPT_CLIENT_ID=AGENT,
            MCP_RESOURCE_URL="https://mcp.example.invalid/mcp", MCP_OAUTH_PROFILE="zitadel_project_roles",
            MCP_ZITADEL_PROJECT_ID=MCP_PROJECT, MCP_ZITADEL_ORGANIZATION_ID=EXTERNAL_ORG,
            MCP_ALLOWED_CLIENT_IDS=AGENT, QDIP_GATEWAY_URL=CORE_URL, QDIP_API_KEY=key,
            MCP_SERVICEOPS_ORIGIN=SO_URL)
        # Unique synthetic database name; refuse to overwrite any existing records.
        mongo = MongoClient(MONGO, serverSelectionTimeoutMS=5000)
        db = mongo.get_default_database()
        assert not db.list_collection_names()
        db["organizations"].insert_one({"id": ORG, "status": "active",
            "identity_provider": "zitadel", "zitadel_issuer": ISSUER,
            "zitadel_organization_id": EXTERNAL_ORG})
        db["org_api_keys"].insert_one({"id": "fixture-scoped", "org_id": ORG,
            "key_hash": hashlib.sha256(key.encode()).hexdigest(), "revoked_at": None,
            "scopes": ["plugins:read", "plugins:execute"], "plugin_id": PLUGIN,
            "allowed_capabilities": [CAPABILITY]})
        db["sdk_application_owners"].insert_one({"organization_id": ORG, "plugin_id": PLUGIN,
            "zitadel_issuer": ISSUER, "zitadel_organization_id": EXTERNAL_ORG,
            "zitadel_application_id": APP, "zitadel_project_id": PROJECT,
            "owner_subject": OWNER, "oidc_client_id": CLIENT, "status": "active"})
        grants = db["sdk_application_delegations"]
        grant = grants.insert_one({"organization_id": ORG, "plugin_id": PLUGIN,
            "agent_client_id": AGENT, "issuer": ISSUER, "owner_subject": OWNER,
            "application_id": APP, "owner_client_id": CLIENT, "status": "active",
            "expires_at": (datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
            "capabilities": [{"capability_id": CAPABILITY, "capability_version": "1"}]}).inserted_id
        core = ServiceOpsCore(env["SERVICEOPS_DB_PATH"])
        try:
            for name, count in (("a", 1), ("b", 2)):
                company = f"tenant-{name}"
                owner = core.bootstrap(company, f"owner-{name}")
                link_identity(core, issuer=ISSUER, subject=SUBJECTS[name],
                              organization_id=company, membership_id=f"owner-{name}")
                core.create_customer(owner, f"client-{name}", "Synthetic customer")
                version = core.publish_workflow(owner, f"workflow-{name}", 1, {
                    "name": "Synthetic workflow", "customer_acceptance": False,
                    "stages": [{"id": "stage", "name": "Stage"}],
                    "tasks": [{"id": "task", "stage_id": "stage", "name": "Task", "skills": []}]})
                for n in range(count):
                    core.create_order(owner, f"client-{name}", version, "Synthetic order", key=f"order-{n}")
            plans.start_trial(core, "tenant-b", "fixture")
        finally:
            core.close()

        def token(subject, admin=False):
            now = int(time.time())
            claims = {"iss": ISSUER, "sub": subject, "aud": PROJECT, "iat": now, "exp": now+600}
            if admin:
                claims[f"urn:zitadel:iam:org:project:{PROJECT}:roles"] = {"serviceops_admin": {EXTERNAL_ORG: "fixture"}}
            return jwt.encode(claims, signer, algorithm="RS256")

        def headers(name):
            return {"Authorization": "Bearer "+token(SUBJECTS[name]), "X-Organization-ID": f"tenant-{name}"}

        def expire(column, company):
            assert column in ("trial_ends_at", "paid_ends_at")
            store = ServiceOpsCore(env["SERVICEOPS_DB_PATH"])
            try:
                store.db.execute(f"UPDATE organization_plans SET {column}=? WHERE organization_id=?",
                                 (int(time.time()), company))
            finally:
                store.close()

        processes = []
        try:
            for mode, source in (("core", core_path), ("so", so_path)):
                p = subprocess.Popen([sys.executable, str(script), mode], cwd=source,
                    env=dict(env, PYTHONPATH=str(source)), stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                processes.append(p)
                wait_http(p, CORE_URL if mode == "core" else SO_URL, str(cert))
            with httpx.Client(verify=str(cert), timeout=15, trust_env=False) as http:
                def activate(name, enabled):
                    response = http.put(SO_URL+"/api/v1/mcp/customer-connection", headers=headers(name),
                                        json={"enabled": enabled})
                    assert response.status_code == 200 and response.json() == {"enabled": enabled}

                def pay():
                    response = http.post(SO_URL+"/api/v1/admin/organizations/tenant-a/plan",
                        headers={"Authorization": "Bearer "+token("9999", admin=True)},
                        json={"action": "paid", "plan": "start", "agreement_reference": "synthetic",
                              "paid_ends_on": (datetime.now(plans.TZ).date()+timedelta(days=30)).isoformat()})
                    assert response.status_code == 200 and response.json()["state"] == "paid"

                def check(name, allowed, count=0, audience="both"):
                    subprocess.run(["node", "test/e2e-serviceops-customer.mjs", name,
                        str(int(allowed)), str(count), audience], cwd=mcp_path, env=env, check=True)

                pay()
                check("a", False)
                activate("a", True)
                activate("b", True)
                check("a", True, 1)
                check("b", True, 2)
                check("a", False, audience="missing")
                activate("a", False)
                check("a", False)
                activate("a", True)
                expire("paid_ends_at", "tenant-a")
                check("a", False)
                pay()
                check("a", True, 1)
                grants.update_one({"_id": grant}, {"$set": {"status": "revoked"}})
                check("a", False, audience="grant-denied")
                grants.update_one({"_id": grant}, {"$set": {"status": "active"}})
                expire("trial_ends_at", "tenant-b")
                check("b", False)
                check("a", True, 1)
                print("SERVICEOPS_MCP_CUSTOMER_E2E=PASS")
        finally:
            for p in reversed(processes):
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
            mongo.drop_database(db.name)
            mongo.close()


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "core":
        run_core()
    elif len(sys.argv) == 2 and sys.argv[1] == "so":
        run_so()
    else:
        scenario(*(Path(x).resolve() for x in sys.argv[1:]))

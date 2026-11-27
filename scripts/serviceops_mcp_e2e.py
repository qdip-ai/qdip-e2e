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
APP, OWNER, CLIENT, AGENT, CLAUDE = "301", "9000", "8000", "123456", "123457"
SUBJECTS = {"a": "9001", "b": "9002"}
PLUGIN = "qdip-serviceops"
CAPABILITY = "serviceops.assignment.propose"
ORG = "aaaa0000-aaaa-4000-8000-aaaaaaaaaaaa"
CORE_URL, SO_URL = "https://127.0.0.1:18443", "https://127.0.0.1:18444"
MCP_METADATA = "/.well-known/oauth-protected-resource/mcp"
METADATA_ORIGIN = "http://127.0.0.1:18445"
MCP_RESOURCE = "https://mcp.qdip.ai/mcp"
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
        subject, agent = next(((value, client) for name, value in SUBJECTS.items()
                               for suffix, client in (("", AGENT), ("-claude", CLAUDE))
                               if token == f"fixture-customer-{name}{suffix}-token"), (None, None))
        now = int(time.time())
        return httpx.Response(200, json={"active": bool(subject), "sub": subject,
            "iss": ISSUER, "aud": [PROJECT, MCP_PROJECT], "client_id": agent,
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
    import httpx
    import uvicorn
    from cryptography.hazmat.primitives import serialization
    from types import SimpleNamespace
    from serviceops_api import auth
    from serviceops_api.app import app, http_client

    public = serialization.load_pem_public_key(Path(os.environ["E2E_JWT_PUBLIC"]).read_bytes())
    # Provider JWKS is the only substituted dependency; actual JWT signature,
    # audience, issuer, membership and plan enforcement remain unchanged.
    auth._keys = lambda issuer: SimpleNamespace(
        get_signing_key_from_jwt=lambda token: SimpleNamespace(key=public))
    # Redirect only the fixed public metadata URL to the real isolated MCP
    # handler. This is test DNS routing, not a mocked metadata response.
    def route_metadata(request):
        if request.url.host == "mcp.qdip.ai":
            assert str(request.url) == "https://mcp.qdip.ai" + MCP_METADATA
            assert request.method == "GET"
            assert "Authorization" not in request.headers and "X-API-Key" not in request.headers
            request.url = httpx.URL(METADATA_ORIGIN + MCP_METADATA)
            request.headers["Host"] = "127.0.0.1:18445"

    def isolated_http():
        with httpx.Client(verify=os.environ["E2E_CERT"], trust_env=False,
                          event_hooks={"request": [route_metadata]},
                          timeout=10, follow_redirects=False) as client:
            yield client

    app.dependency_overrides[http_client] = isolated_http
    uvicorn.run(app, host="127.0.0.1", port=18444, lifespan="off",
                ssl_certfile=os.environ["E2E_CERT"], ssl_keyfile=os.environ["E2E_TLS_KEY"],
                access_log=False)


def wait_http(process, url, cert, health_path):
    import httpx
    with httpx.Client(verify=cert, timeout=1, trust_env=False) as client:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("service terminated")
            try:
                if client.get(url + health_path).status_code == 200:
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
            SERVICEOPS_MCP_CHATGPT_CLIENT_ID=AGENT, SERVICEOPS_MCP_CLAUDE_CLIENT_ID=CLAUDE,
            SERVICEOPS_MCP_CORE_AUDIENCE=PROJECT,
            MCP_RESOURCE_URL=MCP_RESOURCE, MCP_OAUTH_PROFILE="zitadel_project_roles",
            MCP_ZITADEL_PROJECT_ID=MCP_PROJECT, MCP_ZITADEL_ORGANIZATION_ID=EXTERNAL_ORG,
            MCP_ALLOWED_CLIENT_IDS=AGENT+","+CLAUDE, QDIP_GATEWAY_URL=CORE_URL, QDIP_API_KEY=key,
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
        second = grants.find_one({"_id": grant})
        second.pop("_id")
        second["agent_client_id"] = CLAUDE
        grants.insert_one(second)
        print("SO_MCP_PHASE=MONGO_SEEDED", flush=True)
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

        print("SO_MCP_PHASE=SQLITE_SEEDED", flush=True)

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
                wait_http(p, CORE_URL if mode == "core" else SO_URL, str(cert),
                          "/health" if mode == "core" else "/readyz")
                print(f"SO_MCP_PHASE={mode.upper()}_READY", flush=True)
            metadata_process = subprocess.Popen(
                ["node", "test/e2e-serviceops-customer.mjs", "metadata"],
                cwd=mcp_path, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(metadata_process)
            wait_http(metadata_process, METADATA_ORIGIN, str(cert), "/healthz")
            print("SO_MCP_PHASE=SETUP_METADATA_READY", flush=True)
            with httpx.Client(verify=str(cert), timeout=15, trust_env=False) as http:
                setup_url = SO_URL + "/api/v1/mcp/customer-setup"

                def check_setup(name):
                    metadata = http.get(METADATA_ORIGIN + MCP_METADATA)
                    assert metadata.status_code == 200
                    public = metadata.json()
                    assert public["resource"] == MCP_RESOURCE
                    assert public["authorization_servers"] == [ISSUER]
                    assert f"urn:zitadel:iam:org:project:id:{PROJECT}:aud" in public["scopes_supported"]
                    assert f"urn:zitadel:iam:org:project:id:{MCP_PROJECT}:aud" in public["scopes_supported"]
                    response = http.get(setup_url, headers=headers(name))
                    assert response.status_code == 200
                    assert response.headers["Cache-Control"] == "no-store"
                    assert response.json() == {
                        "server_url": MCP_RESOURCE,
                        "client_ids": {"chatgpt": AGENT, "claude": CLAUDE},
                        "scopes": public["scopes_supported"],
                    }

                assert http.get(setup_url, headers=headers("a")).status_code == 403
                foreign = {**headers("a"), "X-Organization-ID": "tenant-b"}
                assert http.get(setup_url, headers=foreign).status_code == 403
                check_setup("b")
                print("SO_MCP_PHASE=SETUP_PUBLIC_PARAMETERS", flush=True)
                def activate(name, enabled):
                    print("SO_MCP_PHASE=ACTIVATION", flush=True)
                    response = http.put(SO_URL+"/api/v1/mcp/customer-connection", headers=headers(name),
                                        json={"enabled": enabled})
                    assert response.status_code == 200 and response.json() == {"enabled": enabled}

                def pay():
                    print("SO_MCP_PHASE=PAID_PLAN", flush=True)
                    response = http.post(SO_URL+"/api/v1/admin/organizations/tenant-a/plan",
                        headers={"Authorization": "Bearer "+token("9999", admin=True)},
                        json={"action": "paid", "plan": "start", "agreement_reference": "synthetic",
                              "paid_ends_on": (datetime.now(plans.TZ).date()+timedelta(days=30)).isoformat()})
                    assert response.status_code == 200 and response.json()["state"] == "paid"

                def check(name, allowed, count=0, audience="both", provider="chatgpt"):
                    print("SO_MCP_PHASE=PROTOCOL_" + ("ALLOW" if allowed else "DENY"), flush=True)
                    subprocess.run(["node", "test/e2e-serviceops-customer.mjs", name,
                        str(int(allowed)), str(count), audience, provider], cwd=mcp_path, env=env, check=True)

                def status_for(name, chatgpt, claude):
                    response = http.get(SO_URL+"/api/v1/mcp/customer-status", headers=headers(name))
                    assert response.status_code == 200
                    clients = response.json()["clients"]
                    for provider, expected in (("chatgpt", chatgpt), ("claude", claude)):
                        proof = clients[provider]
                        assert proof["state"] == expected
                        if expected == "verified":
                            assert int(time.time()) < proof["verified_until"] <= int(time.time()) + 300
                        else:
                            assert proof["verified_until"] is None

                pay()
                check_setup("a")  # Read-only guide is allowed before activation.
                status_for("a", "blocked", "blocked")
                check("a", False)
                activate("a", True)
                activate("b", True)
                status_for("a", "unverified", "unverified")
                status_for("b", "unverified", "unverified")
                check("a", True, 1)
                status_for("a", "verified", "unverified")
                status_for("b", "unverified", "unverified")
                check("a", True, 1, provider="claude")
                status_for("a", "verified", "verified")
                check("b", True, 2)
                status_for("b", "verified", "unverified")
                foreign_headers = {**headers("a"), "X-Organization-ID": "tenant-b"}
                assert http.get(SO_URL+"/api/v1/mcp/customer-status", headers=foreign_headers).status_code == 403
                check("a", False, audience="missing")
                activate("a", False)
                status_for("a", "blocked", "blocked")
                check("a", False)
                activate("a", True)
                status_for("a", "unverified", "unverified")
                expire("paid_ends_at", "tenant-a")
                status_for("a", "blocked", "blocked")
                check("a", False)
                pay()
                status_for("a", "unverified", "unverified")
                check("a", True, 1)
                check("a", True, 1, provider="claude")
                status_for("a", "verified", "verified")
                grants.update_one({"_id": grant}, {"$set": {"status": "revoked"}})
                status_for("a", "blocked", "verified")
                check("a", False, audience="grant-denied")
                grants.update_one({"_id": grant}, {"$set": {"status": "active"}})
                status_for("a", "unverified", "verified")
                expire("trial_ends_at", "tenant-b")
                status_for("b", "blocked", "blocked")
                check("b", False)
                check("a", True, 1)
                status_for("a", "verified", "verified")
                assert http.get(setup_url, headers=headers("b")).status_code == 403
                metadata_process.terminate()
                metadata_process.wait(timeout=10)
                processes.remove(metadata_process)
                response = http.get(setup_url, headers=headers("a"))
                assert response.status_code == 503
                assert response.json()["detail"] == "MCP_SETUP_METADATA_UNAVAILABLE"
                print("SERVICEOPS_MCP_SETUP_E2E=PASS")
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
        try:
            scenario(*(Path(x).resolve() for x in sys.argv[1:]))
        except Exception as exc:
            kind = type(exc).__name__
            if kind not in {"AssertionError", "RuntimeError", "CalledProcessError", "ImportError", "ModuleNotFoundError", "ValueError", "TypeError", "KeyError", "OperationalError", "CoreError", "ConnectError"}:
                kind = "OTHER"
            print("SO_MCP_ERROR_CLASS=" + kind, flush=True)
            raise

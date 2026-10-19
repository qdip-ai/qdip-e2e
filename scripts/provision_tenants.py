"""Create two real org API keys in a disposable replica and mask credentials."""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from pymongo import MongoClient

mongo = os.environ["MONGODB_URL"]
assert "127.0.0.1:27019/qdip_e2e?" in mongo, "Refuse non-disposable Mongo"
assert os.environ.get("GITHUB_ACTIONS") == "true", "Only GitHub Actions runner"
client = MongoClient(mongo, serverSelectionTimeoutMS=5000)
db = client.get_default_database()
assert db.name == "qdip_e2e"
assert db["org_api_keys"].count_documents({}) == 0

names = {
    "E2E_KEY_A": ("rr-e2e-org-a", "rr-e2e-key-a"),
    "E2E_KEY_B": ("rr-e2e-org-b", "rr-e2e-key-b"),
    "E2E_WORKER_KEY": ("rr-e2e-org-a", "rr-e2e-worker-a"),
}
values: dict[str, str] = {}
for env_name, (org, kid) in names.items():
    secret = secrets.token_urlsafe(48)
    scopes = (
        ["plugins:register"] if env_name == "E2E_WORKER_KEY"
        else ["decisions:execute", "decisions:read", "audit:read",
              "plugins:execute", "plugins:read"]
    )
    db["org_api_keys"].insert_one({
        "key_hash": hashlib.sha256(secret.encode()).hexdigest(),
        "revoked_at": None,
        "org_id": org,
        "id": kid,
        "scopes": scopes,
    })
    values[env_name] = secret

values["API_KEY"] = secrets.token_urlsafe(48)
# The Observatory's SDK catalog reader uses platform ADMIN. An org-scoped
# RR execution key cannot list /plugin-publications (403 by design).
# Reuse this disposable runner's platform key server-side only; never export
# it to browser cookies, trace artifacts, or client-facing variables.
values["DIP_ADMIN_API_KEY"] = values["API_KEY"]
values["RR_OPERATOR_PASSWORD"] = secrets.token_urlsafe(48)
values["RR_OPERATOR_SESSION_SECRET"] = secrets.token_urlsafe(64)
# Isolated Core/Web actor-attribution trust secret. Never use in production.
values["RR_ACTOR_ASSERTION_SECRET"] = secrets.token_urlsafe(64)
# Isolated cryptographic BFF-session test. This issuer is deliberately NOT real
# Zitadel; no external IdP or production identity may be used here.
values["QDIP_AUTH_COOKIE_SECRET"] = secrets.token_urlsafe(64)
values["ZITADEL_ISSUER"] = "https://qdip-e2e.invalid"
values["ZITADEL_CLIENT_ID"] = "qdip-e2e-client"
# Current qdip-web signed-session schema requires numeric project + org IDs
# and project-scoped roles. These are invented identifiers on a disposable runner.
values["ZITADEL_QDIP_PROJECT_ID"] = "123456789"
values["ZITADEL_QDIP_ORGANIZATION_ID"] = "987654321"
values["QDIP_STUDIO_ZITADEL_ROLE_KEY"] = "studio"
values["QDIP_RR_ZITADEL_ROLE_KEY"] = "rr_operator"
# These are mock subjects only: real Zitadel login/claim issuance is not tested.
values["RR_E2E_OPERATOR_SUBJECT"] = "qdip-e2e-operator"
values["RR_E2E_STUDIO_SUBJECT"] = "qdip-e2e-studio-only"
# The staged Observatory operator is a separate app, but must use a valid
# org-scoped key. Never pass the platform-level API_KEY to the browser proxy.
values["DIP_API_KEY"] = values["E2E_KEY_A"]
values["RR_E2E_OPERATOR_PASSWORD"] = values["RR_OPERATOR_PASSWORD"]
for value in set(values.values()):
    print(f"::add-mask::{value}")
with Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as out:
    for name, value in values.items():
        assert "\n" not in value and "\r" not in value
        out.write(f"{name}={value}\n")
print("RR_E2E_TWO_DISPOSABLE_TENANTS=PROVISIONED")
client.close()

"""Admit only the pinned, test-owned staffing Worker in disposable native E2E.

Not a production authorization workflow: the manifest is allowlisted solely
in a fresh localhost API process, then approved via the real admin endpoint.
"""
from __future__ import annotations

import argparse
import os
import re
import time

import httpx
from pymongo import MongoClient

from app.plugins.registration_catalog import registration_digest


ROOT = "http://127.0.0.1:8000/api/v1/plugin-publications"
REVIEW = "QDIP-E2E-LOCAL-STAFFING-REVIEW"


def registration() -> tuple[str, int, str, str]:
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert "127.0.0.1:27019/qdip_e2e?" in os.environ["MONGODB_URL"]
    # Wait for the actual SDK Worker WebSocket REGISTER, not a synthetic record.
    with MongoClient(os.environ["MONGODB_URL"], serverSelectionTimeoutMS=5000) as mongo:
        db = mongo.get_default_database()
        for _ in range(50):
            row = db["plugin_publications"].find_one({
                "registration.kind": "remote",
                "registration.tenant_id": "rr-e2e-org-a",
                "registration.plugin_id": "staffing",
                "registration.worker_key_id": "rr-e2e-worker-a",
            })
            if row:
                reg = row["registration"]
                assert reg["capabilities"] == {"staffing.plan": "1"}
                assert reg["version"] == "0.1.0"
                assert reg["manifest_version"] == "1.0.0"
                assert reg["capability_contracts"]["staffing.plan"]["required_scopes"] == []
                assert db["org_api_keys"].count_documents({
                    "id": "rr-e2e-worker-a", "org_id": "rr-e2e-org-a",
                    "plugin_id": "staffing", "scopes": ["plugins:register"],
                    "allowed_capabilities": ["staffing.plan"], "revoked_at": None,
                }) == 1
                digest = registration_digest(reg)
                assert re.fullmatch(r"[a-f0-9]{64}", digest)
                return str(row["_id"]), int(row["revision"]), reg["version"], digest
            time.sleep(0.3)
    raise AssertionError("No registered, exact scoped staffing Worker on disposable Gateway")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["digest", "approve"])
    action = parser.parse_args().action
    name, revision, version, digest = registration()
    if action == "digest":
        # Only stdout: bash command substitution safely passes digest to the
        # isolated API process. Do not print keys, Mongo records or secrets.
        print(digest)
        return
    assert os.environ.get("QDIP_TRUSTED_REMOTE_MANIFESTS") == digest
    assert os.environ["API_KEY"]
    with httpx.Client(timeout=25, trust_env=False) as http:
        res = http.post(
            f"{ROOT}/{name}/security/approve",
            headers={
                "x-api-key": os.environ["API_KEY"],
                "x-qdip-actor": "e2e-local-reviewer",
            },
            json={
                "expected_revision": revision,
                "plugin_version": version,
                "reason": "Reviewed pinned test-only staffing Worker in isolated localhost Mongo runner.",
                "review_reference": REVIEW,
                "risk_acknowledged": True,
            },
        )
        assert res.status_code == 200, f"Disposable Worker manual admission HTTP {res.status_code}"
        security = res.json()["security"]
        assert security["state"] == "approved"
        assert security["approved_manifest_sha256"] == digest
        assert security["approval_source"] == "trusted_first_party_manual"
        assert security["review_reference"] == REVIEW
    print("SDK02_DISPOSABLE_MANUAL_ADMISSION=PASS")


if __name__ == "__main__":
    main()

"""Disposable private-network Gateway for ServiceOps Worker E2E (qdip-core fixture + frozen Kernel v1).

Run inside a qdip-core checkout image (cwd = repo root). Never expose publicly: Railway service without a
public domain, deleted after the run. Keys are random per run, passed via env, no production authority.
Env: PORT, E2E_WORKER_KEY, E2E_CALLER_KEY, optional E2E_HOST (default "::" for Railway private networking).
"""
import os
import sys

sys.path.insert(0, os.getcwd())  # run from the qdip-core checkout root

import uvicorn  # noqa: E402
from tests.remote_plugins import fixture_server as f  # noqa: E402

PLUGIN, CAPABILITY = "qdip-serviceops", "serviceops.assignment.propose"
f.KEYS[os.environ["E2E_WORKER_KEY"]] = (PLUGIN, CAPABILITY, "worker")
f.KEYS[os.environ["E2E_CALLER_KEY"]] = (PLUGIN, CAPABILITY, "caller")
uvicorn.run(f.app, host=os.environ.get("E2E_HOST", "::"), port=int(os.environ.get("PORT", "8080")), log_level="warning")

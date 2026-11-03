"""Independent HTTP negative probe for RR actor assertion transfer.

Only for an isolated RR acceptance server on loopback. The short-lived HMAC
principal is synthetic; this is not a substitute for real Zitadel browser E2E.
Credentials enter through environment variables and are never printed.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit

import httpx


async def run(base_url: str, requests_file: str) -> None:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path:
        raise RuntimeError("RR actor probe requires an isolated loopback acceptance server")
    key = os.environ["RR_E2E_API_KEY"]
    secret = os.environ["RR_E2E_ACTOR_SECRET"]
    actor = "zitadel:" + hashlib.sha256(b"https://synthetic.invalid\0rr-actor-probe").hexdigest()
    prefix = f"v2.{int(time.time()) + 30}.{actor}.execute"
    signature = hmac.new(secret.encode(), prefix.encode() + b"\0" + key.encode(), hashlib.sha256).hexdigest()
    assertion = prefix + "." + signature
    bodies = json.loads(Path(requests_file).read_text())
    async with httpx.AsyncClient(base_url=base_url, trust_env=False, timeout=40) as client:
        first = await client.post(
            "/api/v1/readiness-recovery/executions", json=bodies[0],
            headers={"x-api-key": key, "idempotency-key": "actor-original", "x-qdip-actor-assertion": assertion},
        )
        assert first.status_code == 201, f"initial authorized fixture failed: HTTP {first.status_code}"
        second = await client.post(
            "/api/v1/readiness-recovery/executions", json=bodies[1],
            headers={"x-api-key": key, "idempotency-key": "actor-transferred", "x-qdip-actor-assertion": assertion},
        )
        print(f"RR_ACTOR_CONTEXT_PROBE:initial_status={first.status_code} transferred_status={second.status_code}", flush=True)
        assert second.status_code == 403, "A previously issued actor assertion authorized a different HTTP request"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--requests-file", required=True)
    args = parser.parse_args()
    asyncio.run(run(args.base_url, args.requests_file))

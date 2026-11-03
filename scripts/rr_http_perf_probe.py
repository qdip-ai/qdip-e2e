"""Independent measured RR HTTP baseline; synthetic fixture, no SLA assertion."""
import argparse
import asyncio
import base64
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import statistics
import time
from uuid import uuid4

import httpx


async def run(base_url, fixture_file):
    key = os.environ["RR_E2E_API_KEY"]
    secret = os.environ["RR_E2E_ACTOR_SECRET"]
    organization = os.environ["RR_E2E_ORGANIZATION_ID"]
    template = json.loads(Path(fixture_file).read_text())[0]
    measurements = {name: [] for name in ("create", "replan", "get", "replay")}
    sizes, runtimes, statuses = [], [], []
    gate = asyncio.Semaphore(2)

    def headers(body, path, operation):
        raw = httpx.Request("POST", "http://fixture.invalid", json=body).content
        claims = {"actor_id": "zitadel:" + "a"*64, "assertion_id": uuid4().hex,
                  "expires_at": int(time.time())+30, "organization_id": organization,
                  "operation": operation, "method": "POST", "path": path,
                  "body_sha256": hashlib.sha256(raw).hexdigest(),
                  "idempotency_key": "perf-" + uuid4().hex}
        encoded = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
        prefix = "v3." + encoded
        mac = hmac.new(secret.encode(), prefix.encode()+b"\0"+key.encode(), hashlib.sha256).hexdigest()
        sizes.append(len(raw))
        return {"x-api-key": key, "idempotency-key": claims["idempotency_key"],
                "x-qdip-actor-assertion": prefix + "." + mac}

    async with httpx.AsyncClient(base_url=base_url, timeout=40, trust_env=False) as client:
        async def measured(name, method, path, **kwargs):
            started = time.perf_counter()
            response = await client.request(method, path, **kwargs)
            measurements[name].append((time.perf_counter()-started)*1000)
            statuses.append(response.status_code)
            assert response.status_code == (201 if method == "POST" else 200), name + " HTTP " + str(response.status_code)
            return response.json()

        async def operator():
            async with gate:
                body = deepcopy(template)
                suffix = uuid4().hex
                body["execution_id"] = "perf-create-" + suffix
                body["payload"]["decision_id"] = "perf-decision-" + suffix
                now = datetime.now(UTC)
                body["source"]["snapshot_id"] = "perf-source-" + suffix
                body["source"]["captured_at"] = (now-timedelta(seconds=30)).isoformat()
                body["ingested_at"] = (now-timedelta(seconds=20)).isoformat()
                path = "/api/v1/readiness-recovery/executions"
                first = await measured("create", "POST", path, json=body, headers=headers(body, path, "execute"))
                runtimes.append(float(first["result"]["runtime"]["execution_result"]["diagnostics"]["runtime_ms"]))
                read = path + "/" + body["execution_id"]
                assert await measured("get", "GET", read, headers={"x-api-key": key}) == first
                await measured("replay", "GET", read + "/replay-verification", headers={"x-api-key": key})
                replan = deepcopy(body)
                replan["execution_id"] = "perf-replan-" + suffix
                replan["payload"]["operator_directives"] = {
                    "required_job_ids": [], "excluded_job_ids": [body["payload"]["jobs"][0]["id"]]}
                replan.update(change_id="perf-change-" + suffix, kind="OVERRIDE",
                              reason="Synthetic qualification workload",
                              requested_at=(now-timedelta(seconds=5)).isoformat())
                replan["source"]["captured_at"] = (now-timedelta(seconds=10)).isoformat()
                replan["ingested_at"] = (now-timedelta(seconds=3)).isoformat()
                route = read + "/replan"
                second = await measured("replan", "POST", route, json=replan, headers=headers(replan, route, "replan"))
                runtimes.append(float(second["result"]["runtime"]["execution_result"]["diagnostics"]["runtime_ms"]))
        await asyncio.gather(*(operator() for _ in range(10)))

    def summary(values):
        return {"n": len(values), "p50": round(statistics.median(values), 3),
                "p95": round(sorted(values)[math.ceil(.95*len(values))-1], 3),
                "max": round(max(values), 3)}
    print("RR_HTTP_PERFORMANCE=" + json.dumps({
        "scope": "synthetic fixture baseline; not commercial SLA qualification",
        "concurrent_operators": 2, "operator_sequences": 10,
        "fixture_jobs": len(template["payload"]["jobs"]),
        "fixture_horizon_slots": template["payload"]["horizon_slots"],
        "http_ms": {name: summary(values) for name, values in measurements.items()},
        "post_bytes": summary(sizes), "kernel_runtime_ms": summary(runtimes),
        "errors": sum(status >= 400 for status in statuses),
        "worker_compile_duration": "NOT_EXPOSED_SEPARATELY",
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--requests-file", required=True)
    args = parser.parse_args()
    asyncio.run(run(args.base_url, args.requests_file))

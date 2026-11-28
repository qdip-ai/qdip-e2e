"""ServiceOps Worker -> qdip-core Gateway -> frozen Kernel v1 E2E for KERNEL-00 and the Profit Optimizer.

Runs inside the ServiceOps Worker image (cwd /worker, real `serviceops_worker` + pinned SDK). Starts the
real Worker entrypoint (its actual manifest and input schema), invokes the capability through the Gateway
HTTP API and checks every Kernel answer against an oracle written here, independent of ServiceOps code.
Proves: manifest admission, Gateway input-schema admission of both request shapes, DecisionSpec
compilation, Kernel optimum and status. Does NOT prove production auth, sealing or tenant isolation.
Env: E2E_GATEWAY (http://host:port), E2E_WORKER_KEY, E2E_CALLER_KEY. Last line: SERVICEOPS_E2E_RESULT PASS|FAIL.
"""
from __future__ import annotations

import itertools
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request

GATEWAY = os.environ["E2E_GATEWAY"].rstrip("/")
BASE = f"{GATEWAY}/api/v1/remote-plugins"
CAPABILITY = "serviceops.assignment.propose"
CALLER = os.environ["E2E_CALLER_KEY"]


def http(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"x-api-key": CALLER, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


def option(oid, order, start, end, revenue, resources=("s1",), cost=0, deadline=600):
    return {"id": oid, "order": order, "start": start, "end": end, "deadline": deadline,
            "resources": list(resources), "revenue_grosz": revenue, "cost_grosz": cost}


def oracle(request):
    """Best margin over all valid selections, from the raw business rules only."""
    opts, committed, best = request["options"], set(request.get("committed", [])), None
    for size in range(len(opts) + 1):
        for chosen in itertools.combinations(opts, size):
            orders = [o["order"] for o in chosen]
            if len(set(orders)) != len(orders) or not committed <= set(orders):
                continue
            if any(o["end"] > o["deadline"] for o in chosen):
                continue
            if any(set(a["resources"]) & set(b["resources"]) and a["start"] < b["end"] and b["start"] < a["end"]
                   for a, b in itertools.combinations(chosen, 2)):
                continue
            margin = sum(o["revenue_grosz"] - o["cost_grosz"] for o in chosen)
            best = margin if best is None or margin > best else best
    return best


def selected_margin(request, result):
    by_id = {o["id"]: o for o in request["options"]}
    chosen = [by_id[k] for k, v in (result.get("solution") or {}).items() if k in by_id and float(v) > 0.5]
    return sum(o["revenue_grosz"] - o["cost_grosz"] for o in chosen), sorted(o["id"] for o in chosen)


def main() -> int:
    worker = subprocess.Popen([sys.executable, "-m", "serviceops_worker"], env={
        **os.environ, "QDIP_REMOTE_URL": GATEWAY.replace("http", "ws", 1) + "/api/v1/remote-plugins/connect",
        "QDIP_REMOTE_API_KEY": os.environ["E2E_WORKER_KEY"]})
    failures, cases = 0, []
    try:
        for _ in range(300):
            try:
                status, caps = http("GET", f"{BASE}/capabilities")
            except OSError:
                status, caps = 0, None
            if status == 200 and CAPABILITY in json.dumps(caps):
                break
            time.sleep(0.5)
        else:
            print(json.dumps({"case": "registration", "pass": False}))
            return 1
        assignment = {"tasks": [{"id": "t0", "skills": ["diag"], "day": "2026-12-07"}],
                      "workers": [{"id": "w0", "skills": ["diag"], "available_days": ["2026-12-07"], "current_load": 0}]}
        cases.append(("kernel00_assignment_still_admitted", assignment, "OPTIMAL", None))
        cases.append(("roadmap_180_420_90", {"model": "profit_options_v1", "options": [
            option("o1", "r1", 0, 120, 18000), option("o2", "r2", 0, 120, 42000), option("o3", "r3", 0, 120, 9000)]},
            "OPTIMAL", ["o2"]))
        cases.append(("committed_loss_kept", {"model": "profit_options_v1", "committed": ["r1"], "options": [
            option("o1", "r1", 0, 30, 100, cost=300), option("o2", "r2", 30, 60, 100, cost=150),
            option("o3", "r3", 30, 60, 400, cost=100)]}, "OPTIMAL", ["o1", "o3"]))
        cases.append(("incompatible_commitments_infeasible", {"model": "profit_options_v1", "committed": ["r1", "r2"],
            "options": [option("o1", "r1", 0, 60, 100), option("o2", "r2", 30, 90, 100)]}, "INFEASIBLE", None))
        rng = random.Random(int(os.environ.get("E2E_SEED", "271")))
        for n in range(20):
            opts = []
            for i in range(rng.randint(2, 7)):
                start = rng.randrange(0, 100, 10)
                opts.append(option(f"o{i}", f"r{rng.randint(0, 3)}", start, start + rng.choice((10, 20, 30)),
                                   rng.randint(0, 500), rng.sample(["s1", "s2", "s3"], rng.randint(1, 2)), rng.randint(0, 400)))
            orders = sorted({o["order"] for o in opts})
            request = {"model": "profit_options_v1", "options": opts}
            committed = [o for o in orders if rng.random() < 0.25]
            if committed:
                request["committed"] = committed
            cases.append((f"random_{n}", request, None, None))
        for name, request, expected_status, expected_ids in cases:
            status, body = http("POST", f"{BASE}/{CAPABILITY}/invoke", {"input": request})
            result = (body or {}).get("execution_result") or {}
            backend = result.get("backend_status")
            ok = status == 200
            detail = {}
            if "model" in request:
                best = oracle(request)
                if best is None:
                    ok = ok and backend == "INFEASIBLE"
                else:
                    margin, ids = selected_margin(request, result)
                    ok = ok and backend == "OPTIMAL" and result.get("semantic_status") == "EXACT" and margin == best
                    ok = ok and (expected_ids is None or ids == expected_ids)
                    detail = {"margin": margin, "oracle": best, "selected": ids}
            else:
                ok = ok and backend == expected_status
            ok = ok and (expected_status is None or backend == expected_status)
            failures += not ok
            print(json.dumps({"case": name, "http": status, "status": [result.get("semantic_status"), backend],
                              **detail, "pass": ok}), flush=True)
        return 1 if failures else 0
    finally:
        worker.terminate()
        worker.wait(timeout=10)


if __name__ == "__main__":
    code = main()
    print("SERVICEOPS_E2E_RESULT", "PASS" if code == 0 else "FAIL", flush=True)
    raise SystemExit(code)

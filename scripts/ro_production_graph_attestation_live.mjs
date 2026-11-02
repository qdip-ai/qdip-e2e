/** Live, synthetic-only production RO relay -> @qdip/client -> private SDK
 * ingress -> Worker -> authenticated OSRM graph E2E. No customer data,
 * credentials, accounts, admin actions, or persistent changes.
 */
const url = process.env.QDIP_RO_RELAY_URL ||
  "https://ro-cat-sdk-client-production.up.railway.app/api/ro/compare";
const origin = process.env.QDIP_RO_RELAY_ORIGIN || "https://cats.qdip.ai";
if (!url.startsWith("https://") || !origin.startsWith("https://")) {
  throw new Error("RO_E2E_INVALID_TARGET");
}

const scenario = {
  contractVersion: "ro-compare.v2",
  scenarioId: "cat-cartel.v2-zone1-day1",
  deliveryIds: ["zone1-day1-order0"],
  catCount: 1,
};

async function request(value, requestOrigin) {
  const res = await fetch(url, {
    method: "POST",
    headers: { Origin: requestOrigin, "Content-Type": "application/json" },
    body: JSON.stringify(value),
    signal: AbortSignal.timeout(25_000),
  });
  return { res, body: await res.json() };
}

const { res, body } = await request(scenario, origin);
const revision = String(body.graphId || "").split("/");
if (
  res.status !== 200 ||
  res.headers.get("access-control-allow-origin") !== origin ||
  !res.headers.get("cache-control")?.includes("no-store") ||
  body.source !== "qdip-ro" ||
  body.contractVersion !== "ro-compare.v2" ||
  body.solverStatus !== "FEASIBLE" ||
  body.distanceBasis !== "OSRM_DRIVING_STREET_NETWORK" ||
  body.quality !== "HEURISTIC_NOT_PROVEN_OPTIMAL" ||
  revision.length !== 4 ||
  revision[0] !== "osrm-private" ||
  revision[1] !== "warsaw" ||
  revision[2] !== "mld" ||
  !/^[a-f0-9]{64}$/.test(revision[3]) ||
  body.routedOrderIds?.length !== 1 ||
  body.routedOrderIds[0] !== "zone1-day1-order0" ||
  body.unassignedOrderIds?.length !== 0
) {
  throw new Error("RO_PROD_ATTESTED_CHAIN_FAILED status=" + res.status);
}
console.log("RO_PROD_SDK_ATTESTED_CHAIN_PASS status=200 graph=sha256 deliveries=1");

const denied = await request(scenario, "https://invalid.example");
if (denied.res.status !== 403 || denied.body.code !== "ORIGIN_FORBIDDEN") {
  throw new Error("RO_PROD_ORIGIN_DENIAL_FAILED status=" + denied.res.status);
}
console.log("RO_PROD_ORIGIN_DENIAL_PASS status=403");

const invalid = await request({ ...scenario, scenarioId: "invalid" }, origin);
if (invalid.res.status !== 422 || invalid.body.code !== "INVALID_REQUEST") {
  throw new Error("RO_PROD_INVALID_SCENARIO_FAILED status=" + invalid.res.status);
}
console.log("RO_PROD_INVALID_SCENARIO_PASS status=422");
console.log("RO_PRODUCTION_GRAPH_ATTESTATION_E2E_PASS 3/3");

import assert from 'node:assert/strict';

const capabilityId = 'route-optimizer.select-routes.v1';
const apiKey = process.env.QDIP_RO_SDK02_EXECUTE_KEY;
assert(apiKey, 'Missing RO E2E execute key');

const base = 'https://dzvin-intelligence-platform-production.up.railway.app/api/v1/';
async function getJson(path, payload) {
  const response = await fetch(base + path, {
    method: payload === undefined ? 'GET' : 'POST',
    headers: {
      'x-api-key': apiKey,
      'accept': 'application/json',
      ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    redirect: 'error',
    signal: AbortSignal.timeout(45000),
  });
  assert.equal(response.status, 200, 'Gateway request was not successful');
  return response.json();
}

const inventory = await getJson('remote-plugins/capabilities');
assert(inventory.items.some(item =>
  item.plugin_id === 'route-optimizer-sdk02' &&
  item.capability_id === capabilityId &&
  item.capability_version === '1'), 'RO worker not registered');
console.log('RO_WORKER_DISCOVERY=PASS');

const result = await getJson('remote-plugins/' + capabilityId + '/invoke', {
  capability_version: '1',
  timeout_seconds: 20,
  input: {
    drivers: ['d1', 'd2'],
    deliveries: ['a', 'b', 'c'],
    routes: [
      { id: 'ab', driver: 'd1', deliveries: ['a', 'b'], cost: 7 },
      { id: 'a', driver: 'd1', deliveries: ['a'], cost: 5 },
      { id: 'b', driver: 'd2', deliveries: ['b'], cost: 3 },
      { id: 'c', driver: 'd2', deliveries: ['c'], cost: 4 },
      { id: 'bc', driver: 'd2', deliveries: ['b', 'c'], cost: 5 },
    ],
  },
});
const execution = result.execution_result;
assert.equal(execution.backend_status, 'OPTIMAL');
assert.equal(execution.semantic_status, 'EXACT');
assert.equal(result.actionable, true);
assert.equal(Number(execution.objective_value), 10);
const expected = { route_ab: 0, route_a: 1, route_b: 0, route_c: 0, route_bc: 1 };
for (const [name, selected] of Object.entries(expected)) {
  assert.equal(Number(execution.solution?.[name]), selected);
}
console.log('RO_KERNEL_OPTIMAL_EXACT_10=PASS');

const manifest = execution.manifest;
const replay = result.replay_contract;
assert.equal(execution.decision_id, manifest.decision_id);
assert.equal(execution.ir_hash, manifest.ir_hash);
assert.equal(manifest.decision_id, replay.decision_id);
assert.equal(manifest.ir_hash, replay.ir_hash);
assert.equal(manifest.decision_spec_hash, replay.decision_spec_hash);
assert.equal(manifest.compiler_version, replay.compiler_version);
assert.equal(manifest.runtime_version, 'qdip-runtime-kernel.v1');
assert.match(manifest.ir_hash, /^[a-f0-9]{64}$/);
assert.match(manifest.decision_spec_hash, /^[a-f0-9]{64}$/);
console.log('RO_MANIFEST_REPLAY=PASS');
console.log('RO_REAL_SDK02_GATEWAY_KERNEL_E2E=PASS');

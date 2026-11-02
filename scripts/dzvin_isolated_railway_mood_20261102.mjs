// Dedicated ephemeral Railway QA environment only. No public API or production credentials.
const base = process.env.DZVIN_QA_BACKEND_URL || 'http://dzvin-b2c-rc-build.railway.internal:8080';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const assert = (condition, code) => { if (!condition) throw new Error(code); };
async function call(path, init = {}) {
  return fetch(base + path, { signal: AbortSignal.timeout(9000), ...init });
}
async function main() {
  assert(base.endsWith('.railway.internal:8080'), 'NOT_PRIVATE_RAILWAY_ENDPOINT');
  let health;
  for (let n = 0; n < 20; n++) {
    try { health = await call('/api'); break; } catch { await sleep(3000); }
  }
  assert(health, 'PRIVATE_BACKEND_UNREACHABLE');
  console.log('QA_INTERNAL_BACKEND_REACHABLE=PASS');
  const list = await call('/api/mood-record?page=1&limit=100&order=newest');
  console.log('QA_AUTH_PREFLIGHT_STATUS=' + list.status);
  if (list.status !== 200) throw Error('QA_AUTH_REQUIRED_' + list.status);
  const records = await list.json();
  assert(Array.isArray(records), 'LIST_NOT_ARRAY');
  assert(records.length === 0, 'ISOLATED_DATABASE_NOT_EMPTY');
  console.log('QA_ISOLATED_EMPTY_INITIAL_HISTORY=PASS');
  const body = {
    moodLevel: 4, stressLevel: 2, energyLevel: 3, focusLevel: 5,
    tags: ['qdip-isolated-20261102'],
  };
  const createdResponse = await call('/api/mood-record?timeZone=Europe%2FWarsaw', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  console.log('QA_MOOD_CREATE_HTTP=' + createdResponse.status);
  assert(createdResponse.status === 201, 'CREATE_STATUS_' + createdResponse.status);
  const created = await createdResponse.json();
  assert(typeof created.id === 'string' && Number.isFinite(Date.parse(created.createdAt)),
    'CREATED_DATE_OR_ID');
  for (const dimension of ['moodLevel', 'stressLevel', 'energyLevel', 'focusLevel']) {
    assert(created[dimension] === body[dimension], 'CREATED_DIMENSION_' + dimension);
  }
  assert(Array.isArray(created.tags) && created.tags.includes('qdip-isolated-20261102'), 'CREATED_TAGS');
  console.log('QA_MOOD_CREATE_DIMENSIONS_DATE_TAGS=PASS');
  const historyResponse = await call('/api/mood-record?page=1&limit=100&order=newest');
  assert(historyResponse.status === 200, 'HISTORY_HTTP_' + historyResponse.status);
  const history = await historyResponse.json();
  assert(Array.isArray(history) && history.some(r => r.id === created.id &&
    r.moodLevel === 4 && r.stressLevel === 2 && r.energyLevel === 3 && r.focusLevel === 5 &&
    Array.isArray(r.tags) && r.tags.includes('qdip-isolated-20261102')),
    'CREATED_ENTRY_NOT_IN_HISTORY');
  console.log('QA_MOOD_PERSISTENCE_HISTORY=PASS');
  console.log('QA_CLEANUP_REQUIRED=DROP_WHOLE_ISOLATED_SERVICE_AFTER_TEST');
}
main().catch(error => {
  const safeCode = String(error.message || 'FAIL').replace(/[^A-Za-z0-9_]/g, '_').slice(0,100);
  console.error('QA_ISOLATED_MOOD=FAIL:' + safeCode);
  process.exitCode = 1;
});

/** Authenticated, read-only QA check. Never print diary or mood content. */
import { request } from '@playwright/test';
import { readFileSync } from 'node:fs';

const BASE = 'https://mentality-ho9v3tydz-taras-gezs-projects.vercel.app';
const MAX_PAGE = 101;
const PAGE_SIZE = 100;
const ALLOWED_FIELDS = new Set([
  'id', 'moodLevel', 'stressLevel', 'energyLevel', 'focusLevel', 'tags', 'createdAt',
]);

function assert(ok, code) {
  if (!ok) throw new Error(code);
}
async function ownerIds(api) {
  const ids = new Set();
  for (let page = 1; page <= MAX_PAGE; page++) {
    const response = await api.get(
      '/api/backend/mood-record?page=' + page + '&limit=' + PAGE_SIZE + '&order=oldest',
      { timeout: 30000 },
    );
    assert(response.status() === 200, 'OWNER_MOOD_LIST_FAILED');
    const data = await response.json();
    assert(Array.isArray(data) && data.length <= PAGE_SIZE, 'BAD_OWNER_MOOD_LIST');
    for (const item of data) {
      assert(typeof item.id === 'string' && !ids.has(item.id), 'OWNER_MOOD_LIST_DUPLICATED');
      ids.add(item.id);
    }
    if (data.length < PAGE_SIZE) return ids;
  }
  throw new Error('OWNER_MOOD_LIST_EXCEEDS_LIMIT');
}

async function checkActor(label, path, envKey) {
  const state = JSON.parse(readFileSync(path, 'utf8'));
  const api = await request.newContext({ baseURL: BASE, storageState: state });
  try {
    const session = await api.get('/api/auth/session', { maxRedirects: 0 });
    assert(session.status() === 200, label + '_SESSION_INVALID');
    const subject = await session.json();
    assert(
      subject.id && subject.id === process.env[envKey] && subject.role !== 'admin',
      label + '_VERIFIED_SUBJECT_MISMATCH',
    );
    const owned = await ownerIds(api);
    const response = await api.get('/api/privacy/mood-export', { maxRedirects: 0, timeout: 60000 });
    assert(response.status() === 200, label + '_EXPORT_NOT_OK');
    const headers = response.headers();
    assert((headers['cache-control'] || '').includes('no-store'), label + '_CACHE_UNSAFE');
    assert(headers.vary === 'Cookie', label + '_VARY_COOKIE_MISSING');
    assert(headers['x-content-type-options'] === 'nosniff', label + '_NOSNIFF_MISSING');
    assert(/^attachment; filename="dzvin-mood-history-\d{4}-\d{2}-\d{2}\.json"$/.test(
      headers['content-disposition'] || '',
    ), label + '_DOWNLOAD_CONTRACT_FAILED');
    const payload = await response.json();
    assert(payload.format === 'dzvin-mood-history' && payload.version === 1, label + '_VERSION_MISMATCH');
    assert(Array.isArray(payload.entries), label + '_ENTRIES_INVALID');
    const exported = new Set();
    for (const entry of payload.entries) {
      assert(typeof entry.id === 'string' && !exported.has(entry.id), label + '_DUPLICATE_EXPORTED_ID');
      assert(Object.keys(entry).every(key => ALLOWED_FIELDS.has(key)), label + '_EXPORTED_EXTRA_FIELDS');
      exported.add(entry.id);
    }
    assert(exported.size === owned.size, label + '_OWNED_COUNT_MISMATCH');
    assert([...exported].every(id => owned.has(id)), label + '_FOREIGN_OR_MISSING_ENTRY');
    // No user IDs, data, cookies or access tokens are logged.
    console.log(label + '_MOOD_EXPORT_OWNER_ONLY=PASS');
  } finally {
    await api.dispose();
  }
}

async function main() {
  assert(process.env.DZVIN_MOOD_EXPORT_READONLY_ACK === '1', 'READONLY_APPROVAL_MISSING');
  assert(process.env.E2E_BASE_URL === BASE, 'BASE_ORIGIN_NOT_PINNED');
  assert(process.env.E2E_ALLOWED_MUTATION_ORIGIN === BASE, 'ORIGIN_ALLOWLIST_NOT_PINNED');
  assert(process.env.E2E_DEPLOYED_WEB_SHA === 'ec4a1875ebc9e6e3300d9728c3859dff88da3d79', 'WEB_SHA_MISMATCH');
  assert(process.env.E2E_QA_A_USER_ID && process.env.E2E_QA_B_USER_ID &&
    process.env.E2E_QA_A_USER_ID !== process.env.E2E_QA_B_USER_ID, 'QA_SUBJECTS_NOT_PINNED');
  const anonymous = await request.newContext({ baseURL: BASE });
  try {
    const resp = await anonymous.get('/api/privacy/mood-export', { maxRedirects: 0 });
    assert(resp.status() === 401, 'ANONYMOUS_EXPORT_NOT_REJECTED');
    assert((resp.headers()['cache-control'] || '').includes('no-store'), 'ANON_CACHE_UNSAFE');
    console.log('ANONYMOUS_MOOD_EXPORT_DENIED=PASS');
  } finally {
    await anonymous.dispose();
  }
  await checkActor('QA1', 'playwright/.auth/b2c-a.json', 'E2E_QA_A_USER_ID');
  await checkActor('QA2', 'playwright/.auth/b2c-b.json', 'E2E_QA_B_USER_ID');
  console.log('DZVIN_QA1_QA2_MOOD_EXPORT_READONLY=PASS');
}
main().catch((error) => {
  // Do not emit raw Fetch/Playwright error messages (may include private URLs).
  const code = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
    ? error.message : 'SANITIZED_MOOD_EXPORT_QA_FAILURE';
  console.error('DZVIN_QA1_QA2_MOOD_EXPORT_READONLY=FAIL:' + code);
  process.exitCode = 1;
});
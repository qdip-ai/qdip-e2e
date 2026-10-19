/** Read-only authorization/response-contract checks for partial privacy inventory. */
import { request } from '@playwright/test';
import { readFileSync } from 'node:fs';

const BASE = 'https://mentality-ho9v3tydz-taras-gezs-projects.vercel.app';
const ENDPOINT = '/api/backend/privacy/my-data-inventory';
const KNOWN = [
  'moodrecords', 'diaries', 'goals', 'mood_stories',
  'mood_risk_predictions', 'mood_feed_messages', 'weekly_insights',
  'phq9results', 'gad7results', 'k10results', 'userTags', 'favorites',
];
const RELATED = [
  'usercategorystats', 'exerciseperformances', 'attention_sprint',
  'prediction_snapshots', 'companymemberships', 'groupmemberships',
  'accessscopes', 'research_project_memberships', 'research_projects',
  'research_data_grants', 'decision_risk_events',
];

function assert(ok, reason) {
  if (!ok) throw new Error(reason);
}

async function authenticated(label, path, envName) {
  const state = JSON.parse(readFileSync(path, 'utf8'));
  const api = await request.newContext({ baseURL: BASE, storageState: state });
  try {
    const sess = await api.get('/api/auth/session', { maxRedirects: 0 });
    assert(sess.status() === 200, label + '_SESSION_MISSING');
    const actor = await sess.json();
    assert(actor.id === process.env[envName] && actor.role !== 'admin', label + '_IDENTITY_NOT_PINNED');
    const result = await api.get(ENDPOINT, { maxRedirects: 0, timeout: 30000 });
    assert(result.status() === 200, label + '_INVENTORY_UNAVAILABLE');
    assert((result.headers()['cache-control'] || '').includes('no-store'), label + '_CACHE_UNSAFE');
    const payload = await result.json();
    assert(payload.status === 'incomplete', label + '_MUST_REPORT_INCOMPLETE');
    assert(payload.erasureAvailable === false, label + '_ERASURE_MUST_BE_BLOCKED');
    assert(typeof payload.asOf === 'string', label + '_SNAPSHOT_TIMESTAMP_MISSING');
    assert(Array.isArray(payload.uncovered) && payload.uncovered.length > 0, label + '_GAPS_MISSING');
    assert(payload.counts && typeof payload.counts === 'object', label + '_COUNTS_MISSING');
    assert(Object.keys(payload.counts).length === KNOWN.length, label + '_COLLECTION_ALLOWLIST_CHANGED');
    for (const key of KNOWN) {
      assert(Number.isSafeInteger(payload.counts[key]) && payload.counts[key] >= 0, label + '_INVALID_COUNT');
    }
    assert(payload.relatedCounts && typeof payload.relatedCounts === 'object',
      label + '_LINKED_COUNTS_MISSING');
    assert(Object.keys(payload.relatedCounts).length === RELATED.length,
      label + '_LINKED_COLLECTION_ALLOWLIST_CHANGED');
    for (const key of RELATED) {
      assert(Number.isSafeInteger(payload.relatedCounts[key]) && payload.relatedCounts[key] >= 0,
        label + '_LINKED_COUNT_INVALID');
    }
    assert(payload.uncovered.includes('zitadel-account-and-sessions'),
      label + '_ZITADEL_ERASURE_GAP_HIDDEN');
    assert(payload.uncovered.includes('backup-retention-and-audit-obligations'),
      label + '_BACKUP_RETENTION_GAP_HIDDEN');
    if (Object.values(payload.relatedCounts).some(count => count > 0)) {
      assert(payload.uncovered.includes('linked-records-require-owner-specific-disposition'),
        label + '_LINKED_RECORD_REVIEW_NOT_REQUIRED');
    }
    assert(
      Object.keys(payload).every(key => ['status', 'erasureAvailable', 'asOf', 'counts', 'relatedCounts', 'uncovered'].includes(key)),
      label + '_UNEXPECTED_PERSONAL_FIELDS',
    );
    console.log(label + '_PRIVACY_INVENTORY_READONLY=PASS');
  } finally {
    await api.dispose();
  }
}

async function main() {
  assert(process.env.DZVIN_MOOD_EXPORT_READONLY_ACK === '1', 'READONLY_ACK_MISSING');
  assert(process.env.E2E_BASE_URL === BASE, 'ORIGIN_MISMATCH');
  assert(process.env.E2E_QA_A_USER_ID && process.env.E2E_QA_B_USER_ID &&
    process.env.E2E_QA_A_USER_ID !== process.env.E2E_QA_B_USER_ID, 'PINNED_QA_IDENTITIES_MISSING');
  const anonymous = await request.newContext({ baseURL: BASE });
  try {
    const res = await anonymous.get(ENDPOINT, { maxRedirects: 0 });
    assert(res.status() === 401, 'ANONYMOUS_INVENTORY_NOT_DENIED');
    console.log('ANONYMOUS_PRIVACY_INVENTORY_DENIED=PASS');
  } finally {
    await anonymous.dispose();
  }
  await authenticated('QA1', 'playwright/.auth/b2c-a.json', 'E2E_QA_A_USER_ID');
  await authenticated('QA2', 'playwright/.auth/b2c-b.json', 'E2E_QA_B_USER_ID');
  console.log('DZVIN_QA1_QA2_PRIVACY_INVENTORY_READONLY=PASS');
}

main().catch(error => {
  const code = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
    ? error.message : 'SANITIZED_PRIVACY_INVENTORY_ERROR';
  console.error('DZVIN_QA1_QA2_PRIVACY_INVENTORY_READONLY=FAIL:' + code);
  process.exitCode = 1;
});

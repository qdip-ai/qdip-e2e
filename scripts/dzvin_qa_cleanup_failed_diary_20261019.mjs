/**
 * One-time cleanup of ONLY the three potential UUID-tagged diary records
 * from the failed Dzvin QA1/QA2 run at 2026-10-19 07:38 UTC.
 *
 * The runner supplies real QA browser sessions, not DB administrator access.
 * This script never prints diary text, user IDs, cookies or record IDs.
 */
import { request } from '@playwright/test';
import { readFileSync } from 'node:fs';

const ORIGIN = 'https://mentality-piytogl1z-taras-gezs-projects.vercel.app';
const WINDOW_START = Date.parse('2026-10-19T07:38:09.000Z');
const WINDOW_END = Date.parse('2026-10-19T07:38:32.000Z');
const ID = /^[0-9a-f]{24}$/i;
const FIXTURE = /^e2e-diary-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-(a-active|a-archived|b-private)$/i;
const actors = [
  { label: 'QA1', file: 'playwright/.auth/b2c-a.json', suffixes: new Set(['a-active', 'a-archived']) },
  { label: 'QA2', file: 'playwright/.auth/b2c-b.json', suffixes: new Set(['b-private']) },
];

function assert(value, code) {
  if (!value) throw new Error(code);
}

async function list(api, label) {
  const r = await api.get('/api/backend/diary/user');
  assert(r.status() === 200, label + '_OWNED_LIST_FAILED');
  const entries = await r.json();
  assert(Array.isArray(entries), label + '_DIARY_LIST_NOT_ARRAY');
  return entries;
}

function select(entries, actor) {
  const matches = [];
  for (const e of entries) {
    const content = typeof e.content === 'string' ? e.content : '';
    const m = FIXTURE.exec(content);
    if (!m) continue;
    if (!actor.suffixes.has(m[2])) continue;
    const when = Date.parse(e.createdAt);
    if (!Number.isFinite(when) || when < WINDOW_START || when > WINDOW_END) continue;
    assert(ID.test(e.id), actor.label + '_MATCHED_FIXTURE_ID_INVALID');
    matches.push({ id: e.id, uuid: m[1], suffix: m[2] });
  }
  return matches;
}

async function main() {
  assert(process.env.DZVIN_FAILED_DIARY_CLEANUP_ACK === '1', 'CLEANUP_OPT_IN_MISSING');
  assert(process.env.E2E_BASE_URL === ORIGIN, 'CLEANUP_ORIGIN_MISMATCH');
  assert(process.env.E2E_QA_SHARED_BACKEND_SCOPED_APPROVED === '1', 'QA_MODE_REQUIRED');
  const clients = [];
  try {
    const found = [];
    for (const actor of actors) {
      const state = JSON.parse(readFileSync(actor.file, 'utf8'));
      const api = await request.newContext({ baseURL: ORIGIN, storageState: state });
      clients.push(api);
      const session = await api.get('/api/auth/session');
      assert(session.status() === 200, actor.label + '_SESSION_INVALID');
      const identity = await session.json();
      const expected = process.env[actor.label === 'QA1' ? 'E2E_QA_A_USER_ID' : 'E2E_QA_B_USER_ID'];
      assert(expected && identity.id === expected && identity.role !== 'admin',
        actor.label + '_QA_SUBJECT_UNVERIFIED');
      const entries = await list(api, actor.label);
      const matches = select(entries, actor);
      const maximum = actor.label === 'QA1' ? 2 : 1;
      assert(matches.length <= maximum, actor.label + '_TOO_MANY_MATCHES_ABORT');
      found.push({ actor, api, matches });
    }

    const all = found.flatMap(x => x.matches);
    assert(all.length <= 3, 'CLEANUP_SCOPE_EXCEEDED_ABORT');
    const distinctRunIds = new Set(all.map(x => x.uuid));
    assert(distinctRunIds.size <= 1, 'MULTIPLE_TEST_RUNS_IN_WINDOW_ABORT');
    assert(new Set(all.map(x => x.id)).size === all.length, 'DUPLICATE_IDS_ABORT');
    assert(new Set(all.map(x => x.suffix)).size === all.length, 'DUPLICATE_SUFFIX_ABORT');
    console.log('DZVIN_FAILED_RUN_FIXTURES_FOUND=' + all.length);

    for (const { api, matches } of found) {
      for (const { id } of matches) {
        const deletion = await api.delete('/api/backend/diary/' + id, {
          headers: { Origin: ORIGIN },
        });
        assert([204, 404].includes(deletion.status()), 'MARKED_FIXTURE_DELETE_FAILED');
        const check = await api.get('/api/backend/diary/' + id);
        assert(check.status() === 404, 'MARKED_FIXTURE_STILL_READABLE');
      }
    }

    // Fresh lists must prove the entire narrowly scoped run is absent.
    for (const { actor, api } of found) {
      const remaining = select(await list(api, actor.label), actor);
      assert(remaining.length === 0, actor.label + '_MARKED_FIXTURE_REMAINING');
    }
    console.log('DZVIN_FAILED_RUN_FIXTURES_CLEANED_AND_VERIFIED=' + all.length);
    console.log('DZVIN_FAILED_RUN_SCOPED_CLEANUP=PASS');
  } finally {
    await Promise.all(clients.map(api => api.dispose().catch(() => undefined)));
  }
}
main().catch(error => {
  // No raw exception: HTTP errors may contain sensitive URLs/tokens.
  const code = error instanceof Error && /^[A-Z0-9_]{5,100}$/.test(error.message)
    ? error.message : 'SANITIZED_SCOPED_CLEANUP_FAILURE';
  console.error('DZVIN_FAILED_RUN_SCOPED_CLEANUP=FAIL:' + code);
  process.exitCode = 1;
});
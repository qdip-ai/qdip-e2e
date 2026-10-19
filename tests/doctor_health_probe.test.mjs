import assert from 'node:assert/strict';
import test from 'node:test';
import { checkDoctor, retryDoctor } from '../scripts/doctor_health_probe.mjs';

const origin = 'https://doctor.qdip.ai';
function response(body, status = 200, headers = {}) {
  return {
    status,
    headers: new Headers(headers),
    async json() { return body; },
  };
}
function stub({ failPath, leaked = false } = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    assert.ok(url.startsWith(origin + '/'));
    assert.equal(options.redirect, 'manual');
    calls.push({ path: url.slice(origin.length), options });
    const path = url.slice(origin.length);
    if (path === failPath) return response({}, 503);
    if (path === '/readyz') return response({ status: 'ready' });
    if (path === '/.well-known/oauth-protected-resource/mcp') {
      return response({
        resource: `${origin}/mcp`,
        authorization_servers: ['https://zitadel.example'],
        scopes_supported: ['doctor:use'],
      });
    }
    if (path === '/mcp') {
      assert.equal(options.method, 'POST');
      assert.equal(options.headers.Authorization, undefined);
      return response({ error: 'unauthorized' }, leaked ? 200 : 401, {
        'www-authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
      });
    }
    if (path === '/api/session') {
      return response({ authenticated: leaked, user: null }, 200);
    }
    throw new Error('UNEXPECTED_PATH');
  };
  return { calls, fetchImpl };
}

test('passes actual anonymous protected gateway without credentials', async () => {
  const { calls, fetchImpl } = stub();
  assert.equal(await checkDoctor(fetchImpl), true);
  assert.deepEqual(calls.map(item => item.path), [
    '/readyz', '/.well-known/oauth-protected-resource/mcp',
    '/mcp', '/api/session',
  ]);
});

test('fails closed on worker readiness or anonymous MCP leakage', async () => {
  await assert.rejects(checkDoctor(stub({ failPath: '/readyz' }).fetchImpl),
    { message: 'WORKER_UNAVAILABLE' });
  await assert.rejects(checkDoctor(stub({ leaked: true }).fetchImpl),
    { message: 'ANONYMOUS_MCP_ALLOWED' });
});

test('retries only three times and fails with redacted stable code', async () => {
  let delays = 0;
  const first = stub({ failPath: '/readyz' });
  const failed = await retryDoctor(first.fetchImpl, async () => { delays++; });
  assert.deepEqual(failed, { ok: false, reason: 'WORKER_UNAVAILABLE' });
  assert.equal(delays, 2);
  assert.equal(first.calls.length, 3);
});

test('transient failure recovers without raising an incident', async () => {
  const working = stub();
  let attempts = 0;
  const fetchImpl = async (...args) => {
    attempts++;
    if (attempts === 1) throw new TypeError('A response URL might include sensitive query');
    return working.fetchImpl(...args);
  };
  assert.deepEqual(await retryDoctor(fetchImpl, async () => {}), { ok: true, attempts: 2 });
});

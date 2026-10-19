/**
 * Credential-free external probe of an existing Doctor deployment.
 * Checks liveness through the isolated worker, OAuth metadata and fail-closed
 * anonymous access. This is NOT an authenticated Zitadel or security audit.
 */
import { pathToFileURL } from 'node:url';

const ORIGIN = 'https://doctor.qdip.ai';
const TIMEOUT_MS = 8000;

function requireCheck(value, reason) {
  if (!value) throw new Error(reason);
}

async function request(path, options = {}, fetchImpl = fetch) {
  const response = await fetchImpl(ORIGIN + path, {
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT_MS),
    ...options,
  });
  return response;
}

export async function checkDoctor(fetchImpl = fetch) {
  const readiness = await request('/readyz', {}, fetchImpl);
  requireCheck(readiness.status === 200, 'WORKER_UNAVAILABLE');
  const readyPayload = await readiness.json();
  requireCheck(readyPayload?.status === 'ready', 'WORKER_RESPONSE_INVALID');

  const metadataPath = '/.well-known/oauth-protected-resource/mcp';
  const metadataResponse = await request(metadataPath, {}, fetchImpl);
  requireCheck(metadataResponse.status === 200, 'OAUTH_DISCOVERY_UNAVAILABLE');
  const meta = await metadataResponse.json();
  requireCheck(meta?.resource === ORIGIN + '/mcp'
    && Array.isArray(meta.authorization_servers)
    && meta.authorization_servers.length === 1
    && /^https:\/\/[a-zA-Z0-9.-]+\/?$/.test(meta.authorization_servers[0])
    && Array.isArray(meta.scopes_supported)
    && meta.scopes_supported.includes('doctor:use'), 'OAUTH_DISCOVERY_INVALID');

  const bearer = await request('/mcp', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/event-stream',
      'MCP-Protocol-Version': '2026-07-28',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  }, fetchImpl);
  requireCheck(bearer.status === 401, 'ANONYMOUS_MCP_ALLOWED');
  requireCheck((bearer.headers.get('www-authenticate') || '').includes(
    `resource_metadata="${ORIGIN}${metadataPath}"`), 'MCP_OAUTH_CHALLENGE_INVALID');
  requireCheck((await bearer.json()).error === 'unauthorized', 'MCP_DENIAL_BODY_INVALID');

  const session = await request('/api/session', {}, fetchImpl);
  requireCheck(session.status === 200, 'BROWSER_SESSION_UNAVAILABLE');
  const state = await session.json();
  requireCheck(state?.authenticated === false && state?.user == null,
    'ANONYMOUS_SESSION_LEAK');
  requireCheck(!session.headers.has('set-cookie'), 'UNEXPECTED_SESSION_COOKIE');
  return true;
}

export async function retryDoctor(fetchImpl = fetch, delay = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  let lastReason = 'PROBE_UNAVAILABLE';
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await checkDoctor(fetchImpl);
      return { ok: true, attempts: attempt + 1 };
    } catch (error) {
      // Never report URLs with query strings, credentials or response bodies.
      lastReason = error instanceof Error && /^[A-Z_]{5,64}$/.test(error.message)
        ? error.message : 'PROBE_UNAVAILABLE';
      if (attempt < 2) await delay(10000);
    }
  }
  return { ok: false, reason: lastReason };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = await retryDoctor();
  if (result.ok) {
    console.log('DOCTOR_OPERATIONS_PUBLIC_HEALTH=PASS');
    console.log('DOCTOR_EXTERNAL_ZITADEL_OAUTH=NOT_TESTED');
  } else {
    console.error(`DOCTOR_OPERATIONS_PUBLIC_HEALTH=FAIL:${result.reason}`);
    process.exitCode = 1;
  }
}

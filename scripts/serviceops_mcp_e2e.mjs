// Copied into the pinned MCP checkout's test directory by the existing runner.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createApp } from '../dist/app.js';
import { loadConfig, requiredAuthorizationScopes } from '../dist/config.js';
import { validateClaims } from '../dist/auth.js';

const [name, flag, count, audience, provider = "chatgpt"] = process.argv.slice(2);
if (name === 'metadata') {
  const app = createApp(loadConfig(process.env));
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'https://mcp.qdip.ai');
      assert(['/.well-known/oauth-protected-resource/mcp', '/healthz'].includes(url.pathname));
      assert.equal(req.method, 'GET');
      const result = await app.fetch(new Request(url, { method: 'GET', headers: req.headers }));
      res.writeHead(result.status, Object.fromEntries(result.headers));
      res.end(Buffer.from(await result.arrayBuffer()));
    } catch { res.writeHead(500); res.end(); }
  });
  server.listen(18445, '127.0.0.1');
  await new Promise(resolve => server.once('close', resolve));
  await app.close();
  process.exit(0);
}
assert(["chatgpt", "claude"].includes(provider));
assert(['a','b'].includes(name));
const allowed = flag === '1';
const org = 'tenant-' + name;
const foreign = 'tenant-' + (name === 'a' ? 'b' : 'a');
const config = loadConfig(process.env);
const token = 'fixture-customer-' + name + (provider === 'claude' ? '-claude' : '') + '-token';
const app = createApp(config, {
  async verifyAccessToken(value) {
    // Synthetic identity provider boundary only; real claims normalization.
    assert.equal(value, token);
    const claims = {
      iss: process.env.ZITADEL_ISSUER,
      sub: name === 'a' ? '9001' : '9002',
      aud: audience === 'missing' ? ['100'] : ['100','202'],
      client_id: provider === 'claude' ? '123457' : '123456', exp: Math.floor(Date.now()/1000)+600,
      scope: requiredAuthorizationScopes(config).join(' ')
    };
    return {...validateClaims(claims, config), token:value};
  }
});
const client = new Client({name:'independent-e2e',version:'1'},
  {versionNegotiation:{mode:{pin:'2026-07-28'}}});
await client.connect(new StreamableHTTPClientTransport(config.resource,{
  requestInit:{headers:{authorization:'Bearer '+token}},
  fetch:(input, init)=>app.fetch(new Request(input,init))
}));
try {
  const generic = await client.callTool({name:'qdip_list_capabilities',arguments:{}});
  assert.equal(generic.isError,true);
  assert.equal(generic.structuredContent.error.code,'UNAUTHORIZED');
  const list = await client.callTool({name:'serviceops_list_companies',arguments:{}});
  const summary = organization_id => client.callTool({name:'serviceops_order_summary',arguments:{organization_id}});
  if (audience === 'missing') {
    assert.equal(list.isError,true);
    assert.equal(list.structuredContent.error.code,'OAUTH_SCOPE_REQUIRED');
  } else if (audience === 'grant-denied') {
    assert.equal(list.isError,true);
  } else {
    assert.notEqual(list.isError,true);
    assert.deepEqual(list.structuredContent,{companies: allowed ? [{organization_id:org}] : []});
  }
  const own = await summary(org);
  if (allowed) {
    assert.notEqual(own.isError,true);
    assert.equal(own.structuredContent.organization_id,org);
    assert.equal(own.structuredContent.total_orders,Number(count));
    assert.equal(Object.values(own.structuredContent.orders).reduce((a,b)=>a+b,0),Number(count));
  } else assert.equal(own.isError,true);
  assert.equal((await summary(foreign)).isError,true);
} finally {
  await client.close();
  await app.close();
}

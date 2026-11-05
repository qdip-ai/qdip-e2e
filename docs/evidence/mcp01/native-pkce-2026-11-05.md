# MCP01 real same-client PKCE qualification — 2026-11-05

Status: **Native authorization-code/PKCE and AS token revocation PASS; MCP OAuth and Worker E2E BLOCKED.**

## Exact evidence

- E2E source: `fd1cd43ec433c6cb576b42b475398faa4cc3752f`, [Draft PR143](https://github.com/qdip-ai/qdip-e2e/pull/143), Issue142. PR141 remains ownership preflight only.
- Real run: [41987048936](https://github.com/qdip-ai/qdip-e2e/actions/runs/41987048936), job127110140103, conclusion SUCCESS **for this diagnostic probe only**.
- MCP runtime source: `6c8d448e99a06725e0fc5d6b6eb0a4cbf458a452`; Railway deployment `05b533a4-c20d-4e26-af7c-7bdb7211c5c4`.
- Core implementation: `d1b930808803b7c4e5caa788ba4afe20119627a7`; tested regression source `f465ac38fe66c499dfced0500c59f75380c43b46`; evidence head `4ee8675d4aaa615be9b2bfc44560f28fd7076828`.
- Core regression deployment: `0b941657-4ffc-483f-ae31-ee6709dca9e3`. [Report and raw logs](https://github.com/qdip-ai/qdip-core/blob/4ee8675d4aaa615be9b2bfc44560f28fd7076828/docs/evidence/mcp652/railway-regression-2026-11-05.md): SDK50, remote/ownership402 +16subtests, runtime/Kernel129 passed. Disposable loopback Mongo and AS fixtures are **not live tenant/Worker E2E**.
- SDK tarball SHA-256: `7c19b376113bc3f6f26dac57500ff77201a99516d1452f576af1b4d3fa30904c`.

## Observed real flow

Existing protected QA21 runner read exact existing managed app/client/project references, authenticated the real QA user, and obtained **new tokens from that Native application's own code + S256 flow**. The Console token was used only for configuration inspection/setup and owner comparison, never as a Native/MCP/Gateway caller token.

Both baseline project-audience request and request additionally containing `resource=MCP_RESOURCE_URL` / `mcp:use` returned real access tokens. Userinfo confirmed the same owner. Tokens were opaque; the token response omitted `scope`. **Request acceptance proves neither granted mcp:use nor resource audience nor introspected client binding.** Actual introspection is still required.

Both disposable tokens were revoked: revocation HTTP200, subsequent userinfo HTTP401. This proves AS revocation behavior for these tokens, **not Gateway credential/binding revocation or MCP revocation enforcement**.

The real newly minted Native token was sent to the actual MCP `server/discover` endpoint: HTTP503. Authenticated MCP negotiation and tools/list did not pass. Current MCP config-name inspection still finds no `MCP_ALLOWED_CLIENT_IDS`, dedicated `ZITADEL_INTROSPECTION_CLIENT_ID/SECRET`, `QDIP_GATEWAY_URL/API_KEY`, or approved capability ID/version. Issuer is present.

## Root cause and minimal QA setup

Existing managed Native app initially had zero redirect URIs. Run41985427164 used the real project owner's authorized ApplicationService update to add only `http://127.0.0.1:8765/mcp01/callback`; identity read-back passed. The following broad settings assertion failed because it compared provider-derived fields; the three computed fields were excluded and mutable setting protections retained. Setup writes are now disabled.

Run41986864801 proved callback navigation `ERR_CONNECTION_REFUSED` for the exact registered callback: browser interception did not provide a real Native listener. The tested fix starts a loopback-only HTTP receiver, checks registered path/Host/state, keeps code/token solely in memory, and closes the listener. No verifier or AS audience/scope/client guard was relaxed.

The callback addition remains on the existing managed QA application. No external application, new identity service, project or user was created; no existing key was reset/copied. Rollback of this QA setup requires the authorized owner to remove that one URI after checking no dependent QA flow uses it; this report does not perform that removal.

## Remaining gates

1. Protected dedicated MCP introspection provisioning and actual opaque-token inspection: issuer, audience/resource, exact Native client, owner subject, expiry, granted scope, active/revoked state. No delegation, client-ID bypass or generic project-audience acceptance.
2. Approved runtime custody for owner-authorized canonical linking and separate app-scoped caller / Worker credentials. Current exposed operator script requires unsealed-delivery opt-in; no approved sealed forwarding path was established. Existing sealed Core credentials are not missing and must not be copied/recreated.
3. Exact Core654 live Gateway, canonical records and same-org two-app/cross-org qualification.
4. Actual authenticated tools/list; SDK list/describe/invoke; registered SDK-02 Worker -> frozen Kernel result; Manifest/Replay/decimals; security, schema, timeout/no-duplicate, outage and result-release negatives.
5. Actual end-to-end phase timings remain NOT RUN. No SLA inferred from this small authorization probe.

MCP PR2, Core PR654 and E2E PR143 stay Draft. No merge, production deployment or execution enablement. Sanitized marker transcript is adjacent; no token/code/password/subject/client ID values, full auth URLs, browser traces or screenshots were persisted.

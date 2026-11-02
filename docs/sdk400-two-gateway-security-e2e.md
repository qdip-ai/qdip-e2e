# SDK #400 — actual two-Gateway security acceptance (2026-11-02)

## Result and scope

**PASS** for *cross-Gateway quarantine/revocation and terminal reconnect* on the isolated test-only plugin identity, **not** full Core #400 or SDK #404 release. This is live Railway E2E, not an in-process/mocked Gateway test.

- Repo: `qdip-ai/qdip-e2e`
- Tested script commit: `9d2ad136894409aa52d2501a653cdab4bb2f9a06`
- Core deployment source: `qdip-ai/qdip-core@3cd28d31c93f0b3689a2c4b660ed5a4bf65d2e49` (both Gateways)
- Independent SDK-02 Worker source: `qdip-ai/qdip-core@ffac08fea89c03e76f85e569cefc79dbde6eba53` (two Workers)
- Existing Railway project `qdip-sdk-staging`, environment `staging`; shared real staging MongoDB, **two separate Core Gateway processes** with independently held Worker sessions; existing RR Core and Workers unmodified
- One-shot QA runner exact deployment `d13cfe3d-a894-47e6-a0e7-43dd292e4c7b` **SUCCESS**. Source tested: `9d2ad136894409aa52d2501a653cdab4bb2f9a06`
- QA plugin ID `sdk400-e2e-multigateway-r3`, capability `sdk400.e2e.rr-scheduling-r3.v1`. Fresh scoped Worker key issued through fenced Core lease, delivered using Railway `isSealed:true` to two separate Worker processes. Temporary scoped caller key; exact manifest digest admitted on both Gateways by reviewed platform-admin manual approval with actor, review reference and risk acknowledgement. No public third-party admission or production keys.
- Gateway A `sdk400-mg-gateway-a` deployment `e09be619-d62e-4a59-b674-16ed44301547`.
- Gateway B `sdk400-mg-gateway-b` deployment `173eda50-5ced-4177-a097-04a16def6363`.

## Verified runtime gates

QA runner emitted exactly:

```text
SDK400_TWO_GATEWAY_LIVE_REGISTER=PASS
SDK400_TWO_GATEWAY_APPROVED_KERNEL=PASS
SDK400_TWO_GATEWAY_QUARANTINE_DENY=PASS
SDK400_TWO_GATEWAY_RECONNECT_DENY=PASS
SDK400_TWO_GATEWAY_REVOKED_TERMINAL=PASS
SDK400_TWO_GATEWAY_CREDENTIAL_CLEANUP=PASS
SDK400_TWO_GATEWAY_SECURITY_E2E=PASS
```

Both Gateways independently returned HTTP 200 for real SDK Worker invoke through frozen Kernel, with validated exact/optimal execution, solution, manifest identity and replay hashes.

A quarantined the shared registration in Mongo and disconnected **its own** Worker. Thus its next invocation failed closed with HTTP **503** (no local Worker), while **B retained a live Worker and independently denied with HTTP 403** from the changed Mongo security state. Releasing quarantine restored only `pending_review`; B still denied with HTTP 403. Terminal revoke from A persisted in Mongo, and B again returned HTTP 403 while its previously connected Worker remained. B's attempts to approve/release this revoked identity were rejected HTTP 409. After restarting B's Worker while revoked, the new process received permanent auth denial and the old process-local registration drained; a new `REGISTERED` acknowledgement was **not** observed.

Keys were explicitly revoked, lease released, sealed Worker variables and both Gateway trusted-manifest digests removed and read back absent; no staged Railway changes. After final verification all five disposable `sdk400-mg-*` services (two Gateways, two Workers, QA runner) were deleted with no attached volumes. No changes to production, Core Kernel, shared RR Workers or reconciler.

## Root-cause-driven test iterations

- Runner SHA `fa50271cba74c5fea704e2611c9e48d09e397fbf`, deployment `330c7791-2758-461e-8da4-6ff1e5d83a9e`: both positive Gateways PASS. Quarantine test **incorrectly** required HTTP 403 on the *mutating local Gateway A*, which correctly disconnected its own session and responded 503. This was a test expectation issue, not proof of security bypass. Cleanup passed.
- Runner SHA `f386ecd154975f247dcb4e1fbb2c6205c37be367`, deployment `02348802-6989-4831-9f2e-750f21007965`: both positive and live peer B quarantine deny PASS, terminal revoke on B HTTP 403. Final reconnect assertion incorrectly equated a transient **old** process-local session with a successful new REGISTER. Gateway B logs instead showed `4409` conflicts while stale lease drained, followed by `4403` denied auth; new Worker exited `WorkerAuthenticationError`. Cleanup PASS.
- Runner SHA `9d2ad136894409aa52d2501a653cdab4bb2f9a06`, deployment `d13cfe3d-a894-47e6-a0e7-43dd292e4c7b`: distinct disposable plugin identity; test checks terminated **new** deployment and bounded wait for stale local session drain rather than assuming immediate disappearance. All seven gates PASS.

## Remaining explicit limitations

This does **not** exercise a deterministic *in-flight* solve interrupted exactly between Worker dispatch and result delivery; Gateway B has a real live Worker for the quarantine/revocation checks, but the test invokes after each committed state change. Additional P0 evidence required for Core #400: concurrent in-flight revocation/cancel with two Gateways, Mongo outage/failover, authenticated Observatory/Zitadel browser security UI and untrusted artifact provenance (#399). Do not close #400/#404 from this focused E2E alone. The staging-only manual exception cannot authorize any new production or third-party Worker.

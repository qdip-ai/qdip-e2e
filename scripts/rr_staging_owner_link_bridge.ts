import { createHmac, timingSafeEqual } from "node:crypto";

// Isolated RR staging owner relay. Never issues credentials and cannot
// assert a user: the upstream is signed by the Web session and Core verifies
// the exact human's live Zitadel ORG_OWNER membership a second time.
const STAGING_PROJECT = "f1326384-1e2d-4bea-99a9-bbae2233e36e";
const STAGING_ENV = "9e4a6dac-717c-4327-bb1e-1491a4e5c080";
const STAGING_SERVICE = "1d15af24-a559-4537-a17d-28d4b211c5da";
const QDIP_ZITADEL_ORG = "368555767923594379";
const EXPECTED_ISSUER = "https://mentality-rmwj0i.eu1.zitadel.cloud";
const EXPECTED_CORE_DOMAIN = "qdip-core-staging-staging.up.railway.app";
const seen = new Map<string, number>();
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { "content-type": "application/json", "cache-control": "no-store" },
});
const refuse = (status: number) => json({ error: "RR staging owner verification refused" }, status);

function hmac(secret: string, purpose: string, issuer: string, org: string, sub: string, issued: number, nonce: string) {
  return createHmac("sha256", secret)
    .update([purpose, issuer, org, sub, String(issued), nonce].join("\n"), "utf8")
    .digest("hex");
}
function matchHmac(expected: string, supplied: string) {
  if (!/^[a-f0-9]{64}$/.test(supplied)) return false;
  return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(supplied, "hex"));
}
function configurationReady() {
  return (
    Bun.env.RAILWAY_PROJECT_ID === STAGING_PROJECT &&
    Bun.env.RAILWAY_ENVIRONMENT_ID === STAGING_ENV &&
    Bun.env.RAILWAY_SERVICE_ID === STAGING_SERVICE &&
    Bun.env.CORE_DOMAIN === EXPECTED_CORE_DOMAIN &&
    (Bun.env.CORE_API_KEY?.length ?? 0) >= 32 &&
    (Bun.env.QDIP_ORG_LINK_ASSERTION_SECRET?.length ?? 0) >= 32 &&
    (Bun.env.RR_STAGING_OWNER_RELAY_SECRET?.length ?? 0) >= 32
  );
}

if (Bun.env.RR_STAGING_OWNER_LINK_ENABLED === "1") {
  const port = Number(Bun.env.PORT || "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid Railway port");
  Bun.serve({
    port,
    async fetch(req: Request) {
      const u = new URL(req.url);
      if (u.pathname === "/health" && req.method === "GET") {
        return json({ ready: configurationReady() }, configurationReady() ? 200 : 503);
      }
      if (u.pathname !== "/qa/rr/owner-link") return refuse(404);
      if (req.method !== "POST") return refuse(405);
      if (!configurationReady()) return refuse(503);
      if (req.headers.get("content-type")?.split(";")[0].trim() !== "application/json") return refuse(415);
      const declared = Number(req.headers.get("content-length") ?? "0");
      if (declared > 2048) return refuse(413);
      try {
        const raw = await req.text();
        if (raw.length > 2048) return refuse(413);
        const body: unknown = JSON.parse(raw);
        if (!body || typeof body !== "object" || Array.isArray(body)) return refuse(422);
        const b = body as Record<string, unknown>;
        const action = b.action;
        if (action !== "list" && action !== "link") return refuse(422);
        const keys = Object.keys(b).sort().join(",");
        const listKeys = "action,assertion,authenticated_subject,issued_at,issuer,nonce";
        const linkKeys = "action,assertion,authenticated_subject,issued_at,issuer,nonce,organization_id";
        if (keys !== (action === "list" ? listKeys : linkKeys)) return refuse(422);
        const issuer = b.issuer, sub = b.authenticated_subject, ts = b.issued_at, nonce = b.nonce, assertion = b.assertion;
        if (
          issuer !== EXPECTED_ISSUER || typeof sub !== "string" || !/^[0-9]{1,32}$/.test(sub) ||
          typeof ts !== "number" || !Number.isInteger(ts) ||
          Math.abs(Math.floor(Date.now() / 1000) - ts) > 60 ||
          typeof nonce !== "string" || !/^[a-f0-9]{32}$/.test(nonce) ||
          typeof assertion !== "string" || !/^[a-f0-9]{64}$/.test(assertion) ||
          (action === "link" && b.organization_id !== QDIP_ZITADEL_ORG)
        ) return refuse(403);
        const purpose = action === "list" ? "qdip-core-org-list/v1" : "qdip-core-org-link/v1";
        const org = action === "link" ? QDIP_ZITADEL_ORG : "";
        const expected = hmac(Bun.env.RR_STAGING_OWNER_RELAY_SECRET!, purpose, issuer, org, sub, ts, nonce);
        if (!matchHmac(expected, assertion)) return refuse(403);
        const nonceKey = action + ":" + nonce;
        const now = Date.now();
        for (const [k, expiry] of seen) if (expiry <= now) seen.delete(k);
        if (seen.has(nonceKey)) return refuse(403);
        seen.set(nonceKey, now + 61000);
        if (seen.size > 1024) seen.delete(seen.keys().next().value!);
        const forwarded = {
          issuer, authenticated_subject: sub, ...(action === "link" ? { organization_id: org } : {}),
          issued_at: ts, nonce,
          assertion: hmac(Bun.env.QDIP_ORG_LINK_ASSERTION_SECRET!, purpose, issuer, org, sub, ts, nonce),
        };
        const path = action === "list" ? "/api/v1/organizations/zitadel-owned" : "/api/v1/organizations/zitadel-link";
        const response = await fetch("https://" + EXPECTED_CORE_DOMAIN + path, {
          method: "POST",
          headers: { "x-api-key": Bun.env.CORE_API_KEY!, "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(forwarded), redirect: "error", signal: AbortSignal.timeout(12000),
        });
        if (!response.ok) {
          await response.body?.cancel();
          return refuse(response.status === 403 ? 403 : 503);
        }
        const text = await response.text();
        if (text.length > 16384) return refuse(503);
        const result: unknown = JSON.parse(text);
        if (action === "list") {
          if (!result || typeof result !== "object" || !("organizations" in result) ||
              !Array.isArray(result.organizations) || result.organizations.length > 100) return refuse(503);
          const organizations = result.organizations.filter((v: unknown) =>
            v && typeof v === "object" && "id" in v && v.id === QDIP_ZITADEL_ORG &&
            "state" in v && v.state === "active" && "name" in v && typeof v.name === "string");
          if (organizations.length > 1) return refuse(503);
          return json({ organizations });
        }
        if (
          !result || typeof result !== "object" || !("id" in result) ||
          typeof result.id !== "string" ||
          !/^[a-f0-9]{8}-[a-f0-9-]{27,36}$/i.test(result.id) ||
          !("identity_provider" in result) || result.identity_provider !== "zitadel" ||
          !("zitadel_issuer" in result) || result.zitadel_issuer !== issuer ||
          !("zitadel_organization_id" in result) || result.zitadel_organization_id !== org ||
          !("name" in result) || typeof result.name !== "string"
        ) return refuse(503);
        return json({
          linked: true, coreTenantId: result.id,
          organization: { id: org, name: result.name, state: "active" },
          pluginMigrationComplete: false,
        });
      } catch {
        return refuse(503);
      }
    },
  });
  console.log("RR_STAGING_OWNER_BRIDGE_STARTED");
  // Read-only, sanitized staging inventory: no credentials or subjects in logs.
  // Confirm the exact Zitadel-linked tenant after the owner-authorized POST.
  void (async () => {
    try {
      const response = await fetch("https://" + EXPECTED_CORE_DOMAIN + "/api/v1/organizations", {
        headers: { "x-api-key": Bun.env.CORE_API_KEY! },
        redirect: "error", signal: AbortSignal.timeout(8000),
      });
      if (!response.ok) { console.log("RR_STAGING_QDIP_ORG_READBACK_HTTP", response.status); return; }
      const raw = await response.text();
      if (raw.length > 64_000) { console.log("RR_STAGING_QDIP_ORG_READBACK=INVALID_SIZE"); return; }
      const records: unknown = JSON.parse(raw);
      if (!Array.isArray(records)) { console.log("RR_STAGING_QDIP_ORG_READBACK=INVALID_SHAPE"); return; }
      const linked = records.filter((v: unknown) =>
        v && typeof v === "object" &&
        "identity_provider" in v && v.identity_provider === "zitadel" &&
        "zitadel_organization_id" in v && v.zitadel_organization_id === QDIP_ZITADEL_ORG &&
        "zitadel_issuer" in v && v.zitadel_issuer === EXPECTED_ISSUER &&
        "status" in v && v.status === "active"
      );
      if (linked.length !== 1 || typeof linked[0].id !== "string" ||
          !/^[a-f0-9]{8}-[a-f0-9-]{27,36}$/i.test(linked[0].id)) {
        console.log("RR_STAGING_QDIP_ORG_READBACK=" + (linked.length === 0 ? "ABSENT" : "AMBIGUOUS"));
        return;
      }
      console.log("RR_STAGING_QDIP_ORG_READBACK=PASS", linked[0].id);
    } catch { console.log("RR_STAGING_QDIP_ORG_READBACK=UNAVAILABLE"); }
  })();
} else {
// One-shot staging bootstrap. Prints only non-secret IDs and HTTP statuses.
const base = `https://${Bun.env.CORE_DOMAIN}`;
const key = Bun.env.CORE_API_KEY ?? "";

async function status(apiKey: string): Promise<number> {
  const r = await fetch(`${base}/api/v1/organizations`, { headers: { "x-api-key": apiKey } });
  await r.body?.cancel();
  return r.status;
}

if (!Bun.env.CORE_DOMAIN || key.length < 32) {
  console.log("BOOTSTRAP not configured yet");
} else {
  console.log("CHECK invalid-key status", await status("not-a-real-key"));
  console.log("CHECK dev-default-key status", await status("dev-api-key"));
  console.log("CHECK generated-key length", key.length, "status", await status(key));

  const list = await fetch(`${base}/api/v1/organizations`, { headers: { "x-api-key": key } });
  const orgs = await list.json();
  let org = Array.isArray(orgs) ? orgs.find((o: any) => o.name === "QDIP SDK staging") : null;
  if (!org) {
    const r = await fetch(`${base}/api/v1/organizations`, {
      method: "POST",
      headers: { "x-api-key": key, "content-type": "application/json" },
      body: JSON.stringify({ name: "QDIP SDK staging" }),
    });
    console.log("CREATE status", r.status);
    org = await r.json();
  }
  console.log("STAGING_ORG_ID", org?.id);
}

}

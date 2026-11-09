
import { SQL } from "bun";
const connection = Bun.env.RR_TEST_POSTGRES_DSN;
if (!connection || !new URL(connection).pathname.endsWith("/rr_test")) throw new Error("RR_QA_BLOCKED: dedicated rr_test required");
const db = new SQL(connection);
const expected=["schema","initial","duplicate-head","cas-concurrency","tenant-isolation","unique-change-rollback","snapshot","export","record-readback-equality"];
const passed=[];
function ok(condition,name){if (!condition) throw new Error("RR_QA_FAIL:"+name); passed.push(name); console.log("RR_QA_PASS:"+name);}
function record(org, exec, decision,changeId=null){
 return {organization_id:org,actor_id:"qa",result:{workflow:{execution_id:exec,ingestion:{payload:{decision_id:decision}},change:changeId?{change_id:changeId}:null}}};
}
async function initial(org,dec,exec) {
 try { return await db.begin(async tx=>{
  const h=await tx`INSERT INTO rr_decision_heads (organization_id,decision_id,head_execution_id,head_payload_digest) VALUES (${org},${dec},${exec},${"a".repeat(64)}) ON CONFLICT (organization_id,decision_id) DO NOTHING RETURNING head_execution_id`;
  if(h.length===0) return "conflict";
  await tx`INSERT INTO rr_execution_records (organization_id,execution_id,decision_id,change_id,predecessor_execution_id,payload_digest,created_at,record) VALUES (${org},${exec},${dec},${null},${null},${"a".repeat(64)},${new Date()},${JSON.stringify(record(org,exec,dec))}::jsonb)`;
  return "created";
 });}catch(e){ if(e?.code==="23505")return "conflict"; throw e;}
}
async function advance(org,dec,prev,prevHash,exec,changeId){
 try {return await db.begin(async tx=>{
  const h=await tx`UPDATE rr_decision_heads SET head_execution_id=${exec},head_payload_digest=${"b".repeat(64)} WHERE organization_id=${org} AND decision_id=${dec} AND head_execution_id=${prev} AND head_payload_digest=${prevHash} RETURNING head_execution_id`;
  if(h.length===0)return "stale_predecessor";
  await tx`INSERT INTO rr_execution_records (organization_id,execution_id,decision_id,change_id,predecessor_execution_id,payload_digest,created_at,record) VALUES (${org},${exec},${dec},${changeId},${prev},${"b".repeat(64)},${new Date()},${JSON.stringify(record(org,exec,dec,changeId))}::jsonb)`;
  return "created";
 });}catch(e){if(e?.code==="23505" || String(e?.message || "").includes('duplicate key value violates unique constraint "rr_unique_operator_change_v1"'))return "conflict";throw e;}
}
const readbackExecution = Bun.env.RR_E2E_READBACK_EXECUTION_ID;
if (readbackExecution) {
 try {
  const organization = Bun.env.RR_E2E_READBACK_ORGANIZATION_ID ?? "";
  const rawExpected = Bun.env.RR_E2E_EXPECTED_RECORD_JSON ?? "";
  if (!/^[A-Za-z0-9_.-]{1,128}$/.test(readbackExecution)
      || !/^[0-9a-f]{8}-[0-9a-f-]{27,36}$/i.test(organization)
      || rawExpected.length === 0 || rawExpected.length > 1000000) {
   throw new Error("RR_E2E_READBACK_INVALID_BOUND_INPUT");
  }
  const expected = JSON.parse(rawExpected);
  const kind = Bun.env.RR_E2E_READBACK_KIND ?? "scheduling";
  if (!["scheduling", "scenario"].includes(kind)) {
   throw new Error("RR_E2E_READBACK_KIND_INVALID");
  }
  if (kind === "scenario") {
   if (expected?.execution_id !== readbackExecution
       || expected?.schema_version !== "readiness-recovery.economic-scenario-preview.v1"
       || expected?.actionable !== false || expected?.supply_source_verified !== false) {
    throw new Error("RR_E2E_READBACK_EXPECTED_SCENARIO_INVALID");
   }
   const rows = await db`SELECT (record->'response' = ${rawExpected}::jsonb) AS identical
                         FROM rr_economic_scenario_advice_archive
                         WHERE organization_id=${organization} AND execution_id=${readbackExecution}`;
   if (rows.length !== 1 || rows[0].identical !== true) {
    throw new Error("RR_E2E_READBACK_PERSISTED_SCENARIO_MISMATCH");
   }
  } else {
   if (expected?.organization_id !== organization
       || expected?.result?.workflow?.execution_id !== readbackExecution) {
    throw new Error("RR_E2E_READBACK_EXPECTED_IDENTITY_MISMATCH");
   }
   const rows = await db`SELECT (record = ${rawExpected}::jsonb) AS identical
                         FROM rr_execution_records
                         WHERE organization_id=${organization} AND execution_id=${readbackExecution}`;
   if (rows.length !== 1 || rows[0].identical !== true) {
    throw new Error("RR_E2E_READBACK_PERSISTED_RECORD_MISMATCH");
   }
  }
    const foreign = await db`SELECT organization_id, execution_id FROM rr_execution_records
                           WHERE organization_id <> ${organization}
                           ORDER BY execution_id LIMIT 1`;
  if (foreign.length !== 1) throw new Error("RR_E2E_REAL_FOREIGN_RECORD_MISSING");
  // The identifier stays in Railway-only deployment logs; CI consumes it
  // without printing it or querying PostgreSQL over the public internet.
  console.log("RR_E2E_FOREIGN_RECORD_B64=" +
              Buffer.from(JSON.stringify(foreign[0])).toString("base64"));
  console.log("RR_E2E_INDEPENDENT_POSTGRES_READBACK=PASS");
 } catch (err) {
  console.error("RR_E2E_INDEPENDENT_POSTGRES_READBACK=FAIL", String(err instanceof Error ? err.message : err));
  process.exitCode = 1;
 } finally {
  await db.close();
 }
} else {
try {
 const migration="-- RR-owned schema. Apply only to a dedicated RR PostgreSQL database.\n-- This migration does not touch Core or any MongoDB collection.\nCREATE TABLE IF NOT EXISTS rr_decision_heads (\n    organization_id text NOT NULL,\n    decision_id text NOT NULL,\n    head_execution_id text NOT NULL,\n    head_payload_digest char(64) NOT NULL CHECK (head_payload_digest ~ '^[0-9a-f]{64}$'),\n    PRIMARY KEY (organization_id, decision_id)\n);\n\nCREATE TABLE IF NOT EXISTS rr_execution_records (\n    organization_id text NOT NULL,\n    execution_id text NOT NULL,\n    decision_id text NOT NULL,\n    change_id text,\n    predecessor_execution_id text,\n    payload_digest char(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),\n    created_at timestamptz NOT NULL,\n    record jsonb NOT NULL,\n    PRIMARY KEY (organization_id, execution_id)\n);\n\nCREATE UNIQUE INDEX IF NOT EXISTS rr_unique_operator_change_v1\n    ON rr_execution_records (organization_id, decision_id, change_id)\n    WHERE change_id IS NOT NULL;\n\nCREATE INDEX IF NOT EXISTS rr_tenant_decision_history_v1\n    ON rr_execution_records (organization_id, decision_id, created_at, execution_id);\n\nCREATE INDEX IF NOT EXISTS rr_tenant_decision_export_v1\n    ON rr_execution_records (organization_id, decision_id, execution_id);\n";
 for(const statement of migration.split(";").map(s=>s.trim()).filter(Boolean)) await db.unsafe(statement);
 const scenarioMigration = "CREATE TABLE IF NOT EXISTS rr_economic_scenario_advice_archive (" +
  "organization_id text NOT NULL, execution_id text NOT NULL, snapshot_id text NOT NULL, " +
  "snapshot_digest char(64) NOT NULL CHECK (snapshot_digest ~ ('^[0-9a-f]{64}' || chr(36))), " +
  "record jsonb NOT NULL, PRIMARY KEY (organization_id, execution_id))";
 await db.unsafe(scenarioMigration);
 const tables=await db`SELECT count(*)::int AS n FROM pg_tables WHERE schemaname=current_schema() AND tablename IN ('rr_decision_heads','rr_execution_records')`;
 ok(tables[0].n===2,"schema");
 const org="rrqa-"+crypto.randomUUID();const org2="rrqa-"+crypto.randomUUID();const dec="rr-test";
 ok(await initial(org,dec,"e1")==="created","initial");
 ok(await initial(org,dec,"e-other")==="conflict","duplicate-head");
 const r=await Promise.all([advance(org,dec,"e1","a".repeat(64),"e2","c2"),advance(org,dec,"e1","a".repeat(64),"e3","c3")]);
 const head=await db`SELECT head_execution_id,head_payload_digest FROM rr_decision_heads WHERE organization_id=${org} AND decision_id=${dec}`;
 const hist=await db`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec} ORDER BY execution_id`;
 ok(r.includes("created")&&r.includes("stale_predecessor")&&hist.length===2&&head[0].head_execution_id===hist[1].execution_id,"cas-concurrency");
 await initial(org2,dec,"e1");
 const other=await db`SELECT count(*)::int AS n FROM rr_execution_records WHERE organization_id=${org2} AND decision_id=${dec}`;
 ok(other[0].n===1&&hist.length===2,"tenant-isolation");
 const oldHead=head[0].head_execution_id;
 const duplicate=await advance(org,dec,oldHead,"b".repeat(64),"e4",hist[1].execution_id==="e2"?"c2":"c3");
 const after=await db`SELECT head_execution_id FROM rr_decision_heads WHERE organization_id=${org} AND decision_id=${dec}`;
 ok(duplicate==="conflict"&&after[0].head_execution_id===oldHead,"unique-change-rollback");
 const snap=await db.begin(async tx=>{await tx.unsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");const h=await tx`SELECT head_execution_id FROM rr_decision_heads WHERE organization_id=${org} AND decision_id=${dec}`; const rows=await tx`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec}`;return {h:h[0].head_execution_id,n:rows.length};});
 ok(snap.h===oldHead&&snap.n===2,"snapshot");
 const first=await db`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec} ORDER BY execution_id LIMIT 1`;
 const next=await db`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec} AND execution_id > ${first[0].execution_id} ORDER BY execution_id LIMIT 1`;
 ok(first.length===1&&next.length===1&&first[0].execution_id!==next[0].execution_id,"export");
 const readbackOk=await db`SELECT (record = ${JSON.stringify(record(org,"e1",dec))}::jsonb) AS identical FROM rr_execution_records WHERE organization_id=${org} AND execution_id=${"e1"}`;
 const negative=await db`SELECT (record = ${JSON.stringify({...record(org,"e1",dec), actor_id:"wrong-actor"})}::jsonb) AS identical FROM rr_execution_records WHERE organization_id=${org} AND execution_id=${"e1"}`;
 ok(readbackOk.length===1&&readbackOk[0].identical===true&&negative.length===1&&negative[0].identical===false,"record-readback-equality");
 console.log("RR_QA_RESULT:PASS "+passed.length+"/"+expected.length);
} catch(e){console.error("RR_QA_RESULT:FAIL",String(e?.message || e));process.exitCode=1;}
finally{await db.close();}

}
), record jsonb NOT NULL, PRIMARY KEY (organization_id, execution_id))";
 await db.unsafe(scenarioMigration);
 const tables=await db`SELECT count(*)::int AS n FROM pg_tables WHERE schemaname=current_schema() AND tablename IN ('rr_decision_heads','rr_execution_records')`;
 ok(tables[0].n===2,"schema");
 const org="rrqa-"+crypto.randomUUID();const org2="rrqa-"+crypto.randomUUID();const dec="rr-test";
 ok(await initial(org,dec,"e1")==="created","initial");
 ok(await initial(org,dec,"e-other")==="conflict","duplicate-head");
 const r=await Promise.all([advance(org,dec,"e1","a".repeat(64),"e2","c2"),advance(org,dec,"e1","a".repeat(64),"e3","c3")]);
 const head=await db`SELECT head_execution_id,head_payload_digest FROM rr_decision_heads WHERE organization_id=${org} AND decision_id=${dec}`;
 const hist=await db`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec} ORDER BY execution_id`;
 ok(r.includes("created")&&r.includes("stale_predecessor")&&hist.length===2&&head[0].head_execution_id===hist[1].execution_id,"cas-concurrency");
 await initial(org2,dec,"e1");
 const other=await db`SELECT count(*)::int AS n FROM rr_execution_records WHERE organization_id=${org2} AND decision_id=${dec}`;
 ok(other[0].n===1&&hist.length===2,"tenant-isolation");
 const oldHead=head[0].head_execution_id;
 const duplicate=await advance(org,dec,oldHead,"b".repeat(64),"e4",hist[1].execution_id==="e2"?"c2":"c3");
 const after=await db`SELECT head_execution_id FROM rr_decision_heads WHERE organization_id=${org} AND decision_id=${dec}`;
 ok(duplicate==="conflict"&&after[0].head_execution_id===oldHead,"unique-change-rollback");
 const snap=await db.begin(async tx=>{await tx.unsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");const h=await tx`SELECT head_execution_id FROM rr_decision_heads WHERE organization_id=${org} AND decision_id=${dec}`; const rows=await tx`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec}`;return {h:h[0].head_execution_id,n:rows.length};});
 ok(snap.h===oldHead&&snap.n===2,"snapshot");
 const first=await db`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec} ORDER BY execution_id LIMIT 1`;
 const next=await db`SELECT execution_id FROM rr_execution_records WHERE organization_id=${org} AND decision_id=${dec} AND execution_id > ${first[0].execution_id} ORDER BY execution_id LIMIT 1`;
 ok(first.length===1&&next.length===1&&first[0].execution_id!==next[0].execution_id,"export");
 const readbackOk=await db`SELECT (record = ${JSON.stringify(record(org,"e1",dec))}::jsonb) AS identical FROM rr_execution_records WHERE organization_id=${org} AND execution_id=${"e1"}`;
 const negative=await db`SELECT (record = ${JSON.stringify({...record(org,"e1",dec), actor_id:"wrong-actor"})}::jsonb) AS identical FROM rr_execution_records WHERE organization_id=${org} AND execution_id=${"e1"}`;
 ok(readbackOk.length===1&&readbackOk[0].identical===true&&negative.length===1&&negative[0].identical===false,"record-readback-equality");
 console.log("RR_QA_RESULT:PASS "+passed.length+"/"+expected.length);
} catch(e){console.error("RR_QA_RESULT:FAIL",String(e?.message || e));process.exitCode=1;}
finally{await db.close();}

}

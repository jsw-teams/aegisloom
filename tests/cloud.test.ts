import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";
import { UpdateFirewallConfigRequestBody$outboundSchema } from "@vercel/sdk/models/updatefirewallconfigop.js";
import { CloudflareGateway } from "../adapters/cloudflare/index.js";
import { createEdgeOneGateway, EdgeOneGateway } from "../adapters/edgeone/index.js";
import { createEsaSdkGateway, EsaGateway } from "../adapters/esa/index.js";
import { VercelGateway } from "../adapters/vercel/index.js";
import {
  createCloudflareAdapter,
  createEdgeOneAdapter,
  createEsaAdapter,
  createNetlifyAdapter,
  createVercelAdapter,
  type NativeGateway,
  type NativeRule,
} from "../packages/cloud-compiler/index.js";
import { syncCloud } from "../packages/control-plane/cloud-sync.js";
import { stableJson } from "../packages/core/types.js";
import { loadPolicy } from "../packages/rule-ir/index.js";
import { attackRule } from "./helpers.js";

class FakeGateway implements NativeGateway {
  target = "offline-test-only";
  rules: NativeRule[] = [];
  writes = 0;
  async list() {
    return structuredClone(this.rules);
  }
  async replace(rules: NativeRule[]) {
    this.writes++;
    this.rules = structuredClone(rules).map((r, i) => ({ ...r, id: String(i) }));
  }
}
const nativePolicy = () =>
  loadPolicy({
    version: "1",
    rules: [
      {
        ...attackRule,
        cache: { enabled: false, ttl: "1m" },
        placement: "edge-preferred",
        when: {
          any: [
            { field: "method", op: "eq", value: "DELETE" },
            { field: "client.ip", op: "eq", value: "8.8.8.8" },
          ],
        },
      },
    ],
  });
const approve = (hash: string) => ({
  planHash: hash,
  approvedBy: "test-operator",
  expiresAt: Date.now() + 60000,
});

test("all five adapters expose full lifecycle, strict compatibility and no false equivalence", async () => {
  const config = { tenant: "t", service: "api", maxRules: 5, gateway: new FakeGateway() };
  for (const adapter of [
    createCloudflareAdapter(config),
    createEsaAdapter(config),
    createVercelAdapter(config),
    createEdgeOneAdapter(config),
  ]) {
    assert.equal(adapter.compile(nativePolicy().rules[0]!).status, "exact");
    const unsupported = loadPolicy({ version: "1", rules: [attackRule] }).rules[0]!;
    assert.equal(adapter.compile(unsupported).status, "runtime-only");
    assert.equal(
      adapter.compile({ ...unsupported, placement: "edge-required" }).status,
      "unsupported",
    );
    assert.equal(adapter.capabilities().verifiedLive, false);
    await assert.rejects(
      adapter.plan(
        loadPolicy({ version: "1", rules: [{ ...attackRule, placement: "edge-required" }] }),
      ),
      /incompatible/,
    );
  }
  const netlify = createNetlifyAdapter("t", "api");
  assert.equal(netlify.capabilities().management, false);
  await assert.rejects(netlify.readback(), /unsupported/);
  await assert.rejects(netlify.revoke("r"), /unsupported/);
});
test("plan approval, readback, drift, capacity, revocation and tenant namespaces", async () => {
  const gateway = new FakeGateway();
  const a = createCloudflareAdapter({ tenant: "a", service: "api", maxRules: 5, gateway });
  const b = createCloudflareAdapter({ tenant: "b", service: "api", maxRules: 5, gateway });
  const plan = await a.plan(nativePolicy());
  await assert.rejects(a.apply(plan, approve("wrong")), /approval/);
  await assert.rejects(a.apply({ ...plan, desired: [] }, approve(plan.hash)), /approval/);
  await a.apply(plan, approve(plan.hash));
  assert.equal((await a.reconcile(plan)).drift, false);
  const other = await b.plan(nativePolicy());
  await b.apply(other, approve(other.hash));
  assert.equal(gateway.rules.length, 2);
  assert.equal((await a.reconcile(plan)).drift, true);
  await assert.rejects(a.apply(plan, approve(plan.hash)), /drift/);
  const removal = await a.revoke("query-attack");
  await a.apply(removal, approve(removal.hash));
  assert.equal(gateway.rules.length, 1);
  assert.ok(gateway.rules[0]?.name.startsWith(other.namespace));
  const small = createCloudflareAdapter({ tenant: "c", service: "api", maxRules: 1, gateway });
  await assert.rejects(small.plan(nativePolicy()), /capacity/);
});
test("retry re-plans after an ambiguous apply and never issues per-request management calls", async () => {
  const gateway = new FakeGateway();
  let failed = false;
  const replace = gateway.replace.bind(gateway);
  gateway.replace = async (rules) => {
    await replace(rules);
    if (!failed) {
      failed = true;
      throw new Error("lost response");
    }
  };
  const adapter = createEsaAdapter({ tenant: "t", service: "api", maxRules: 10, gateway });
  const log: unknown[] = [];
  const result = await syncCloud(
    adapter,
    nativePolicy(),
    async (p) => approve(p.hash),
    async (e) => {
      log.push(e);
    },
  );
  assert.equal(result.status, "confirmed");
  assert.equal(gateway.rules.length, 1);
  assert.equal(log.length, 4);
});
test("Cloudflare real REST paths, ownership, retry, readback and delete contract", async () => {
  let rules: any[] = [];
  let reads = 0;
  const calls: string[] = [];
  const gateway = new CloudflareGateway(
    "a".repeat(32),
    "b".repeat(32),
    "never-logged-token",
    async (url, init) => {
      const u = String(url);
      calls.push(`${init?.method} ${u}`);
      if (init?.method === "GET") {
        if (++reads === 1) return new Response(null, { status: 429 });
        return Response.json({
          success: true,
          result: { phase: "http_request_firewall_custom", rules },
        });
      }
      if (init?.method === "POST")
        rules.push({ ...JSON.parse(String(init.body)), id: "native-id" });
      if (init?.method === "DELETE") rules = [];
      return Response.json({ success: true, result: {} });
    },
  );
  const adapter = createCloudflareAdapter({ tenant: "t", service: "api", maxRules: 5, gateway });
  const p = await adapter.plan(nativePolicy());
  await adapter.apply(p, approve(p.hash));
  const r = await adapter.revoke("query-attack");
  await adapter.apply(r, approve(r.hash));
  assert.equal(rules.length, 0);
  assert.ok(calls.some((s) => s.includes("/rules/native-id")));
  assert.ok(reads >= 2);
});
test("ESA SDK contract uses typed API requests, scoped pagination and real lifecycle", async () => {
  const require = createRequire(import.meta.url);
  const sdk = require("@alicloud/esa20240910");
  let rules: any[] = [];
  const seen: Record<string, unknown>[] = [];
  const gateway = new EsaGateway(
    {
      list: async (args) => {
        new sdk.ListWafRulesRequest(args).validate();
        seen.push(args);
        return { rules, totalCount: rules.length };
      },
      create: async (args) => {
        new sdk.CreateWafRuleRequest(args).validate();
        rules.push({ id: 12, rulesetId: 2, phase: "http_custom", config: args.config });
      },
      update: async (args) => {
        new sdk.UpdateWafRuleRequest(args).validate();
        rules[0].config = args.config;
      },
      remove: async (args) => {
        new sdk.DeleteWafRuleRequest(args).validate();
        rules = [];
      },
    },
    1,
    2,
  );
  const adapter = createEsaAdapter({ tenant: "t", service: "api", maxRules: 10, gateway });
  const p = await adapter.plan(nativePolicy());
  await adapter.apply(p, approve(p.hash));
  const r = await adapter.revoke("query-attack");
  await adapter.apply(r, approve(r.hash));
  assert.equal(rules.length, 0);
  assert.ok(seen.every((a) => a.siteId === 1 && a.phase === "http_custom"));
  assert.ok(
    createEsaSdkGateway({
      accessKeyId: "offline",
      accessKeySecret: "offline",
      region: "cn-hangzhou",
      siteId: 1,
      rulesetId: 2,
    }),
  );
});
test("EdgeOne API contract preserves unrelated rules when replacing CustomRules", async () => {
  const preserved = {
    Id: "unowned",
    Name: "manual",
    Condition: "condition",
    Action: { Name: "Deny" },
    Enabled: "on",
    Priority: 50,
    CustomExtension: "preserve-me",
  };
  let rules: any[] = [preserved];
  const gateway = new EdgeOneGateway(
    {
      describe: async () => ({ SecurityPolicy: { CustomRules: { Rules: rules } } }),
      modify: async (args) => {
        assert.equal(args.Entity, "Template");
        assert.equal(args.TemplateId, "template-id");
        rules = args.SecurityPolicy.CustomRules.Rules.map((r: any) => ({
          ...r,
          Id: r.Id ?? "assigned",
        }));
      },
    },
    "zone-id",
    "template-id",
  );
  const adapter = createEdgeOneAdapter({ tenant: "t", service: "api", maxRules: 10, gateway });
  const p = await adapter.plan(nativePolicy());
  await adapter.apply(p, approve(p.hash));
  assert.equal(stableJson(rules.find((r) => r.Id === "unowned")), stableJson(preserved));
  const r = await adapter.revoke("query-attack");
  await adapter.apply(r, approve(r.hash));
  assert.equal(rules.length, 1);
  assert.ok(
    createEdgeOneGateway({
      secretId: "offline",
      secretKey: "offline",
      zoneId: "zone-id",
      templateId: "template-id",
      endpoint: "teo.tencentcloudapi.com",
    }),
  );
});
test("Vercel REST contract validates against pinned SDK and activates only its new draft", async () => {
  let active: any = { firewallEnabled: true, version: 1, rules: [] };
  const draft = structuredClone(active);
  const calls: string[] = [];
  const gateway = new VercelGateway("project", "team", "token", async (url, init) => {
    const path = new URL(String(url)).pathname;
    calls.push(`${init?.method} ${path}`);
    if (init?.method === "GET") return Response.json(path.endsWith("/active") ? active : draft);
    if (init?.method === "PATCH") {
      const body = JSON.parse(String(init.body));
      assert.equal(UpdateFirewallConfigRequestBody$outboundSchema.safeParse(body).success, true);
      draft.version++;
      if (body.action === "rules.insert") draft.rules.push({ ...body.value, id: "native-rule" });
      if (body.action === "rules.remove")
        draft.rules = draft.rules.filter((r: any) => r.id !== body.id);
    }
    if (path.endsWith("/activate")) {
      active = structuredClone(draft);
    }
    return Response.json({});
  });
  const adapter = createVercelAdapter({ tenant: "t", service: "api", maxRules: 5, gateway });
  const p = await adapter.plan(nativePolicy());
  await adapter.apply(p, approve(p.hash));
  assert.ok(calls.some((c) => c.includes("POST") && c.endsWith("/activate")));
  const r = await adapter.revoke("query-attack");
  await adapter.apply(r, approve(r.hash));
  assert.equal(active.rules.length, 0);
  draft.version++;
  const refused = await adapter.plan(nativePolicy());
  await assert.rejects(adapter.apply(refused, approve(refused.hash)), /Unrelated/);
});

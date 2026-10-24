import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AdaptiveLearner,
  anomalyCandidate,
  diffAssets,
  discoverOpenApi,
  type Observation,
  RuleRollout,
} from "../packages/learning/index.js";

const observation = (source: string, overrides: Partial<Observation> = {}): Observation => ({
  tenant: "t",
  path: "/api",
  method: "POST",
  at: 1000,
  source,
  trust: "verified",
  bodyBytes: 100,
  status: 200,
  fields: { name: "string" },
  ...overrides,
});

test("trusted multi-source API discovery, bounded source contribution and EWMA explanation", () => {
  const learner = new AdaptiveLearner("t", ["ci", "contract", "operator"], 100, 3);
  for (let i = 0; i < 50; i++) learner.observe(observation("ci"));
  assert.equal(learner.stagedCount, 3);
  learner.observe(observation("contract"));
  learner.observe(observation("operator"));
  const model = learner.train();
  assert.equal(model.routes.length, 1);
  assert.equal(model.routes[0]?.samples, 3);
  assert.equal(model.routes[0]?.meanBytes, 100);
  const anomaly = learner.score(
    observation("ci", { bodyBytes: 20000, status: 500, fields: { injection: "object" } }),
  );
  assert.ok(anomaly.score >= 50);
  assert.ok(anomaly.reasons.length >= 2);
  assert.equal(learner.observe(observation("ci", { bodyBytes: 20000 })).accepted, false);
});
test("untrusted traffic cannot poison baseline; source registry and freeze/rollback enforced", () => {
  const learner = new AdaptiveLearner("t", ["ci", "contract", "operator"]);
  learner.observe(observation("unregistered", { bodyBytes: 999999 }));
  learner.observe(observation("ci", { trust: "candidate", bodyBytes: 999999 }));
  learner.observe(observation("ci"));
  learner.train();
  assert.equal(learner.snapshot().routes.length, 0);
  assert.equal(learner.candidateCount, 2);
  for (const source of ["ci", "contract", "operator"]) learner.observe(observation(source));
  learner.train();
  assert.equal(learner.snapshot().routes.length, 1);
  learner.freeze();
  assert.equal(learner.observe(observation("ci")).accepted, false);
  assert.throws(() => learner.train());
  assert.equal(learner.rollback(1).routes.length, 0);
  assert.equal(learner.snapshot().frozen, true);
});
test("OpenAPI discovery distinguishes undeclared vs unobserved without resolving remote refs", () => {
  const assets = discoverOpenApi({
    openapi: "3.1.0",
    paths: {
      "/api": { post: { security: [{ apiKey: [] }] } },
      "/public": { get: { security: [] } },
    },
  });
  assert.equal(assets[0]?.authenticated, true);
  assert.equal(assets[1]?.authenticated, false);
  assert.deepEqual(diffAssets(assets, [{ path: "/new", method: "GET" }]).undeclared, ["GET /new"]);
  assert.throws(() =>
    discoverOpenApi({ openapi: "3.0.0", paths: { "/api": { $ref: "https://evil/schema" } } }),
  );
});
test("candidate verification, shadow, deterministic canary and false-positive rollback", async () => {
  const rollout = new RuleRollout(anomalyCandidate("api", "/api", "POST"), 2, 1);
  assert.equal(await rollout.shouldEnforce("user"), false);
  assert.throws(() => rollout.verify());
  const pass = () => {
    rollout.record(false, false);
    rollout.record(false, false);
    rollout.record(true, true);
  };
  pass();
  rollout.verify();
  rollout.shadow();
  assert.throws(() => rollout.canary(10));
  pass();
  rollout.canary(10);
  assert.equal(await rollout.shouldEnforce("user"), await rollout.shouldEnforce("user"));
  assert.throws(() => rollout.deploy());
  pass();
  rollout.deploy();
  assert.equal(await rollout.shouldEnforce("user"), true);
  rollout.record(false, true);
  assert.equal(rollout.snapshot().stage, "revoked");
  assert.equal(await rollout.shouldEnforce("user"), false);
});

import { MemoryDecisionStore } from "../decision-cache/index.js";
import type { Policy } from "../rule-ir/index.js";
import { createShield } from "../runtime/index.js";

export interface RegressionSample {
  name: string;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  identity?: string;
  expectedStatus: number;
  kind: "attack" | "legitimate";
}

/** Executes the real runtime with an in-process origin. No sample can trigger network traffic. */
export async function verifySourcePolicy(policy: Policy, input: unknown): Promise<number> {
  if (!Array.isArray(input) || input.length < 2 || input.length > 1000)
    throw new Error("Require 2..1000 regression samples");
  let attacks = 0,
    legitimate = 0;
  for (const raw of input) {
    const sample = raw as RegressionSample;
    if (
      !sample ||
      typeof sample.url !== "string" ||
      typeof sample.name !== "string" ||
      sample.name.length > 128 ||
      !["attack", "legitimate"].includes(sample.kind) ||
      !Number.isInteger(sample.expectedStatus)
    )
      throw new Error("Invalid regression sample");
    const url = new URL(sample.url);
    if (
      url.origin !== "https://simulation.test" ||
      url.username ||
      url.password ||
      url.hash ||
      url.href.length > 8192 ||
      (sample.body?.length ?? 0) > 65536
    )
      throw new Error("Invalid regression target or body");
    if (sample.kind === "attack") {
      if (![403, 429].includes(sample.expectedStatus)) throw new Error("Attack must be blocked");
      attacks++;
    } else {
      if (sample.expectedStatus !== 204) throw new Error("Legitimate sample must reach the origin");
      legitimate++;
    }
    // Each test is isolated: a previous cached IP block cannot mask a nonmatching attack rule.
    const matched: string[] = [];
    const runtime = await createShield({
      tenant: "regression",
      service: policy.rules[0]?.service ?? "api",
      publicHosts: ["simulation.test"],
      policy,
      decisions: new MemoryDecisionStore(),
      event: (event) => {
        matched.push(event.source);
      },
      routes: [
        {
          path: url.pathname,
          methods: [sample.method ?? "GET"],
          authenticated: false,
          body: "json",
        },
      ],
      proxy: {
        origin: "https://origin.invalid",
        allowedOrigins: ["https://origin.invalid"],
        originToken: "offline-regression-origin-token-32-characters",
        fetch: async () => new Response(null, { status: 204 }),
      },
    });
    const response = await runtime.handle(
      new Request(url, {
        method: sample.method ?? "GET",
        ...(sample.headers ? { headers: sample.headers } : {}),
        ...(sample.body === undefined ? {} : { body: sample.body }),
      }),
      {
        tenant: "regression",
        verifiedClientIp: "192.0.2.1",
        ...(sample.identity ? { identity: sample.identity } : {}),
      },
    );
    await response.body?.cancel();
    if (response.status !== sample.expectedStatus) throw new Error("Source regression failed");
    if (sample.kind === "attack" && !matched.includes("rule"))
      throw new Error("Attack regression must exercise the imported policy");
  }
  if (!attacks || !legitimate) throw new Error("Attack and legitimate samples are both required");
  return input.length;
}

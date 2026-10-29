import deployment from "edgeaegis:deployment";
import createOriginFetches from "edgeaegis:origin";
import { INJECTION, PCRE2 } from "edgeaegis:wasm";
import { createCloudflareRuntime } from "./runtime.js";

// Cloudflare charges module initialization separately from request execution.
const runtime = await createCloudflareRuntime({
  ...deployment,
  pcre2: PCRE2,
  libinjection: INJECTION,
  originFetches: createOriginFetches(),
});
export default {
  async fetch(request: Request, env: Record<string, unknown>) {
    try {
      return await runtime.handle(request, createOriginFetches(env));
    } catch {
      return Response.json(
        { error: "shield_unavailable" },
        { status: 503, headers: { "cache-control": "no-store" } },
      );
    }
  },
};

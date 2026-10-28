import deployment from "edgeshield:deployment";
import originFetches from "edgeshield:origin";
import { INJECTION, PCRE2 } from "edgeshield:wasm";
import { createCloudflareRuntime } from "./runtime.js";

// Cloudflare charges module initialization separately from request execution.
const runtime = await createCloudflareRuntime({
  ...deployment,
  pcre2: PCRE2,
  libinjection: INJECTION,
  originFetches,
});
export default {
  async fetch(request: Request) {
    try {
      return runtime.handle(request);
    } catch {
      return Response.json(
        { error: "shield_unavailable" },
        { status: 503, headers: { "cache-control": "no-store" } },
      );
    }
  },
};

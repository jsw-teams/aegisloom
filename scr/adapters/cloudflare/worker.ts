import deployment from "edgeshield:deployment";
import originFetches from "edgeshield:origin";
import { INJECTION, PCRE2 } from "edgeshield:wasm";
import { createCloudflareRuntime } from "./runtime.js";

let pending: ReturnType<typeof createCloudflareRuntime> | undefined;
export default {
  async fetch(request: Request) {
    try {
      pending ??= createCloudflareRuntime({
        ...deployment,
        pcre2: PCRE2,
        libinjection: INJECTION,
        originFetches,
      });
      return (await pending).handle(request);
    } catch {
      return Response.json(
        { error: "shield_unavailable" },
        { status: 503, headers: { "cache-control": "no-store" } },
      );
    }
  },
};

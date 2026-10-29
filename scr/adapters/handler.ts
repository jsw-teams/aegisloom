import deployment from "edgeaegis:deployment";
import createOriginFetches from "edgeaegis:origin";
import { INJECTION, PCRE2 } from "edgeaegis:wasm";
import { verifyIngress } from "./ingress.js";
import { createPortableRuntime } from "./runtime.js";

let pending: ReturnType<typeof createPortableRuntime> | undefined;
/** Fetch-only runtimes require signed original transport metadata, never client headers. */
export async function handleCloudRequest(request: Request) {
  try {
    if (!deployment.credentials.ingressKey)
      throw new Error("Configure a trusted ingress signing key");
    const metadata = await verifyIngress(request, deployment.credentials.ingressKey);
    pending ??= createPortableRuntime({
      ...deployment,
      pcre2: PCRE2,
      libinjection: INJECTION,
      originFetches: createOriginFetches(),
    });
    const headers = new Headers(request.headers);
    headers.delete("x-edgeshield-ingress");
    if (metadata.originalUrl) headers.set("host", new URL(metadata.originalUrl).host);
    const inspected = new Request(
      metadata.originalUrl ?? request.url,
      new Request(request, { headers }),
    );
    return (await pending).handle(
      inspected,
      { httpProtocol: metadata.httpProtocol!, verifiedClientIp: metadata.verifiedClientIp! },
      metadata.rawTarget,
    );
  } catch {
    return Response.json(
      { error: "trusted_ingress_required" },
      { status: 503, headers: { "cache-control": "no-store" } },
    );
  }
}

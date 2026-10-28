import type { Fetch } from "../core/types.js";
import { type IngressMetadata, signIngress } from "./ingress.js";
/** Optional transport bridge for platforms whose Fetch API hides the wire protocol. */
export function createIngressForwarder(endpoint: string, secret: string, transport: Fetch = fetch) {
  const destination = new URL(endpoint);
  if (
    destination.protocol !== "https:" ||
    destination.username ||
    destination.password ||
    destination.hash ||
    destination.search ||
    destination.pathname !== "/"
  )
    throw new Error("Ingress destination must be an exact HTTPS origin");
  return async (request: Request, metadata: IngressMetadata) => {
    const original = new URL(request.url);
    if (request.headers.get("host") !== original.host) throw new Error("Ingress Host mismatch");
    const target = new URL(original.pathname + original.search, destination);
    const headers = new Headers(request.headers);
    headers.set("host", target.host);
    headers.delete("x-edgeshield-ingress");
    const forwarded = new Request(target, new Request(request, { headers, redirect: "manual" }));
    forwarded.headers.set(
      "x-edgeshield-ingress",
      await signIngress(forwarded, { ...metadata, originalUrl: request.url }, secret),
    );
    return transport(forwarded);
  };
}

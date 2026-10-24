import { ManagedCloudAdapter } from "../../packages/cloud-compiler/adapter.js";
import type { Capability } from "../../packages/cloud-compiler/types.js";

export const netlifyCapabilities: Capability = {
  provider: "netlify",
  management: false,
  verifiedLive: false,
  maxRules: 0,
  actions: [],
  fields: [],
  limitations: [
    "Traffic Rules provide plan-dependent IP/geography controls",
    "No verified public custom-WAF lifecycle API in the reviewed OpenAPI; native apply/readback/revoke are explicitly unsupported",
    "Deploy the portable Shield runtime in Netlify Functions or Edge Functions; authenticated platform client context must be supplied by the integration",
  ],
};
export function createNetlifyAdapter(tenant: string, service: string) {
  return new ManagedCloudAdapter(netlifyCapabilities, undefined, tenant, service);
}

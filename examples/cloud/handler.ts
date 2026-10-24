import { HttpDecisionStore } from "../../packages/decision-cache/http.js";
import { loadPolicy } from "../../packages/rule-ir/index.js";
import { createShield, type Route, type TrustedContext } from "../../packages/runtime/index.js";

export interface CloudEnvironment {
  TENANT: string;
  SERVICE: string;
  PUBLIC_HOST: string;
  ORIGIN: string;
  ORIGIN_TOKEN: string;
  CONTROL_ORIGIN: string;
  CONTROL_RUNTIME_TOKEN: string;
  /** JSON/YAML IR provisioned by the operator; never read from request input. */
  POLICY: string;
  ROUTES: Route[];
}
/** One engine per configured isolate; management SDKs are deliberately absent from this graph. */
export function makeCloudHandler(environment: CloudEnvironment) {
  const engine = createShield({
    tenant: environment.TENANT,
    service: environment.SERVICE,
    publicHosts: [environment.PUBLIC_HOST],
    routes: environment.ROUTES,
    policy: loadPolicy(environment.POLICY),
    decisions: new HttpDecisionStore(
      environment.CONTROL_ORIGIN,
      environment.CONTROL_RUNTIME_TOKEN,
      environment.TENANT,
    ),
    proxy: {
      origin: environment.ORIGIN,
      allowedOrigins: [environment.ORIGIN],
      originToken: environment.ORIGIN_TOKEN,
    },
  });
  return async (request: Request, verified: Omit<TrustedContext, "tenant"> = {}) =>
    (await engine).handle(request, { ...verified, tenant: environment.TENANT });
}

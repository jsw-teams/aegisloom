import { type CloudEnvironment, makeCloudHandler } from "./handler.js";
/** Bind context.ip from Netlify's documented function context; never X-Forwarded-For. */
export function netlifyHandler(environment: CloudEnvironment) {
  const handler = makeCloudHandler(environment);
  return (request: Request, context: { ip?: string }) =>
    handler(request, context.ip ? { verifiedClientIp: context.ip } : {});
}

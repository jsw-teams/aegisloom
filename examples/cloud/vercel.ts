import { type CloudEnvironment, makeCloudHandler } from "./handler.js";
/** Supply a platform-verified IP from @vercel/functions ipAddress() in the deployment wrapper. */
export function vercelHandler(
  environment: CloudEnvironment,
  ipAddress: (request: Request) => string | undefined,
) {
  const handler = makeCloudHandler(environment);
  return (request: Request) => {
    const ip = ipAddress(request);
    return handler(request, ip ? { verifiedClientIp: ip } : {});
  };
}

import type { Fetch } from "../../core/types.js";
import { createPortableRuntime, type PortableOptions } from "../runtime.js";
export async function createCloudflareRuntime(options: PortableOptions) {
  const runtime = await createPortableRuntime(options);
  return {
    ...runtime,
    handle(request: Request, originFetches?: Record<string, Fetch>) {
      const protocol = (request as Request & { cf?: { httpProtocol?: string } }).cf?.httpProtocol;
      const ip = request.headers.get("cf-connecting-ip");
      return runtime.handle(
        request,
        {
          ...(protocol ? { httpProtocol: protocol } : {}),
          ...(ip ? { verifiedClientIp: ip } : {}),
        },
        undefined,
        originFetches,
      );
    },
  };
}

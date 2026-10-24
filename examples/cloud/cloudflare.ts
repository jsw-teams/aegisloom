import { type CloudEnvironment, makeCloudHandler } from "./handler.js";

const engines = new WeakMap<CloudEnvironment, ReturnType<typeof makeCloudHandler>>();
export default {
  fetch(request: Request, env: CloudEnvironment) {
    let handler = engines.get(env);
    if (!handler) {
      handler = makeCloudHandler(env);
      engines.set(env, handler);
    }
    // Trust this header ONLY when this entry is reached directly through Cloudflare Workers.
    const ip = request.headers.get("cf-connecting-ip");
    return handler(request, ip ? { verifiedClientIp: ip } : {});
  },
};

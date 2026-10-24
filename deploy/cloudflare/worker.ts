import {
  createCloudflareRuntime,
  type WorkerEnvironment,
} from "../../adapters/cloudflare/runtime.js";

const runtimes = new WeakMap<WorkerEnvironment, ReturnType<typeof createCloudflareRuntime>>();
export default {
  async fetch(request: Request, env: WorkerEnvironment): Promise<Response> {
    try {
      let runtime = runtimes.get(env);
      if (!runtime) {
        runtime = createCloudflareRuntime(env);
        runtimes.set(env, runtime);
      }
      return await (await runtime)(request);
    } catch {
      return Response.json(
        { error: "shield_unavailable" },
        { status: 503, headers: { "cache-control": "no-store" } },
      );
    }
  },
};

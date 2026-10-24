import { createControlHandler } from "../../packages/control-plane/handler.js";
import { MemoryDecisionStore } from "../../packages/decision-cache/memory.js";

const store = new MemoryDecisionStore();
// Emulator-only control service. Production must use a persistent authority, not this fixture.
export default {
  async fetch(request: Request, env: { RUNTIME_TOKEN: string; ADMIN_TOKEN: string }) {
    const response = await (
      await createControlHandler(store, [
        { token: env.RUNTIME_TOKEN, tenant: "test", role: "runtime" },
        { token: env.ADMIN_TOKEN, tenant: "test", role: "admin" },
      ])
    )(request);
    return response;
  },
};

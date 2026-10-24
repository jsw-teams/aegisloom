import { boundedJson } from "../core/remote.js";
import type { Fetch } from "../core/types.js";

export class CloudApiError extends Error {
  constructor(public readonly status: number) {
    super(`Cloud management API failed (${status}); response body omitted to protect secrets`);
  }
}
/** Retry reads only. Retrying non-idempotent creates without readback can duplicate native rules. */
export async function cloudJson(transport: Fetch, url: string, init: RequestInit): Promise<any> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const response = await transport(url, {
      ...init,
      redirect: "manual",
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      if (
        (init.method ?? "GET") === "GET" &&
        (response.status === 429 || response.status >= 500) &&
        attempt < 2
      ) {
        await new Promise((resolve) => setTimeout(resolve, 50 * 2 ** attempt));
        continue;
      }
      throw new CloudApiError(response.status);
    }
    if (response.status === 204) return {};
    return boundedJson(response);
  }
  throw new Error("Retry exhausted");
}

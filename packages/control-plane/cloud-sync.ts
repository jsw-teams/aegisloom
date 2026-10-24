import type { Approval, CloudAdapter, CloudPlan } from "../cloud-compiler/types.js";
import type { Policy } from "../rule-ir/index.js";

/** Run off the request path. Re-plan/read back after ambiguous API failures before retrying. */
export async function syncCloud(
  adapter: CloudAdapter,
  policy: Policy,
  authorize: (plan: CloudPlan) => Promise<Approval>,
  audit: (event: { at: number; attempt: number; status: string; hash?: string }) => Promise<void>,
  attempts = 3,
) {
  if (!Number.isInteger(attempts) || attempts < 1 || attempts > 5)
    throw new Error("Invalid retry bound");
  let failure: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const plan = await adapter.plan(policy);
      const approval = await authorize(plan);
      await audit({ at: Date.now(), attempt, status: "approved", hash: plan.hash });
      const result = await adapter.apply(plan, approval);
      await audit({ at: Date.now(), attempt, status: result.status, hash: result.hash });
      return result;
    } catch (error) {
      failure = error;
      await audit({ at: Date.now(), attempt, status: "failed" });
      if (attempt < attempts)
        await new Promise((resolve) => setTimeout(resolve, 50 * 2 ** (attempt - 1)));
    }
  }
  throw failure;
}

declare module "edgeaegis:deployment" {
  import type { DeploymentConfig, ProjectCredentials } from "../config.js";
  import type { ErrorPages } from "../runtime/error-pages.js";
  import type { AllowlistEntry } from "../runtime/index.js";

  const value: {
    config: DeploymentConfig;
    credentials: ProjectCredentials;
    source: string;
    files: Record<string, string>;
    allowlist: AllowlistEntry[];
    errorPages: ErrorPages;
  };
  export default value;
}
declare module "edgeaegis:origin" {
  import type { Fetch } from "../core/types.js";

  const value: Record<string, Fetch>;
  export default value;
}
declare module "edgeaegis:wasm" {
  export const PCRE2: WebAssembly.Module | BufferSource;
  export const INJECTION: WebAssembly.Module | BufferSource;
}

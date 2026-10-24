import { type CloudEnvironment, makeCloudHandler } from "./handler.js";
/** ESA trigger wrapper must pass trusted platform connection metadata. No raw header inference. */
export function esaHandler(environment: CloudEnvironment) {
  return makeCloudHandler(environment);
}

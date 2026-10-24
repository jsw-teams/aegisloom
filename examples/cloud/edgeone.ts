import { type CloudEnvironment, makeCloudHandler } from "./handler.js";
/** EdgeOne trigger wrapper must pass trusted platform connection metadata. */
export function edgeoneHandler(environment: CloudEnvironment) {
  return makeCloudHandler(environment);
}

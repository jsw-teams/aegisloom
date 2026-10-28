import { handleCloudRequest } from "../handler.js";
export const runtime = "nodejs";
export default { fetch: handleCloudRequest };

import { handleCloudRequest } from "../handler.js";
export function onRequest(context: { request: Request }) {
  return handleCloudRequest(context.request);
}

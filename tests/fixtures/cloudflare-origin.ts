import { createOriginVerifier } from "../../packages/backend-security/origin.js";

declare const WebSocketPair: new () => { 0: WebSocket; 1: WebSocket & { accept(): void } };
export default {
  async fetch(request: Request, env: { ORIGIN_TOKEN: string }) {
    if (!(await (await createOriginVerifier([env.ORIGIN_TOKEN]))(request)))
      return new Response(null, { status: 403 });
    if (request.headers.get("upgrade") === "websocket") {
      const pair = new WebSocketPair();
      pair[1].binaryType = "arraybuffer";
      pair[1].accept();
      pair[1].addEventListener("message", (event) =>
        pair[1].send(typeof event.data === "string" ? `echo:${event.data}` : event.data),
      );
      return new Response(null, { status: 101, webSocket: pair[0] } as ResponseInit);
    }
    if (new URL(request.url).pathname === "/media")
      return new Response(new Uint8Array([1, 2, 3]), { headers: { "content-type": "video/mp4" } });
    return Response.json({ ok: true });
  },
};

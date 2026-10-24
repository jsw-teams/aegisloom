import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { canonicalPath, checkRawHeaders } from "../http-boundary/index.js";

/** Node-only transport; the engine itself imports no Node API. Never trusts X-Forwarded-For. */
export function createNodeServer(
  handler: (request: Request, incoming: IncomingMessage) => Promise<Response>,
  publicHost: string | (() => string),
) {
  const server = createServer(
    {
      maxHeaderSize: 16384,
      insecureHTTPParser: false,
      requestTimeout: 15000,
      headersTimeout: 10000,
      keepAliveTimeout: 5000,
    },
    async (incoming: IncomingMessage, outgoing: ServerResponse) => {
      const abort = new AbortController();
      incoming.on("aborted", () => abort.abort());
      outgoing.on("close", () => {
        if (!outgoing.writableFinished) abort.abort();
      });
      try {
        const expectedHost = typeof publicHost === "string" ? publicHost : publicHost();
        checkRawHeaders(incoming.rawHeaders);
        canonicalPath(incoming.url ?? "");
        if (
          incoming.headers.host !== expectedHost ||
          !incoming.url?.startsWith("/") ||
          incoming.url.startsWith("//")
        )
          throw new Error("Invalid authority/target");
        const headers = new Headers();
        for (let i = 0; i < incoming.rawHeaders.length; i += 2)
          headers.append(incoming.rawHeaders[i] ?? "", incoming.rawHeaders[i + 1] ?? "");
        const init: RequestInit & { duplex?: "half" } = {
          method: incoming.method ?? "GET",
          headers,
          signal: abort.signal,
        };
        if (!["GET", "HEAD"].includes(init.method ?? "GET")) {
          init.body = Readable.toWeb(incoming) as ReadableStream<Uint8Array>;
          init.duplex = "half";
        }
        const request = new Request(`http://${expectedHost}${incoming.url}`, init);
        const response = await handler(request, incoming);
        if (!incoming.complete) {
          outgoing.setHeader("connection", "close");
          outgoing.once("finish", () => incoming.destroy());
        }
        outgoing.statusCode = response.status;
        for (const [name, value] of response.headers)
          if (name !== "set-cookie") outgoing.setHeader(name, value);
        const cookies = response.headers.getSetCookie();
        if (cookies.length) outgoing.setHeader("set-cookie", cookies);
        if (!response.body) {
          outgoing.end();
          return;
        }
        const reader = response.body.getReader();
        try {
          while (true) {
            const item = await reader.read();
            if (item.done) break;
            if (!outgoing.write(item.value))
              await new Promise<void>((resolve, reject) => {
                const done = () => {
                  outgoing.off("error", failed);
                  outgoing.off("close", failed);
                  resolve();
                };
                const failed = () => {
                  outgoing.off("drain", done);
                  reject(new Error("client-closed"));
                };
                outgoing.once("drain", done);
                outgoing.once("error", failed);
                outgoing.once("close", failed);
              });
          }
          outgoing.end();
        } catch {
          void reader.cancel().catch(() => {});
          outgoing.destroy();
        }
      } catch {
        if (!outgoing.headersSent) {
          outgoing.writeHead(400, { "content-type": "application/json", connection: "close" });
          outgoing.end('{"error":"invalid_http_request"}');
        } else outgoing.destroy();
      }
    },
  );
  server.maxConnections = 256;
  return server;
}

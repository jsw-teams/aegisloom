import assert from "node:assert/strict";
import { test } from "node:test";
import { createCloudflareWebSocketGateway } from "../adapters/cloudflare/websocket.js";
import {
  grpcWebInspector,
  type MessageSocket,
  relayWebSockets,
} from "../packages/protocols/index.js";
import { attackRule, context, fixture, token } from "./helpers.js";

const media = {
  headerTimeoutMs: 20,
  idleTimeoutMs: 80,
  maxBytes: 4096,
  contentTypes: ["video/mp4"],
};
const grpcWeb = {
  headerTimeoutMs: 50,
  idleTimeoutMs: 100,
  maxResponseBytes: 4096,
  maxMessageBytes: 256,
  maxMessages: 10,
};
const frame = (data: string, flag = 0) => {
  const bytes = new TextEncoder().encode(data);
  const out = new Uint8Array(5 + bytes.length);
  out[0] = flag;
  new DataView(out.buffer).setUint32(1, bytes.length, false);
  out.set(bytes, 5);
  return out;
};
const concatenate = (...chunks: Uint8Array[]) => {
  const out = new Uint8Array(chunks.reduce((n, b) => n + b.length, 0));
  let offset = 0;
  for (const bytes of chunks) {
    out.set(bytes, offset);
    offset += bytes.length;
  }
  return out;
};
test("media continues beyond the header deadline while progressing; normal IR and auth still run", async () => {
  const f = await fixture({
    routes: [{ path: "/media", methods: ["GET", "HEAD"], authenticated: true, media }],
    proxy: {
      origin: "https://origin.test",
      allowedOrigins: ["https://origin.test"],
      originToken: token,
      fetch: async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            async start(c) {
              for (let i = 0; i < 4; i++) {
                c.enqueue(new Uint8Array([i]));
                await new Promise((r) => setTimeout(r, 15));
              }
              c.close();
            },
          }),
          { headers: { "content-type": "video/mp4" } },
        ),
    },
  });
  const request = (query = "") => new Request(`https://api.test/media${query}`);
  assert.equal((await f.handle(request(), context)).status, 401);
  const trusted = { ...context, identity: "verified" };
  assert.equal((await f.handle(request("?q=attack"), trusted)).status, 403);
  const result = await f.handle(request(), trusted);
  assert.deepEqual(new Uint8Array(await result.arrayBuffer()), new Uint8Array([0, 1, 2, 3]));
});
test("media rejects multi-range, bad MIME, oversized and stalled transfers", async () => {
  const config = {
    routes: [
      {
        path: "/media",
        methods: ["GET"],
        authenticated: false,
        media: { ...media, idleTimeoutMs: 15, maxBytes: 4 },
      },
    ],
  };
  let calls = 0;
  const f = await fixture({
    ...config,
    proxy: {
      origin: "https://origin.test",
      allowedOrigins: ["https://origin.test"],
      originToken: token,
      fetch: async () => {
        calls++;
        return new Response("abcdef", { headers: { "content-type": "video/mp4" } });
      },
    },
  });
  assert.equal(
    (
      await f.handle(
        new Request("https://api.test/media", { headers: { range: "bytes=0-1,4-5" } }),
        context,
      )
    ).status,
    416,
  );
  assert.equal(calls, 0);
  await assert.rejects(
    (await f.handle(new Request("https://api.test/media"), context)).text(),
    /too-large/,
  );
  const stalled = await fixture({
    ...config,
    maxConcurrentRequests: 1,
    proxy: {
      origin: "https://origin.test",
      allowedOrigins: ["https://origin.test"],
      originToken: token,
      fetch: async () =>
        new Response(new ReadableStream(), { headers: { "content-type": "video/mp4" } }),
    },
  });
  await assert.rejects(
    (await stalled.handle(new Request("https://api.test/media"), context)).text(),
    /idle-timeout/,
  );
  const again = await stalled.handle(new Request("https://api.test/media"), context);
  assert.equal(again.status, 200);
  await again.body?.cancel();
  const wrongType = await fixture({ ...config });
  assert.equal(
    (await wrongType.handle(new Request("https://api.test/media"), context)).status,
    502,
  );
});
test("gRPC-Web envelopes validate fragmented lengths, compression flags, truncation and status trailers", () => {
  const bytes = concatenate(frame("message"), frame("grpc-status: 0\r\n", 128));
  const inspect = grpcWebInspector({
    maxMessageBytes: 256,
    maxMessages: 10,
    direction: "response",
  });
  for (const byte of bytes) inspect(new Uint8Array([byte]), false);
  inspect(new Uint8Array(), true);
  grpcWebInspector({ maxMessageBytes: 256, maxMessages: 10, direction: "response" })(
    frame("grpc-status:0", 128),
    true,
  );
  for (const invalid of [
    frame("x", 1),
    frame("grpc-status: 0\r\ngrpc-status: 1\r\n", 128),
    frame("grpc-status: 0\r\ngrpc-status: 99", 128),
    frame("message"),
    bytes.slice(0, -1),
    new Uint8Array([0, 127, 255, 255, 255]),
  ])
    assert.throws(() =>
      grpcWebInspector({ maxMessageBytes: 256, maxMessages: 10, direction: "response" })(
        invalid,
        true,
      ),
    );
  assert.throws(() =>
    grpcWebInspector({ maxMessageBytes: 256, maxMessages: 10, direction: "request" })(
      frame("grpc-status: 0\r\n", 128),
      true,
    ),
  );
});

test("WebSocket inspection timeout and idle expiry close both sides and release sessions", async () => {
  const client = new Socket();
  const upstream = new Socket();
  let closed = 0;
  relayWebSockets(client, upstream, {
    limits: { inspectionTimeoutMs: 10 },
    inspect: async () => new Promise<boolean>(() => {}),
    closed: () => {
      closed++;
    },
  });
  client.message("pending");
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(client.closed[0], 1008);
  assert.equal(upstream.sent.length, 0);
  assert.equal(closed, 1);
  const a = new Socket();
  const b = new Socket();
  relayWebSockets(a, b, { limits: { idleTimeoutMs: 10 } });
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(a.closed[0], 1008);
  assert.equal(b.closed[0], 1008);
});
test("gRPC-Web runtime protects unary input and server streams without interpreting protobuf as JSON", async () => {
  const f = await fixture({
    routes: [{ path: "/rpc", methods: ["POST"], authenticated: true, body: "grpc-web", grpcWeb }],
    proxy: {
      origin: "https://origin.test",
      allowedOrigins: ["https://origin.test"],
      originToken: token,
      fetch: async () =>
        new Response(concatenate(frame("reply"), frame("grpc-status: 0\r\n", 128)), {
          headers: { "content-type": "application/grpc-web+proto" },
        }),
    },
  });
  const call = (body: Uint8Array, type = "application/grpc-web+proto") =>
    new Request("https://api.test/rpc", {
      method: "POST",
      headers: { "content-type": type },
      body: body as BodyInit,
    });
  const trusted = { ...context, identity: "verified" };
  assert.equal((await f.handle(call(frame("hello")), context)).status, 401);
  const result = await f.handle(call(frame("hello")), trusted);
  assert.equal(result.status, 200);
  assert.deepEqual(
    new Uint8Array(await result.arrayBuffer()),
    concatenate(frame("reply"), frame("grpc-status: 0\r\n", 128)),
  );
  assert.equal((await f.handle(call(frame("x", 1)), trusted)).status, 400);
  assert.equal((await f.handle(call(frame("x"), "application/grpc"), trusted)).status, 501);
  assert.equal(
    (await f.handle(call(frame("x"), "application/grpc-web-text"), trusted)).status,
    415,
  );
  await assert.rejects(
    fixture({
      routes: [
        { path: "/rpc", methods: ["POST"], authenticated: false, body: "grpc-web", grpcWeb },
      ],
      policy: {
        version: "1",
        rules: [
          {
            ...attackRule,
            phase: "request-body",
            when: { field: "body", op: "contains", value: "x" },
          },
        ],
      } as any,
    }),
    /body rules/i,
  );
});

class Socket implements MessageSocket {
  sent: (string | ArrayBuffer | ArrayBufferView)[] = [];
  closed: number[] = [];
  accepted = false;
  messages: ((event: { data: unknown }) => void)[] = [];
  closes: (() => void)[] = [];
  accept() {
    this.accepted = true;
  }
  send(data: string | ArrayBuffer | ArrayBufferView) {
    this.sent.push(data);
  }
  close(code = 1000) {
    this.closed.push(code);
  }
  addEventListener(type: string, callback: any) {
    if (type === "message") this.messages.push(callback);
    else if (type === "close") this.closes.push(callback);
  }
  message(data: unknown) {
    for (const fn of this.messages) fn({ data });
  }
}
const tick = () => new Promise((resolve) => setTimeout(resolve, 2));
test("WebSocket relay inspects both directions in order; rate, size and queues close both sockets", async () => {
  const client = new Socket();
  const upstream = new Socket();
  const relay = relayWebSockets(client, upstream, {
    inspect: async (message) => message !== "attack",
  });
  client.message("one");
  client.message("two");
  upstream.message("reply");
  await tick();
  assert.deepEqual(upstream.sent, ["one", "two"]);
  assert.deepEqual(client.sent, ["reply"]);
  client.message("attack");
  await tick();
  assert.equal(client.closed[0], 1008);
  assert.equal(upstream.closed[0], 1008);
  relay.close();
  for (const mode of ["size", "rate", "queue"]) {
    const a = new Socket();
    const b = new Socket();
    const r = relayWebSockets(a, b, {
      limits: { maxMessageBytes: 4, maxMessagesPerWindow: 1, maxQueuedMessages: 1 },
      ...(mode === "queue"
        ? { limits: { maxQueuedMessages: 1 }, inspect: async () => new Promise<boolean>(() => {}) }
        : {}),
    });
    a.message(mode === "size" ? "12345" : "one");
    if (mode !== "size") a.message("two");
    assert.ok(a.closed[0] === 1008 || a.closed[0] === 1009);
    r.close();
  }
});
test("WebSocket handshake uses the same Shield IR and prevents cross-site upgrades before connecting", async () => {
  const engine = await fixture({
    routes: [{ path: "/ws", methods: ["GET"], authenticated: true, protocol: "websocket" }],
  });
  const ws = (query = "", origin = "https://app.test") =>
    new Request(`https://api.test/ws${query}`, {
      headers: {
        upgrade: "websocket",
        "sec-websocket-version": "13",
        "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
        origin,
      },
    });
  let connects = 0;
  const client = new Socket();
  const server = new Socket();
  const upstream = new Socket();
  const gateway = createCloudflareWebSocketGateway({
    tenant: context.tenant,
    engine,
    origin: "https://origin.test",
    allowedOrigins: ["https://origin.test"],
    originToken: token,
    allowedBrowserOrigins: ["https://app.test"],
    context: async () => ({ ...context, identity: "verified" }),
    maxConnections: 1,
    fetch: async (_, init) => {
      connects++;
      assert.equal(new Headers(init?.headers).get("x-shield-origin-auth"), token);
      return { status: 101, headers: new Headers(), webSocket: upstream } as unknown as Response;
    },
    pair: () => ({ 0: client, 1: server }),
    upgrade: () => new Response(null, { status: 200 }),
  });
  assert.equal((await gateway(ws("", "https://evil.test"))).status, 403);
  assert.equal((await gateway(ws("?q=attack"))).status, 403);
  assert.equal(connects, 0);
  assert.equal((await gateway(ws())).status, 200);
  assert.equal(connects, 1);
  assert.equal((await gateway(ws())).status, 503);
  server.message("hello");
  await tick();
  assert.deepEqual(upstream.sent, ["hello"]);
  for (const fn of server.closes) fn();
  assert.equal(server.closed[0], 1000);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { build } from "esbuild";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import type { MessageSocket } from "../packages/protocols/websocket.js";

test("real workerd: bound origin, shared L2, L1, admin revoke, media and WebSocket relay", {
  timeout: 45000,
}, async () => {
  async function bundle(entry: string) {
    const result = await build({
      entryPoints: [entry],
      bundle: true,
      platform: "browser",
      format: "esm",
      target: "es2022",
      write: false,
    });
    return result.outputFiles[0]!.text;
  }
  const [script, origin, control] = await Promise.all([
    bundle("deploy/cloudflare/worker.ts"),
    bundle("tests/fixtures/cloudflare-origin.ts"),
    bundle("tests/fixtures/cloudflare-control.ts"),
  ]);
  const originToken = "workerd-only-origin-fixture-token-32-chars";
  const runtimeToken = "workerd-only-runtime-fixture-token-32-chars";
  const adminToken = "workerd-only-administrator-fixture-token-32-chars";
  const clientToken = "workerd-only-client-fixture-token-32-chars";
  const bindings = {
    TENANT: "test",
    SERVICE: "api",
    PUBLIC_HOST: "api.test",
    ORIGIN: "https://origin.test",
    ORIGIN_TOKEN: originToken,
    CONTROL_ORIGIN: "https://control.test",
    CONTROL_RUNTIME_TOKEN: runtimeToken,
    CLIENT_TOKEN: clientToken,
    WEBSOCKET_BROWSER_ORIGINS: ["https://app.test"],
    ROUTES: [
      { path: "/api", methods: ["GET"], authenticated: true },
      { path: "/ws", methods: ["GET"], authenticated: true, protocol: "websocket" },
      {
        path: "/media",
        methods: ["GET"],
        authenticated: true,
        media: {
          headerTimeoutMs: 1000,
          idleTimeoutMs: 1000,
          maxBytes: 1024,
          contentTypes: ["video/mp4"],
        },
      },
    ],
    POLICY: JSON.stringify({
      version: "1",
      rules: [
        {
          id: "attack",
          name: "Block marker",
          service: "api",
          when: { field: "query", key: "q", op: "contains", value: "attack" },
          then: { action: "block" },
          cache: { enabled: true, ttl: "1m" },
        },
      ],
    }),
  };
  const shared = {
    modules: true as const,
    compatibilityDate: "2026-10-01",
    script,
    bindings,
    serviceBindings: { ORIGIN_SERVICE: "origin", CONTROL_SERVICE: "control" },
  };
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      host: "127.0.0.1",
      port: 0,
      workers: [
        {
          name: "router",
          modules: true,
          compatibilityDate: "2026-10-01",
          serviceBindings: { a: "shield-a", b: "shield-b", origin: "origin", control: "control" },
          script: `export default { fetch(request, env) { const headers = new Headers(request.headers); const target = headers.get('x-fixture-target') || 'a'; headers.delete('x-fixture-target'); headers.set('host', new URL(request.url).host); return env[target].fetch(new Request(request, {headers})); } };`,
        },
        { name: "shield-a", ...shared },
        { name: "shield-b", ...shared },
        {
          name: "origin",
          modules: true,
          script: origin,
          compatibilityDate: "2026-10-01",
          bindings: { ORIGIN_TOKEN: originToken },
        },
        {
          name: "control",
          modules: true,
          script: control,
          compatibilityDate: "2026-10-01",
          bindings: { RUNTIME_TOKEN: runtimeToken, ADMIN_TOKEN: adminToken },
        },
      ],
    }),
  );
  // Use a real ingress plus service bindings; the Node RPC proxy adds an internal Host header.
  const getWorker = async (name: string) => ({
    fetch: (
      input: string,
      init?: { method?: string; headers?: Record<string, string>; body?: string },
    ) => {
      const headers = new Headers(init?.headers);
      headers.set("x-fixture-target", name === "shield-a" ? "a" : name === "shield-b" ? "b" : name);
      return mf.dispatchFetch(input, {
        ...init,
        headers: Object.fromEntries(headers),
      }) as unknown as Promise<Response & { webSocket?: MessageSocket }>;
    },
  });
  try {
    const headers = { authorization: `Bearer ${clientToken}`, host: "api.test" };
    const workerA = await getWorker("shield-a");
    const workerB = await getWorker("shield-b");
    const initial = await workerA.fetch("https://api.test/api", { headers: { host: "api.test" } });
    assert.equal(initial.status, 401, await initial.text());
    assert.deepEqual(await (await workerA.fetch("https://api.test/api", { headers })).json(), {
      ok: true,
    });
    const attack = () => workerA.fetch("https://api.test/api?q=attack", { headers });
    assert.equal(((await (await attack()).json()) as any).reason, "rule-match");
    assert.equal(((await (await attack()).json()) as any).reason, "cached-attack");
    assert.equal(
      ((await (await workerB.fetch("https://api.test/api?q=attack", { headers })).json()) as any)
        .reason,
      "distributed-attack",
    );
    const authority = await getWorker("control");
    const adminHeaders = {
      authorization: `Bearer ${adminToken}`,
      "content-type": "application/json",
    };
    const list = (await (
      await authority.fetch("https://control.test/v1/decisions", { headers: adminHeaders })
    ).json()) as any;
    assert.equal(list.decisions.length, 1);
    assert.equal(
      (
        await authority.fetch("https://control.test/v1/revoke", {
          method: "POST",
          headers: adminHeaders,
          body: JSON.stringify({ id: list.decisions[0].id }),
        })
      ).status,
      200,
    );
    // Worker default generation-poll bound is one second, not instant cross-isolate invalidation.
    await new Promise((resolve) => setTimeout(resolve, 1100));
    assert.equal(((await (await attack()).json()) as any).reason, "rule-match");
    const media = await workerA.fetch("https://api.test/media", { headers });
    assert.deepEqual(new Uint8Array(await media.arrayBuffer()), new Uint8Array([1, 2, 3]));
    const upstream = await getWorker("origin");
    assert.equal((await upstream.fetch("https://origin.test/api")).status, 403);
    const upgrade = await workerA.fetch("https://api.test/ws", {
      headers: {
        ...headers,
        origin: "https://app.test",
        upgrade: "websocket",
        "sec-websocket-version": "13",
        "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
      },
    });
    assert.equal(upgrade.status, 101);
    const socket = upgrade.webSocket!;
    socket.binaryType = "arraybuffer";
    socket.accept();
    const echoed = new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("WebSocket echo deadline")), 2000);
      socket.addEventListener("message", (event) => {
        clearTimeout(timer);
        resolve(event.data);
      });
    });
    socket.send("hello");
    assert.equal(await echoed, "echo:hello");
    const binaryEcho = new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("WebSocket binary echo deadline")), 2000);
      socket.addEventListener("message", (event) => {
        clearTimeout(timer);
        resolve(event.data);
      });
    });
    socket.send(new Uint8Array([1, 2, 255]));
    assert.deepEqual(
      new Uint8Array((await binaryEcho) as ArrayBuffer),
      new Uint8Array([1, 2, 255]),
    );
    socket.close(1000, "test complete");
  } finally {
    await mf.dispose();
  }
});

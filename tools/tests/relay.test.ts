import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createRelayServer, createRelayTransport } from "../../scr/origin/relay.js";
import { SqliteReplayStore } from "../../scr/origin/replay-node.js";

const authenticationKey = "a".repeat(43),
  originToken = "test-origin-token-".repeat(3);
async function fixture() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const serverPrivateKey = await crypto.subtle.exportKey("jwk", pair.privateKey),
    serverPublicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const directory = await mkdtemp(join(tmpdir(), "shield-relay-"));
  const path = join(directory, "replay.db");
  let replay = new SqliteReplayStore(path);
  let received = 0,
    packet: Request | undefined;
  const server = await createRelayServer({
    serverPrivateKey,
    authenticationKey,
    originToken,
    replay: { claim: (id, at) => replay.claim(id, at) },
    business: async (request) => {
      received++;
      return new Response(await request.arrayBuffer(), {
        status: 201,
        headers: [
          ["content-type", "application/octet-stream"],
          ["set-cookie", "a=1; Secure"],
          ["set-cookie", "b=2; Secure"],
        ],
      });
    },
  });
  const transport = await createRelayTransport({
    serverPublicKey,
    authenticationKey,
    endpoint: "https://relay.test/_edgeshield/relay",
    fetch: async (input, init) => {
      packet = new Request(input, init);
      return server(packet.clone());
    },
  });
  return {
    transport,
    server,
    get packet() {
      return packet!;
    },
    get received() {
      return received;
    },
    restart() {
      replay.close();
      replay = new SqliteReplayStore(path);
    },
    async close() {
      replay.close();
      await rm(directory, { recursive: true, force: true });
    },
  };
}
test("encrypted relay preserves binary payload and cookies, and persists replay rejection across restart", async () => {
  const f = await fixture();
  try {
    const body = new Uint8Array(2 * 1024 * 1024 + 321);
    for (let i = 0; i < body.length; i++) body[i] = i % 256;
    const response = await f.transport("https://origin.internal/upload?name=hello", {
      method: "POST",
      headers: { "x-shield-origin-auth": originToken },
      body,
    });
    assert.equal(response.status, 201);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), body);
    assert.equal(response.headers.getSetCookie().length, 2);
    assert.equal(f.received, 1);
    const wire = await f.packet.clone().text();
    assert.ok(!wire.includes("upload?"));
    assert.ok(!wire.includes(originToken));
    f.restart();
    assert.equal((await f.server(f.packet.clone())).status, 403);
    assert.equal(f.received, 1);
    const altered = JSON.parse(wire);
    altered.id = crypto.randomUUID();
    assert.equal(
      (await f.server(new Request(f.packet.url, { method: "POST", body: JSON.stringify(altered) })))
        .status,
      403,
    );
  } finally {
    await f.close();
  }
});
test("relay rejects wrong credentials, forged ciphertext, insecure endpoints and invalid byte limits", async () => {
  const f = await fixture();
  try {
    await assert.rejects(
      f.transport("https://origin.internal/upload", {
        method: "POST",
        body: "secret",
        headers: { "x-shield-origin-auth": "wrong" },
      }),
      /rejected/,
    );
    assert.equal(f.received, 0);
    await assert.rejects(f.transport("https://other.test/"), /outside/);
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
        "deriveBits",
      ]),
      key = await crypto.subtle.exportKey("jwk", pair.publicKey);
    await assert.rejects(
      createRelayTransport({
        endpoint: "http://relay.test",
        serverPublicKey: key,
        authenticationKey,
      }),
      /HTTPS/,
    );
    await assert.rejects(
      createRelayTransport({
        endpoint: "https://relay.test",
        serverPublicKey: key,
        authenticationKey,
        maxBytes: Infinity,
      }),
      /limit/,
    );
    const transport = await createRelayTransport({
      endpoint: "https://relay.test",
      serverPublicKey: key,
      authenticationKey,
      fetch: async () => Response.json({ v: 1, id: "forged", nonce: "", body: "" }),
    });
    await assert.rejects(transport("https://origin.internal/"), /binding/);
  } finally {
    await f.close();
  }
});

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CommunityHub,
  CommunitySubscriber,
  communityDisabled,
  type IpSignal,
  signValue,
  uploadSignal,
} from "../integrations/threat-intelligence/index.js";

const pair = () =>
  crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as Promise<CryptoKeyPair>;

test("community upload, subscribe and automatic blocking are independently disabled", async () => {
  const keys = await pair();
  let network = 0;
  const signal: IpSignal = {
    ip: "8.8.4.4",
    category: "protocol-abuse",
    at: Date.now(),
    observations: 5,
    confidence: 0.99,
    expiresAt: Date.now() + 60000,
    reporter: "r",
  };
  await assert.rejects(
    uploadSignal(
      communityDisabled,
      await signValue(signal, keys.privateKey),
      "https://community.test/report",
      ["https://community.test"],
      async () => {
        network++;
        return new Response();
      },
    ),
    /disabled/,
  );
  assert.equal(network, 0);
  const subscriber = new CommunitySubscriber(communityDisabled, keys.publicKey, []);
  await assert.rejects(
    subscriber.ingest(
      await signValue(
        {
          version: 1,
          issuedAt: Date.now(),
          expiresAt: Date.now() + 1000,
          entries: [],
          revoked: [],
        },
        keys.privateKey,
      ),
    ),
    /disabled/,
  );
  assert.equal(subscriber.shouldBlock("8.8.4.4"), false);
});
test("independent organizations, signature verification, warning lists, TTL and revocation", async () => {
  const root = await pair();
  const keys = await pair();
  const secondKeys = await pair();
  const thirdKeys = await pair();
  const now = Date.now();
  const reporters = new Map([
    ["a", { publicKey: keys.publicKey, organization: "one" }],
    ["b", { publicKey: keys.publicKey, organization: "one" }],
    ["c", { publicKey: secondKeys.publicKey, organization: "two" }],
    ["d", { publicKey: thirdKeys.publicKey, organization: "three" }],
    ["key-reused", { publicKey: keys.publicKey, organization: "fake-independent-org" }],
  ]);
  const hub = new CommunityHub(reporters, ["1.1.1.0/24"]);
  const signal = (reporter: string, ip = "8.8.4.4"): IpSignal => ({
    ip,
    reporter,
    category: "injection",
    at: now,
    observations: 3,
    confidence: 0.95,
    expiresAt: now + 60000,
  });
  assert.equal(
    await hub.accept(await signValue(signal("a", "1.1.1.1"), keys.privateKey), now),
    false,
  );
  assert.equal(
    await hub.accept(
      await signValue({ ...signal("a"), cookie: "secret" } as IpSignal, keys.privateKey),
      now,
    ),
    false,
  );
  for (const r of ["a", "b", "c"])
    await hub.accept(
      await signValue(signal(r), r === "c" ? secondKeys.privateKey : keys.privateKey),
      now,
    );
  assert.equal(
    await hub.accept(await signValue(signal("key-reused"), keys.privateKey), now),
    false,
  );
  assert.equal((await hub.snapshot(root.privateKey, now)).value.entries.length, 0);
  await hub.accept(await signValue(signal("d"), thirdKeys.privateKey), now);
  const subscriber = new CommunitySubscriber(
    { upload: false, subscribe: true, autoBlock: true },
    root.publicKey,
    [],
  );
  const feed = await hub.snapshot(root.privateKey, now);
  await subscriber.ingest(feed, now);
  assert.equal(subscriber.shouldBlock("8.8.4.4", now), true);
  assert.equal(subscriber.shouldBlock("8.8.4.4", now + 60001), false);
  await assert.rejects(subscriber.ingest(feed, now), /Stale/);
  const tampered = structuredClone(feed);
  tampered.value.version++;
  await assert.rejects(subscriber.ingest(tampered, now), /signature/);
  const signalsOnly = new CommunitySubscriber(
    { upload: false, subscribe: true, autoBlock: false },
    root.publicKey,
    [],
  );
  await signalsOnly.ingest(feed, now);
  assert.equal(signalsOnly.shouldBlock("8.8.4.4", now), false);
  hub.revoke("8.8.4.4");
  await subscriber.ingest(await hub.snapshot(root.privateKey, now), now);
  assert.equal(subscriber.shouldBlock("8.8.4.4", now), false);
});

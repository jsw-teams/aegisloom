import assert from "node:assert/strict";
import { test } from "node:test";
import { CollectionStore } from "../../scr/seclang/state.js";

test("collection capacity reclaims expired values and never evicts live state", () => {
  let now = 0;
  const store = new CollectionStore(() => now);
  for (let i = 0; i < 1024; i++) store.get(`ip:${i}`).values.set("score", i + 1);
  assert.throws(() => store.get("overflow"), /capacity exceeded/);
  store.get("ip:0").expires.set("score", 1);
  now = 2;
  const added = store.get("replacement");
  assert.equal(added.values.size, 0);
  added.values.set("score", 9);
  assert.equal(store.get("ip:1023").values.get("score"), 1024);
  assert.throws(() => store.get("overflow"), /capacity exceeded/);
});

test("accessing an idle collection cannot revive its expired state", () => {
  let now = 0;
  const store = new CollectionStore(() => now, 2);
  store.get("client").values.set("blocked", 1);
  now = 2000;
  assert.equal(store.get("client").values.has("blocked"), false);
  store.get("client").values.set("score", 1);
  store.get("client").expires.set("score", 2500);
  now = 2500;
  assert.equal(store.get("client").values.has("score"), false);
});

import assert from "node:assert/strict";
import { test } from "node:test";
import { createShield } from "../../scr/runtime/index.js";
import { jsonArguments } from "../../scr/seclang/json.js";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("JSON processor preserves numeric spelling, null semantics, arrays and every duplicate member", () => {
  assert.deepEqual(
    jsonArguments('{"n":9007199254740993,"n":1.20e+99,"values":[null,true,"text"]}'),
    [
      ["json.n", "9007199254740993"],
      ["json.n", "1.20e+99"],
      ["json.values.array_0", ""],
      ["json.values.array_1", "true"],
      ["json.values.array_2", "text"],
    ],
  );
  const program = compileSecLang('SecRule ARGS:json.q "@contains attack" "id:47001,deny"', {
    strict: true,
  });
  try {
    assert.equal(
      executeSecLang(program, {
        url: "https://test/",
        method: "POST",
        headers: { "content-type": "application/json" },
        bodyText: '{"q":"attack","q":"hello"}',
      }).blocked,
      true,
    );
  } finally {
    program.dispose();
  }
  for (const text of ['{"x":1,}', "[true,]", '{"q":"\\ud800"}', "1.2.3"])
    assert.throws(() => jsonArguments(text), /JSON/);
});
test("body parser errors are real SecLang variables and the HTTP runtime rejects invalid bodies before origin", async () => {
  const vm = compileSecLang('SecRule REQBODY_ERROR "@eq 1" "id:47003,deny"', { strict: true });
  try {
    assert.equal(
      executeSecLang(vm, {
        url: "https://test/",
        method: "POST",
        headers: { "content-type": "application/json" },
        bodyText: "{broken",
      }).blocked,
      true,
    );
  } finally {
    vm.dispose();
  }
  let forwarded = false;
  const engine = await createShield({
    tenant: "test",
    service: "api",
    publicHosts: ["test"],
    secLang: 'SecAction "id:47004,phase:2,pass"',
    routes: [{ business: "app", path: "/", methods: ["POST"], authenticated: false, body: "text" }],
    origins: {
      app: {
        origin: "https://origin.test",
        allowedOrigins: ["https://origin.test"],
        originToken: "test-origin-secret-".repeat(3),
        fetch: async () => {
          forwarded = true;
          return new Response("ok");
        },
      },
    },
  });
  try {
    const response = await engine.handle(
      new Request("https://test/", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{broken",
      }),
      { tenant: "test" },
    );
    await response.text();
    assert.equal(response.status, 400);
    assert.equal(forwarded, false);
  } finally {
    engine.dispose();
  }
});
test("JSON raw body remains available to full CRS rules alongside parsed field values", () => {
  const program = compileSecLang(
    'SecRule REQUEST_BODY "@contains __contained_by" "id:47002,deny"',
    { strict: true },
  );
  try {
    assert.equal(
      executeSecLang(program, {
        url: "https://test/",
        method: "POST",
        headers: { "content-type": "application/json" },
        bodyText: '{"roles__contained_by":["admin"]}',
      }).blocked,
      true,
    );
  } finally {
    program.dispose();
  }
});

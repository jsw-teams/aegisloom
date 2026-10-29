import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { createShield } from "../../scr/runtime/index.js";
import { loadSecLangDeployment } from "../../scr/seclang/node.js";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("shipped behavior policy enforces unknown-request bursts, confirmed attacks, TTL, IP isolation and exemptions", async () => {
  let now = 0,
    hits = 0;
  const setup = await readFile("rules/setup.conf", "utf8");
  const emergency = await readFile("rules/emergency.conf", "utf8");
  const engine = await createShield({
    tenant: "test",
    service: "api",
    publicHosts: ["api.test"],
    now: () => now,
    secLang: `${setup}\nSecRule ARGS:q "@streq attack" "id:42,phase:2,deny,setvar:tx.edgeshield_attack=1"`,
    secLangOptions: { files: { "emergency.conf": emergency } },
    routes: ["/api", "/exempt"].map((path) => ({
      path,
      business: "app",
      authenticated: false,
      methods: ["GET"],
    })),
    allowlist: [{ id: "operator", path: "/exempt", skip: ["rules"] }],
    origins: {
      app: {
        origin: "https://origin.test",
        allowedOrigins: ["https://origin.test"],
        originToken: "fixture-origin-credential-".repeat(3),
        fetch: async () => {
          hits++;
          return new Response("ok");
        },
      },
    },
  });
  const send = async (ip = "192.0.2.1", path = "/api?q=ordinary-new-payload") => {
    const response = await engine.handle(new Request(`https://api.test${path}`), {
      tenant: "test",
      verifiedClientIp: ip,
    });
    await response.text();
    return response.status;
  };
  try {
    for (let i = 0; i < 120; i++) assert.equal(await send(), 200);
    assert.equal(await send(), 403);
    assert.equal(hits, 120, "blocked request must not reach origin");
    now = 290000;
    assert.equal(await send(), 403);
    assert.equal(await send("192.0.2.2"), 200);
    assert.equal(await send("192.0.2.1", "/exempt"), 200);
    now = 300001;
    assert.equal(await send(), 200, "blocked traffic must not renew the ban");
    for (let i = 0; i < 3; i++) assert.equal(await send("192.0.2.3", "/api?q=attack"), 403);
    assert.equal(
      await send("192.0.2.3"),
      403,
      "confirmed offenses block later innocent-looking requests",
    );
    for (let i = 0; i < 30; i++) {
      now += 1000;
      for (let n = 0; n < 10; n++) assert.equal(await send("192.0.2.4"), 200);
    }
    now = 600002;
    assert.equal(await send("192.0.2.3"), 200);
  } finally {
    engine.dispose();
  }
});

test("deployment setup precedes complete upstream rules and operator rules retain separate source scope", async () => {
  const loaded = await loadSecLangDeployment(
    "rules/seclang-bundle.json",
    "rules/local.conf",
    "rules/setup.conf",
  );
  assert.ok(loaded.secLang.startsWith("Include setup.conf\n"));
  assert.ok(loaded.secLang.endsWith("Include local.conf"));
  await assert.rejects(loadSecLangDeployment("rules/local.conf", "rules/local.conf"), /separate/);
});

test("native emergency patch and repeated real CRS attacks block before origin and expire", async () => {
  let now = 0;
  const loaded = await loadSecLangDeployment(
    "rules/seclang-bundle.json",
    "rules/local.conf",
    "rules/setup.conf",
  );
  const program = compileSecLang(loaded.secLang, {
    ...loaded.secLangOptions,
    now: () => now,
    strict: true,
  });
  const request = (query = "hello", ip = "192.0.2.10", headers = {}) => ({
    url: `https://test/api?q=${encodeURIComponent(query)}`,
    method: "GET",
    protocol: "HTTP/1.1",
    remoteAddr: ip,
    headers: { host: "test", accept: "text/html", "user-agent": "Mozilla/5.0", ...headers },
  });
  const send = (input: ReturnType<typeof request>) => {
    const result = executeSecLang(program, input);
    executeSecLang(program, input, { phases: [5], transaction: result.transaction });
    return result;
  };
  try {
    for (const value of ["", "middleware", "middleware:middleware:middleware"]) {
      const result = send(
        request("hello", `192.0.2.${20 + value.length}`, { "X-Middleware-Subrequest": value }),
      );
      assert.equal(result.blocked, true);
      assert.ok(result.matched.includes("1000300"));
    }
    assert.equal(send(request()).blocked, false);
    for (let i = 0; i < 3; i++) {
      const result = send(request("1 UNION SELECT password FROM users"));
      assert.equal(result.blocked, true);
      assert.ok(result.matched.includes("949110"), "actual CRS blocking evaluation required");
    }
    assert.ok(send(request()).matched.includes("1000201"));
    now = 299999;
    assert.equal(send(request()).blocked, true);
    now = 300000;
    assert.equal(send(request()).blocked, false);
  } finally {
    program.dispose();
  }
});

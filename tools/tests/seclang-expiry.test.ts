import assert from "node:assert/strict";
import { test } from "node:test";
import { createShield } from "../../scr/runtime/index.js";
import { compileSecLang, executeSecLang } from "./seclang-helpers.js";

test("expirevar resets only when executed, removes at the deadline, and is isolated by IP", () => {
  let now = 0;
  const program = compileSecLang(
    'SecAction "id:1,phase:1,pass,initcol:ip=%{REMOTE_ADDR}"\nSecRule ARGS:q "@streq attack" "id:2,phase:2,pass,setvar:ip.bad=+1,expirevar:ip.bad=10"\nSecRule IP:bad "@ge 2" "id:3,phase:2,deny"',
    { strict: true, now: () => now },
  );
  const send = (q: string, ip = "192.0.2.1") =>
    executeSecLang(program, { url: `https://test/?q=${q}`, method: "GET", remoteAddr: ip });
  try {
    assert.equal(send("attack").blocked, false);
    now = 5000;
    assert.equal(send("attack").blocked, true);
    now = 12000;
    assert.equal(send("normal").blocked, true);
    assert.equal(send("normal", "192.0.2.2").blocked, false);
    now = 15000;
    assert.equal(send("normal").blocked, false);
  } finally {
    program.dispose();
  }
});
test("deprecatevar applies elapsed whole intervals without resetting the remainder or going below zero", () => {
  let now = 0;
  const program = compileSecLang(
    'SecAction "id:1,phase:1,pass,initcol:ip=%{REMOTE_ADDR}"\nSecRule &IP:score "@eq 0" "id:2,phase:1,pass,setvar:ip.score=10"\nSecAction "id:3,phase:1,pass,deprecatevar:ip.score=2/5,setvar:tx.score=%{ip.score}"',
    { strict: true, now: () => now },
  );
  const send = () =>
    executeSecLang(program, { url: "https://test/", method: "GET", remoteAddr: "192.0.2.1" }).tx
      .score;
  try {
    assert.equal(send(), "10");
    now = 12000;
    assert.equal(send(), "6");
    now = 14999;
    assert.equal(send(), "6");
    now = 15000;
    assert.equal(send(), "4");
    now = 50000;
    assert.equal(send(), "0");
  } finally {
    program.dispose();
  }
});
test("native SecLang alone implements temporary repeated-offense denial and respects operator global exemptions", async () => {
  let now = 0;
  const source =
    'SecAction "id:1,phase:1,pass,initcol:ip=%{REMOTE_ADDR}"\nSecRule IP:blocked "@eq 1" "id:2,phase:1,deny,status:429"\nSecRule ARGS:q "@streq attack" "id:3,phase:2,deny,setvar:ip.hits=+1,expirevar:ip.hits=60"\nSecRule IP:hits "@ge 3" "id:4,phase:5,pass,setvar:ip.blocked=1,expirevar:ip.blocked=300"';
  const engine = await createShield({
    tenant: "test",
    service: "api",
    publicHosts: ["api.test"],
    secLang: source,
    routes: ["/api", "/exempt"].map((path) => ({
      business: "app",
      path,
      methods: ["GET"],
      authenticated: false,
    })),
    allowlist: [{ id: "owned-exemption", skip: ["rules"], path: "/exempt" }],
    now: () => now,
    origins: {
      app: {
        origin: "https://origin.test",
        allowedOrigins: ["https://origin.test"],
        originToken: "test-origin-secret-".repeat(3),
        fetch: async () => Response.json({ ok: true }),
      },
    },
  });
  const send = async (q: string, path = "/api") => {
    const response = await engine.handle(new Request(`https://api.test${path}?q=${q}`), {
      tenant: "test",
      verifiedClientIp: "192.0.2.1",
    });
    await response.text();
    return response.status;
  };
  try {
    assert.equal(await send("attack", "/exempt"), 200);
    for (let i = 0; i < 3; i++) assert.equal(await send("attack"), 403);
    assert.equal(await send("normal"), 429);
    now = 300001;
    assert.equal(await send("normal"), 200);
  } finally {
    engine.dispose();
  }
});

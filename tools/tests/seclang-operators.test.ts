import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { compileSecLang, createInjectionDetectors, executeSecLang } from "./seclang-helpers.js";

const detectors = await createInjectionDetectors(
  await readFile(new URL("../../scr/seclang/vendor/libinjection.wasm", import.meta.url)),
);
test("numeric operators and setvar use SecLang integer-prefix conversion rather than JavaScript Number", () => {
  const program = compileSecLang(
    'SecRule ARGS:q "@eq 12.9" "id:41201,deny"\nSecAction "id:41202,phase:1,pass,setvar:tx.count=word,setvar:tx.count=+3suffix"',
    { strict: true },
  );
  try {
    for (const value of ["12suffix", "  +12.5"]) {
      const result = executeSecLang(program, {
        url: `https://test/?q=${encodeURIComponent(value)}`,
        method: "GET",
      });
      assert.equal(result.blocked, true);
      assert.equal(result.tx.count, 3);
    }
  } finally {
    program.dispose();
  }
});
const send = (program: ReturnType<typeof compileSecLang>, value: string) =>
  executeSecLang(program, {
    url: `https://test/?q=${encodeURIComponent(value)}`,
    method: "GET",
    headers: {},
  });

test("actual libinjection SQLi detection and capture execute without a WAF engine", () => {
  const program = compileSecLang('SecRule ARGS "@detectSQLi" "id:41001,deny,capture"', {
    strict: true,
    detectors,
  });
  const attack = send(program, "1 UNION SELECT password FROM users");
  assert.equal(attack.blocked, true);
  assert.equal(typeof attack.tx["0"], "string");
  assert.equal(send(program, "a normal search about database migrations").blocked, false);
});

test("actual libinjection XSS detection distinguishes markup from script", () => {
  const program = compileSecLang('SecRule ARGS "@detectXSS" "id:41002,deny"', {
    strict: true,
    detectors,
  });
  assert.equal(send(program, "<img src=x onerror=alert(1)>").blocked, true);
  assert.equal(send(program, "<p>Hello world</p>").blocked, false);
});

test("phrase capture uses matched input text and resolves all listed phrase files", () => {
  const program = compileSecLang(
    'SecRule ARGS "@pmFromFile first.data second.data" "id:41003,deny,capture"',
    {
      strict: true,
      phraseFiles: { "first.data": ["scanner"], "second.data": ["attack"] },
    },
  );
  assert.equal(send(program, "an ATTACK").tx["0"], "ATTACK");
});

test("compiled phrase matching preserves file order, original capture case and non-ASCII bytes", () => {
  const program = compileSecLang(
    'SecRule ARGS "@pmFromFile signatures.data" "id:41005,deny,capture"',
    { strict: true, phraseFiles: { "signatures.data": ["SCANNER", "ATTACK", "À"] } },
  );
  try {
    assert.equal(send(program, "attack then ScAnNeR").tx["0"], "ScAnNeR");
    assert.equal(send(program, "prefix\0À").blocked, true);
    assert.equal(send(program, "prefix\0à").blocked, false);
    assert.equal(send(program, "ordinary traffic").blocked, false);
  } finally {
    program.dispose();
  }
});

test("IP CIDR operator handles IPv4 and IPv6 and rejects a different network", () => {
  const program = compileSecLang(
    'SecRule ARGS "@ipMatch 192.0.2.0/24,2001:db8::/32" "id:41004,deny"',
    { strict: true },
  );
  assert.equal(send(program, "192.0.2.2").blocked, true);
  assert.equal(send(program, "2001:db8::5").blocked, true);
  assert.equal(send(program, "192.0.3.2").blocked, false);
});

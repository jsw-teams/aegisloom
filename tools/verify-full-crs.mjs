import assert from "node:assert/strict";
import { compileSecLang, executeSecLang } from "./.build/scr/seclang/index.js";
import { loadSecLangBackends } from "./.build/scr/seclang/node.js";
import { parseSecLangSyntax } from "./.build/scr/seclang/syntax.js";

/** Required full-corpus gate: any missing data or unsupported statement aborts compilation. */
export async function verifyFullCrs(bundle) {
  const compiled = compileSecLang(bundle.source, {
    strict: true,
    files: bundle.files,
    ...(await loadSecLangBackends()),
  });
  let steps = 0;
  for (const root of compiled.instructions) {
    if (root.type !== "rule") continue;
    for (let node = root; node; node = node.next) steps++;
  }
  const expected = Object.entries(bundle.files)
    .filter(([path]) => path.endsWith(".conf"))
    .reduce(
      (n, [, text]) =>
        n +
        parseSecLangSyntax(text).filter(
          (stmt) => stmt.directive === "SecRule" || stmt.directive === "SecAction",
        ).length,
      0,
    );
  assert.equal(steps, expected, "Every source rule/action must have an executable instruction");
  const normal = [
    "/?q=hello",
    "/api?item=123",
    "/health",
    "/.well-known/security.txt",
    `/?q=${encodeURIComponent("你好世界")}`,
  ];
  const attacks = [
    ["SQL injection", "/?q=1%20UNION%20SELECT%20password%20FROM%20users"],
    ["XSS", "/?q=%3Cscript%3Ealert(1)%3C/script%3E"],
    ["LFI", "/?file=../../../../etc/passwd"],
    ["RCE", "/?cmd=;cat%20/etc/passwd"],
  ];
  const request = (path) => ({
    url: `https://example.test${path}`,
    method: "GET",
    protocol: "HTTP/1.1",
    remoteAddr: "192.0.2.5",
    headers: { host: "example.test", "user-agent": "Mozilla/5.0", accept: "text/html" },
  });
  const timings = [];
  try {
    for (const path of normal) {
      const start = performance.now();
      const result = executeSecLang(compiled, request(path));
      timings.push(performance.now() - start);
      assert.equal(result.blocked, false, `Normal request blocked: ${path}`);
      const response = executeSecLang(
        compiled,
        {
          ...request(path),
          responseStatus: 200,
          responseHeaders: { "content-type": "text/html" },
          responseBody: "<html><p>Hello</p></html>",
        },
        { phases: [3, 4, 5], transaction: result.transaction },
      );
      assert.equal(response.blocked, false, `Normal response blocked: ${path}`);
    }
    for (const [name, path] of attacks) {
      const result = executeSecLang(compiled, request(path));
      assert.equal(result.blocked, true, `${name} bypassed full CRS`);
      assert.ok(
        result.matched.includes("949110") || result.matched.includes("949111"),
        `${name} must reach actual CRS blocking evaluation`,
      );
    }
    const incoming = executeSecLang(compiled, request("/"));
    const leak = executeSecLang(
      compiled,
      {
        ...request("/"),
        responseStatus: 200,
        responseHeaders: { "content-type": "text/html" },
        responseBody: "<title>=[ 1n73ct10n privat shell ]=</title>",
      },
      { phases: [3, 4, 5], transaction: incoming.transaction },
    );
    assert.equal(leak.blocked, true, "Official PHP web-shell phrase file must execute");
    assert.ok(
      leak.matched.includes("955100"),
      "Web-shell detection must be from official data, not a replacement regex",
    );
    assert.ok(
      leak.matched.includes("959100"),
      "Response must reach CRS outbound blocking evaluation",
    );
    for (let i = 0; i < 20; i++) {
      const start = performance.now();
      assert.equal(executeSecLang(compiled, request("/?q=normal")).blocked, false);
      timings.push(performance.now() - start);
    }
    timings.sort((a, b) => a - b);
    const p95 = timings[Math.floor(timings.length * 0.95)];
    assert.ok(p95 < 500, "Full CRS normal-request p95 exceeds the 500ms regression ceiling");
    return {
      sourceRules: compiled.sourceRules,
      executableSteps: steps,
      rootRules: compiled.supportedRules,
      normal: normal.length,
      attacks: attacks.length,
      responseAttack: 1,
      p95Ms: Number(p95.toFixed(3)),
      unsupported: 0,
      convertedToIR: false,
    };
  } finally {
    compiled.dispose();
  }
}
